#!/usr/bin/env python3

# Copyright 2019 The Kapitan Authors
# SPDX-FileCopyrightText: 2020 The Kapitan Authors <kapitan-admins@googlegroups.com>
#
# SPDX-License-Identifier: Apache-2.0

import logging
import multiprocessing as mp
import os
from copy import deepcopy
from dataclasses import dataclass, field
from time import time
from cachetools import cached, LRUCache
import yaml
from omegaconf import ListMergeMode, OmegaConf, DictConfig

from ..inventory import InventoryError, Inventory, InventoryTarget
from .resolvers import register_resolvers

logger = logging.getLogger(__name__)


class OmegaConfInventory(Inventory):
    classes_cache: dict = {}

    def render_targets(self, targets: list[InventoryTarget] = None, ignore_class_not_found: bool = False) -> None:
        targets = self.targets.values()
        self.ignore_class_not_found = ignore_class_not_found
        manager = mp.Manager()  # perf: bottleneck --> 90 % of the inventory time
        shared_targets = manager.dict()

        mp.set_start_method("spawn", True)  # platform independent
        with mp.Pool(min(len(targets), os.cpu_count())) as pool:
            r = pool.map_async(self.inventory_worker, [(self, target, shared_targets) for target in targets])
            r.wait()

        # store parameters and classes
        for target_name, rendered_target in shared_targets.items():
            self.targets[target_name].parameters = rendered_target["parameters"]
            logger.debug(f"Rendered {target_name} using OmegaConf with {len(rendered_target['parameters'])} parameters")


    @staticmethod
    def inventory_worker(zipped_args):
        self, target, nodes = zipped_args
        start = time()
        try:
            register_resolvers(self.inventory_path)
            self.load_target(target)
            nodes[target.name] = {"parameters": target.parameters}
        except Exception as e:
            logger.error(f"{target.name}: could not render due to error {e}")
            raise

    @cached(cache=LRUCache(maxsize=1024))
    def resolve_class_file_path(self, class_name: str, class_parent_dir: str = None):
        class_file = None
        
        if class_name.startswith(".") and class_parent_dir:
            class_name = class_parent_dir + class_name
        
        class_path_base = os.path.join(self.classes_path, *class_name.split("."))
        
        
        if os.path.isfile(os.path.join(class_path_base, "init.yml")):
            class_file = os.path.join(class_path_base, "init.yml")
        elif os.path.isfile(class_path_base + ".yml"):
            class_file = f"{class_path_base}.yml"
            
        return class_file
 
    @cached(cache=LRUCache(maxsize=1024))
    def load_class(self, class_file: str):
        if class_file not in self.classes_cache:
            self.classes_cache[class_file] = self._load_file(class_file)
        return self.classes_cache[class_file]
                                 
                                 
    def load_classes(self, target: InventoryTarget, classes: list, ignore_class_not_found=False, class_parent_dir=None):
        for class_name in classes:
            class_file = self.resolve_class_file_path(class_name, class_parent_dir=class_parent_dir)
            
            if not class_file:
                if ignore_class_not_found:
                    logger.warning(f"Class {class_name} not found")
                    continue
                raise InventoryError(f"Class {class_name} not found")
            
            content = self.load_class(class_file)
            
            sub_classes = content.get("classes", [])
                
            if sub_classes:
                new_class_parent_dir = os.path.dirname(class_file.removeprefix(self.classes_path).removeprefix("/"))
                self.load_classes(target, sub_classes, self.ignore_class_not_found, new_class_parent_dir)
            
            parameters = content.get("parameters", {})
            target.parameters = self._merge_parameters(target.parameters, parameters)
    
    def load_target(self, target: InventoryTarget):
        """
        load only one target with all its classes
        """

        # load the target parameters
        content = self._load_file(os.path.join(self.targets_path, target.path))
        target.classes = content.get("classes", [])
        self.load_classes(target, target.classes, ignore_class_not_found=self.ignore_class_not_found)

        target.parameters = self._merge_parameters(target.parameters, content.get("parameters", {}))
        
        logger.debug(f"Loaded {target.name} with {len(target.parameters)} parameters and {len(target.classes)} classes")
        # resolve interpolations
        self._add_metadata(target)
        target.parameters = self._resolve_parameters(target.parameters)

        # obtain target name to insert in inv dict
        vars_target_name = target.parameters.get("kapitan", {}).get("vars", {}).get("target")
        if not vars_target_name:
            # add hint to kapitan.vars.target
            logger.warning(f"Could not resolve target name on target {target.name}")

    def _add_metadata(self, target: InventoryTarget):
        metadata = {
            "name": {
                "short": target.name.split(".")[-1],
                "full": target.name,
                "path": target.path,
                "parts": target.name.split("."),
            }
        }
        target.parameters["_kapitan_"] = metadata
        target.parameters["_reclass_"] = metadata

    @staticmethod
    def _load_file(path: str):
        with open(path, "r") as f:
            f.seek(0)
            config = yaml.load(f, yaml.SafeLoader)
        return config

    @staticmethod
    def _merge_parameters(target_parameters: DictConfig, class_parameters: DictConfig) -> DictConfig:
        if not target_parameters:
            return class_parameters

        return OmegaConf.unsafe_merge(
            class_parameters, target_parameters, list_merge_mode=ListMergeMode.EXTEND,
        )

    @staticmethod
    def _resolve_parameters(target_parameters: DictConfig):
        # resolve first time
        OmegaConf.resolve(target_parameters, escape_interpolation_strings=False)

        # remove specified keys between first and second resolve-stage
        remove_location = "omegaconf.remove"
        removed_keys = OmegaConf.select(target_parameters, remove_location, default=[])
        for key in removed_keys:
            OmegaConf.update(target_parameters, key, {}, merge=False)

        # resolve second time and convert to object
        # TODO: add `throw_on_missing = True` when resolving second time (--> wait for to_object support)
        # reference: https://github.com/omry/omegaconf/pull/1113
        OmegaConf.resolve(target_parameters, escape_interpolation_strings=False)
        return OmegaConf.to_container(target_parameters)

