#!/usr/bin/env python3

# Copyright 2019 The Kapitan Authors
# SPDX-FileCopyrightText: 2020 The Kapitan Authors <kapitan-admins@googlegroups.com>
#
# SPDX-License-Identifier: Apache-2.0

"inventory tests"

import logging
import unittest

from kapitan.resources import AVAILABLE_BACKENDS

logger = logging.getLogger(__name__)

TARGETS_NUMBER = 211

class InventoryOmegaconfTest(unittest.TestCase):
    def setUp(self):
        # Configure `compile.inventory_path` and `inventory-backend`. This
        # allows us to reuse the tests by inheriting from this test class.
        backend = AVAILABLE_BACKENDS.get("omegaconf")
        self.inventory_backend = backend("../mcp/inventory", compose_target_name=True)
        logger.error(f"Testing get_single_target, inventory is initialised: {self.inventory_backend.initialised}")
        
    def test_get_single_target(self):
        target = self.inventory_backend.get_target("docs")
        self.assertEqual(target.name, "docs")
        self.assertEqual(target.path, "docs.yml")
        self.assertEqual(target.parameters["kapitan"]["vars"]["target"], "docs")

        
    def test_get_all_targets(self):
        targets = self.inventory_backend.get_targets()
        self.assertEqual(len(targets), TARGETS_NUMBER)
        self.assertEqual(targets["docs"].name, "docs")
        self.assertEqual(targets["docs"].path, "docs.yml")
        self.assertEqual(targets["docs"].parameters["kapitan"]["vars"]["target"], "docs")

        for target in targets.values():
            self.assertTrue(target.name)
            self.assertTrue(target.path)
            self.assertTrue(target.parameters)