#!/usr/bin/env python3

# Copyright 2019 The Kapitan Authors
# SPDX-FileCopyrightText: 2020 The Kapitan Authors <kapitan-admins@googlegroups.com>
#
# SPDX-License-Identifier: Apache-2.0

"compile tests"

import unittest
import os

from tempfile import TemporaryDirectory
from kapitan.resources import inventory
from kapitan.cached import args
from kapitan.targets import compile_target

INSTALLATION_PATH = "examples/kubernetes"
SEARCH_PATHS = [
    os.getcwd(), 
    INSTALLATION_PATH,
]

class CompileCodeTest(unittest.TestCase):
    def setUp(self):
        args.inventory_backend = "reclass"
        args.inventory_path = "inventory"
        args.inv = inventory([INSTALLATION_PATH])
    
    def test_compile(self):
        target_name = "minikube-es"
        with TemporaryDirectory() as dir:
            target_obj = args.inv[target_name]
            compile_target(
                target_obj,
                SEARCH_PATHS,
                dir,
                None,
                None)
            
            for root, dirs, files in os.walk(dir):
                path = root.split(os.sep)
                print((len(path) - 1) * '---', os.path.basename(root))
                for file in files:
                    print(len(path) * '---', file)
            assert os.path.exists(os.path.join(dir, target_name, "script.sh"))
            
        
        
        