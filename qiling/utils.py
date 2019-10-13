#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
#
# LAU kaijern (xwings) <kj@qiling.io>
# NGUYEN Anh Quynh <aquynh@gmail.com>
# DING tianZe (D1iv3) <dddliv3@gmail.com>
# SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
# CHEN huitao (null) <null@qiling.io>
# YU tong (sp1ke) <spikeinhouse@gmail.com>

"""
This module is intended for general purpose functions that can be used
thoughout the qiling framework
"""

import importlib
import sys
from qiling.exception import *


def get_module_function(module_name, function_name):
    try:
        imp_module = importlib.import_module(module_name)
    except:
        raise QlErrorModuleNotFound(f"Unable to import module {module_name}")

    try:
        module_function = getattr(imp_module, function_name)
    except:
        raise QlErrorModuleFunctionNotFound(f"Unable to function {function_name} from {module_name}")

    return module_function