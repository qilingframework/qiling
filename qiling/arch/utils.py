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
This module is intended for general purpose functions that are only used in qiling.arch
"""

from qiling.utils import *
from qiling.arch.filetype import *
from qiling.exception import *

def get_arch_module_function(arch, function_name):
    module_dict = {
        QL_X86: {
            "module": "qiling.arch.x86",
        },
        QL_X8664: {
            "module": "qiling.arch.x86",
        },
        QL_ARM: {
            "module": "qiling.arch.arm",
        },
        QL_ARM64: {
            "module": "qiling.arch.arm64",
        },
        QL_MIPS32EL: {
            "module": "qiling.arch.mips32el",
        }
    }

    if arch not in module_dict:
        raise QlErrorArch(f"Invalid Arch {arch}")

    return get_module_function(module_dict[arch]["module"], function_name)
