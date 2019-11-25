#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


"""
This module is intended for general purpose functions that can be used
thoughout the qiling framework
"""

import importlib
import sys
from qiling.exception import *
from qiling.arch.filetype import *

def ql_get_os_module_function(ostype, arch, function_name):
    if not ql_is_valid_ostype(ostype):
        raise QlErrorOsType(f"Invalid OSType {ostype}")

    if not ql_is_valid_arch(arch):
        raise QlErrorArch("Invalid Arch")

    module_name = ql_build_module_import_name("os", ostype, arch)
    return ql_get_module_function(module_name, function_name)

def ql_get_arch_module_function(arch, function_name):
    if not ql_is_valid_arch(arch):
        raise QlErrorArch("Invalid Arch")

    module_name = ql_build_module_import_name("arch", None, arch)
    return ql_get_module_function(module_name, function_name)

def ql_build_module_import_name(module, ostype, arch):
    ret_str = "qiling." + module

    if ostype:
        ostype_str = ql_ostype_convert_str(ostype)
        ret_str += "." + ostype_str

    if arch:
        if module == "arch" and arch == QL_X8664:  #This is because X86_64 is bundled into X86 in arch
            arch_str = "x86"
        else:
            arch_str = ql_arch_convert_str(arch)
        ret_str += "." + arch_str

    return ret_str

def ql_get_module_function(module_name, function_name):
    try:
        imp_module = importlib.import_module(module_name)
    except:
        raise QlErrorModuleNotFound(f"Unable to import module {module_name}")

    try:
        module_function = getattr(imp_module, function_name)
    except:
        raise QlErrorModuleFunctionNotFound(f"Unable to function {function_name} from {module_name}")

    return module_function