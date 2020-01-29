#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

"""
This module is intended for general purpose functions that can be used
thoughout the qiling framework
"""

import importlib
import sys, random, logging
from qiling.exception import *
from qiling.arch.filetype import *

def ql_get_os_module_function(ostype, arch, function_name):
    if not ql_is_valid_ostype(ostype):
        raise QlErrorOsType("[!] Invalid OSType")

    if not ql_is_valid_arch(arch):
        raise QlErrorArch("[!] Invalid Arch")

    module_name = ql_build_module_import_name("os", ostype, arch)
    return ql_get_module_function(module_name, function_name)

def ql_get_arch_module_function(arch, function_name):
    if not ql_is_valid_arch(arch):
        raise QlErrorArch("[!] Invalid Arch")

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
        raise QlErrorModuleNotFound("[!] Unable to import module %s" %(module_name))

    try:
        module_function = getattr(imp_module, function_name)
    except:
        raise QlErrorModuleFunctionNotFound("[!] Unable to import %s from %s" % (function_name, imp_module))

    return module_function


def ql_setup_logger(logger_name=None):
    if logger_name is None: # increasing logger name counter to prevent conflict 
        loggers = logging.root.manager.loggerDict
        _counter = len(loggers)
        logger_name = 'qiling_%s' % _counter
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    return logger


def ql_setup_logging_stream(ql_mode, logger=None):

    # setup StreamHandler for logging to stdout
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    if ql_mode in (QL_OUT_DISASM, QL_OUT_DUMP):
        # use empty string for newline if disasm or dump mode was enabled
        ch.terminator = ""

    if logger is None:
        logger = ql_setup_logger()

    logger.addHandler(ch)
    return logger


def ql_setup_logging_file(ql_mode, log_file_path, logger=None):

    # setup FileHandler for logging to disk file
    fh = logging.FileHandler('%s.qlog' % (log_file_path))
    fh.setLevel(logging.DEBUG)

    if ql_mode in (QL_OUT_DISASM, QL_OUT_DUMP):
        # use empty string for newline if disasm or dump mode was enabled
        fh.terminator = ""

    if logger is None:
        logger = ql_setup_logger()

    logger.addHandler(fh)
    return logger
