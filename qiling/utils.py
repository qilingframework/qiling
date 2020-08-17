#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

"""
This module is intended for general purpose functions that can be used
thoughout the qiling framework
"""
import importlib, logging, os
from .exception import *
from .const import QL_ARCH, QL_ARCH_ALL, QL_OS, QL_OS_ALL, QL_OUTPUT, QL_DEBUGGER, QL_ARCH_32BIT, QL_ARCH_64BIT, QL_ARCH_16BIT
from .const import debugger_map, arch_map, os_map

def catch_KeyboardInterrupt(ql):
    def decorator(func):
        def wrapper(*args, **kw):
            try:
                return func(*args, **kw)
            except BaseException as e:
                from .os.const import THREAD_EVENT_UNEXECPT_EVENT
                ql.os.stop(stop_event=2)
                ql.internal_exception = e
        return wrapper
    return decorator

def ql_get_arch_bits(arch):
    if arch in QL_ARCH_16BIT:
        return 16
    if arch in QL_ARCH_32BIT:
        return 32
    if arch in QL_ARCH_64BIT:
        return 64
    raise QlErrorArch("[!] Invalid Arch")

def ql_is_valid_ostype(ostype):
    if ostype not in QL_OS_ALL:
        return False
    return True

def ql_is_valid_arch(arch):
    if arch not in QL_ARCH_ALL:
        return False
    return True

def loadertype_convert_str(ostype):
    adapter = {
        QL_OS.LINUX: "ELF",
        QL_OS.MACOS: "MACHO",
        QL_OS.FREEBSD: "ELF",
        QL_OS.WINDOWS: "PE",
        QL_OS.UEFI: "PE_UEFI",
        QL_OS.DOS: "DOS",
    }
    return adapter.get(ostype)

def ostype_convert_str(ostype):
    adapter = {}
    adapter.update(os_map)
    adapter = {v: k for k, v in adapter.items()}
    return adapter.get(ostype)

def ostype_convert(ostype):
    # this is for ql.platform
    if ostype == "darwin":
        ostype = "macos"
    adapter = {}
    adapter.update(os_map)
    if ostype in adapter:
        return adapter[ostype]
    # invalid
    return None, None

def arch_convert_str(arch):
    adapter = {}
    adapter.update(arch_map)
    adapter = {v: k for k, v in adapter.items()}
    return adapter.get(arch)

def arch_convert(arch):
    adapter = {}
    adapter.update(arch_map)
    if arch in adapter:
        return adapter[arch]
    # invalid
    return None, None

def output_convert(output):
    adapter = {
        None: QL_OUTPUT.DEFAULT,
        "default": QL_OUTPUT.DEFAULT,
        "disasm": QL_OUTPUT.DISASM,
        "debug": QL_OUTPUT.DEBUG,
        "dump": QL_OUTPUT.DUMP,
    }
    if output in adapter:
        return adapter[output]
    # invalid
    return None, None

def debugger_convert(debugger):
    adapter = {}
    adapter.update(debugger_map)
    if debugger in adapter:
        return adapter[debugger]
    # invalid
    return None, None

def debugger_convert_str(debugger_id):
    adapter = {}
    adapter.update(debugger_map)
    adapter = {v: k for k, v in adapter.items()}
    if debugger_id in adapter:
        return adapter[debugger_id]
    # invalid
    return None, None

def ql_build_module_import_name(module, ostype, arch = None):
    ret_str = "qiling." + module

    ostype_str = ostype
    arch_str = arch

    if type(ostype) is QL_OS:
        ostype_str = ostype_convert_str(ostype)
    
    if ostype_str and "loader" not in ret_str:
        ret_str += "." + ostype_str

    if arch:
        # This is because X86_64 is bundled into X86 in arch
        if module == "arch" and arch == QL_ARCH.X8664:  
            arch_str = "x86"
        elif type(arch) is QL_ARCH:
            arch_str = arch_convert_str(arch)
    else:
        arch_str = ostype_str
        
    ret_str += "." + arch_str
    return ret_str

def ql_get_module_function(module_name, function_name = None):
    try:
        imp_module = importlib.import_module(module_name)
    except:
        raise QlErrorModuleNotFound("[!] Unable to import module %s" % module_name)

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
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    return logger

def ql_setup_logging_env(ql, logger=None):
    if not os.path.exists(ql.log_dir):
        os.makedirs(ql.log_dir, 0o755)

    ql.log_filename = ql.targetname + ql.append          
    ql.log_file = os.path.join(ql.log_dir, ql.log_filename) 

    _logger = ql_setup_logging_stream(ql)

    if ql.log_split == False:
        _logger = ql_setup_logging_file(ql.output, ql.log_file, _logger)

    return _logger


def ql_setup_logging_stream(ql, logger=None):

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    ch.terminator = ""

    if logger is None:
        logger = ql_setup_logger()

    logger.addHandler(ch)
    return logger

def ql_setup_logging_file(ql_mode, log_file_path, logger=None):

    # setup FileHandler for logging to disk file
    fh = logging.FileHandler('%s.qlog' % log_file_path)
    fh.setLevel(logging.DEBUG)
    
    # use empty character for stirng terminateor by default
    fh.terminator = ""

    if logger is None:
        logger = ql_setup_logger()

    logger.addHandler(fh)
    return logger

def ql_setup_filter(func_names=None):
    class _filter(logging.Filter):
        def __init__(self, func_names):
            super().__init__()
            # accept list or string func_names so you can use it in qltool and programming
            self.filter_list = func_names.strip().split(",") if isinstance(func_names, str) else func_names

        def filter(self, record):
            return any((record.getMessage().startswith(each) for each in self.filter_list))

    class _FalseFilter(logging.Filter):
        def __init__(self):
            super().__init__()
        def filter(self, record):
            return False

    if func_names == False:
        return _FalseFilter()
    else:
        return _filter(func_names)
