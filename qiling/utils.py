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
from .const import QL_ARCH, QL_ARCH_ALL, QL_OS, QL_OS_ALL, QL_OUTPUT, QL_DEBUGGER

def catch_KeyboardInterrupt(ql):
    def decorator(func):
        def wrapper(*args, **kw):
            try:
                return func(*args, **kw)
            except BaseException as e:
                ql.os.stop(stop_event=THREAD_EVENT_UNEXECPT_EVENT)
                ql.internal_exception = e
        return wrapper
    return decorator

def ql_get_arch_bits(arch):
    arch_32b = [QL_ARCH.ARM, QL_ARCH.MIPS32, QL_ARCH.X86]
    arch_64b = [QL_ARCH.ARM64, QL_ARCH.X8664]

    if arch in arch_32b:
        return 32
    if arch in arch_64b:
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

def ql_ostype_convert_str(ostype):
    adapter = {
        QL_OS.LINUX: "linux",
        QL_OS.MACOS: "macos",
        QL_OS.FREEBSD: "freebsd",
        QL_OS.WINDOWS: "windows",
    }
    return adapter.get(ostype)

def ql_loadertype_convert_str(ostype):
    adapter = {
        QL_OS.LINUX: "ELF",
        QL_OS.MACOS: "MACHO",
        QL_OS.FREEBSD: "ELF",
        QL_OS.WINDOWS: "PE",
    }
    return adapter.get(ostype)

def ostype_convert(ostype):
    adapter = {
        "linux": QL_OS.LINUX,
        "macos": QL_OS.MACOS,
        "darwin": QL_OS.MACOS,
        "freebsd": QL_OS.FREEBSD,
        "windows": QL_OS.WINDOWS,
    }
    if ostype in adapter:
        return adapter[ostype]
    # invalid
    return None, None

def ql_arch_convert_str(arch):
    adapter = {
        QL_ARCH.X86: "x86",
        QL_ARCH.X8664: "x8664",
        QL_ARCH.MIPS32: "mips32",
        QL_ARCH.ARM: "arm",
        QL_ARCH.ARM64: "arm64",
    }
    return adapter.get(arch)

def arch_convert(arch):
    adapter = {
        "x86": QL_ARCH.X86,
        "x8664": QL_ARCH.X8664,
        "mips32": QL_ARCH.MIPS32,
        "arm": QL_ARCH.ARM,
        "arm64": QL_ARCH.ARM64,
    }
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
    adapter = {
        "gdb": QL_DEBUGGER.GDB,
        "ida": QL_DEBUGGER.IDAPRO,
    }
    if debugger in adapter:
        return adapter[debugger]
    # invalid
    return None, None

def debugger_convert_str(debugger_id):
    adapter = {
        None : "gdb",
        QL_DEBUGGER.GDB : "gdb",
        QL_DEBUGGER.IDAPRO: "ida",
    }
    if debugger_id in adapter:
        return adapter[debugger_id]
    # invalid
    return None, None

def ql_get_arch_module_function(arch, function_name):
    if not ql_is_valid_arch(arch):
        raise QlErrorArch("[!] Invalid Arch")
    function_name = function_name.upper()    
    module_name = ql_build_module_import_name("arch", None, arch)
    return ql_get_module_function(module_name, function_name)

def ql_build_module_import_name(module, ostype, arch = None):
    ret_str = "qiling." + module

    ostype_str = ostype
    arch_str = arch

    if type(ostype) is QL_OS:
        ostype_str = ql_ostype_convert_str(ostype)
    
    if ostype_str and "loader" not in ret_str:
        ret_str += "." + ostype_str

    if arch:
        # This is because X86_64 is bundled into X86 in arch
        if module == "arch" and arch == QL_ARCH.X8664:  
            arch_str = "x86"
        elif type(arch) is QL_ARCH:
            arch_str = ql_arch_convert_str(arch)
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
    logger.setLevel(logging.DEBUG)
    return logger

def ql_setup_logging_env(ql, logger=None):
    if not os.path.exists(ql.log_dir):
        os.makedirs(ql.log_dir, 0o755)

    pid = os.getpid()

    if ql.append:
        ql.log_filename = ql.targetname + "_" + ql.append          
    else:
        ql.log_filename = ql.targetname
    
    ql.log_file = os.path.join(ql.log_dir, ql.log_filename) 

    _logger = ql_setup_logging_file(ql.output, ql.log_file + "_" + str(pid), logger)
    return _logger

def ql_setup_logging_stream(ql, logger=None):
    #ql_mode = ql.output

    # setup StreamHandler for logging to stdout
    if ql.log_console == True:
        ch = logging.StreamHandler()
    else:
        # not print out to stdout by using NullHandler
        ch = logging.NullHandler()

    ch.setLevel(logging.DEBUG)
    
    # use empty character for string terminator by default
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

class Strace_filter(logging.Filter):
    def __init__(self, func_names):
        super(Strace_filter, self).__init__()
        self.filter_list = func_names.split(",") if isinstance(func_names, str) else func_names

    def filter(self, record):
        return any((record.getMessage().startswith(each) for each in self.filter_list))
      