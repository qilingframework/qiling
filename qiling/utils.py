#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

"""
This module is intended for general purpose functions that can be used
thoughout the qiling framework
"""
import importlib, logging, os, logging, copy, re
from logging import LogRecord
from pathlib import Path
from .exception import *
from .const import QL_ARCH, QL_ARCH_ALL, QL_OS, QL_OS_ALL, QL_OUTPUT, QL_DEBUGGER, QL_ARCH_32BIT, QL_ARCH_64BIT, QL_ARCH_16BIT
from .const import debugger_map, arch_map, os_map, D_INFO

from unicorn import UcError, UC_ERR_READ_UNMAPPED, UC_ERR_FETCH_UNMAPPED

FMT_STR = "[%(levelname)s] [%(filename)s:%(lineno)d] %(message)s"

# \033 -> ESC
# ESC [ -> CSI
# CSI %d;%d;... m -> SGR
class COLOR_CODE:
    WHITE = '\033[37m'
    CRIMSON = '\033[31m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    ENDC = '\033[0m'

LEVEL_COLORS = {
    'WARNING': COLOR_CODE.YELLOW,
    'INFO': COLOR_CODE.BLUE,
    'DEBUG': COLOR_CODE.WHITE,
    'CRITICAL': COLOR_CODE.CRIMSON,
    'ERROR': COLOR_CODE.RED
}

class ColoredFormatter(logging.Formatter):
    def __init__(self, *args, **kwargs):
        super(ColoredFormatter, self).__init__(*args, **kwargs)
    
    def get_colored_level(self, record: LogRecord):
        levelname = record.levelname
        return f"{LEVEL_COLORS[levelname]}{levelname}{COLOR_CODE.ENDC}"

    def format(self, record: LogRecord):
        _record = copy.copy(record)
        _record.levelname = self.get_colored_level(_record)
        return super(ColoredFormatter, self).format(_record)

class MultithreadColoredFormatter(ColoredFormatter):
    def __init__(self, ql, *args, **kwargs):
        super(MultithreadColoredFormatter, self).__init__(*args, **kwargs)
        self._ql = ql

    def format(self, record: LogRecord):
        try:
            cur_thread = self._ql.os.thread_management.cur_thread
        except AttributeError:
            return super(MultithreadColoredFormatter, self).format(record)
        _record = copy.copy(record)
        levelname = self.get_colored_level(_record)
        _record.levelname = f"{levelname}] [{COLOR_CODE.GREEN}Thread {cur_thread.id}{COLOR_CODE.ENDC}"
        msg = super(ColoredFormatter, self).format(_record)
        return msg

class RegexFilter(logging.Filter):
    def __init__(self, filters):
        super(RegexFilter, self).__init__()
        self._filters = [ re.compile(ft) for ft in  filters ]
    
    def filter(self, record: LogRecord):
        msg = record.getMessage()
        for ft in self._filters:
            if re.match(ft, msg):
                return True
        return False

class MultithreadSplitHandler(logging.Handler):
    def __init__(self, ql):
        super(MultithreadSplitHandler, self).__init__()
        self._ql = ql
    
    def emit(self, record: LogRecord):
        msg = self.format(record)
        try:
            cur_thread = self._ql.os.thread_management.cur_thread
        except AttributeError:
            self._ql._msg_before_main_thread.append((record.levelno, msg))
            return
        cur_thread.log_file_fd.log(record.levelno, msg)


def catch_KeyboardInterrupt(ql):
    def decorator(func):
        def wrapper(*args, **kw):
            try:
                return func(*args, **kw)
            except BaseException as e:
                from .os.const import THREAD_EVENT_UNEXECPT_EVENT
                ql.os.stop()
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
    return QL_OUTPUT.DEFAULT

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

def ql_resolve_logger_level(output, verbose):
    level = logging.INFO
    if output in (QL_OUTPUT.DEBUG, QL_OUTPUT.DUMP, QL_OUTPUT.DISASM):
        level = logging.DEBUG
    
    if verbose == 0:
        level = logging.WARNING
    elif verbose >= 4:
        level = logging.DEBUG
    elif verbose >= 1:
        level = logging.INFO
    
    logging.getLogger().setLevel(level)


# TODO: qltool compatibility
def ql_setup_logger(ql, log_dir, log_filename, log_split, console, filter, multithread):
    # Covered use cases:
    #    - Normal console output.
    #    - Write to a single file.
    #    - Write to splitted log files.

    # Clear all handlers and filters.
    lger = logging.getLogger()
    lger.handlers = []
    lger.filters = []

    # Do we have console output?
    if console:
        handler = logging.StreamHandler()
        if multithread:
            formatter = MultithreadColoredFormatter(ql, FMT_STR)
        else:
            formatter = ColoredFormatter(FMT_STR)
        handler.setFormatter(formatter)
        lger.addHandler(handler)
    
    # If log_dir isn't specified, return.
    if log_dir is None or log_dir == "":
        return

    os.makedirs(log_dir, 0o755, exist_ok=True)
    
    # If we don't have to split logs, that's the most simple case.
    if not log_split:
        handler = logging.FileHandler(Path(log_dir) / log_filename)
        handler.setFormatter(logging.Formatter(FMT_STR))
        lger.addHandler(handler)
    else:
        if multithread:
            # A placeholder for messages before the first(main) thread is created.
            ql._msg_before_main_thread = []
            handler = MultithreadSplitHandler(ql)
            handler.setFormatter(logging.Formatter(FMT_STR))
            lger.addHandler(handler)
        # For spliting logs with child process, we do that during fork.

    # Remeber to add filters.
    if filter is not None and type(filter) == list and len(filter) != 0:
        lger.addFilter(RegexFilter(filter))
    
    lger.setLevel(logging.INFO)


# verify if emulator returns properly
def verify_ret(ql, err):
    ql.dprint(D_INFO, "Got exception %u: init SP = %x, current SP = %x, PC = %x" %(err.errno, ql.os.init_sp, ql.reg.arch_sp, ql.reg.arch_pc))
    # print("Got exception %u: init SP = %x, current SP = %x, PC = %x" %(err.errno, ql.os.init_sp, self.reg.arch_sp, self.reg.arch_pc))

    ql.os.RUN = False

    # timeout is acceptable in this case
    if err.errno in (UC_ERR_READ_UNMAPPED, UC_ERR_FETCH_UNMAPPED):
        if ql.ostype == QL_OS.MACOS:
            if ql.loader.kext_name:
                # FIXME: Should I push saved RIP before every method callings of IOKit object?
                if ql.os.init_sp == ql.reg.arch_sp - 8:
                    pass
                else:
                    raise
        
        if ql.archtype == QL_ARCH.X8664: # Win64
            if ql.os.init_sp == ql.reg.arch_sp or ql.os.init_sp + 8 == ql.reg.arch_sp or ql.os.init_sp + 0x10 == ql.reg.arch_sp:  # FIXME
                # [+] 0x11626	 c3	  	ret
                # print("OK, stack balanced!")
                pass
            else:
                raise
        else:   # Win32
            if ql.os.init_sp + 12 == ql.reg.arch_sp:   # 12 = 8 + 4
                # [+] 0x114dd	 c2 08 00	  	ret 	8
                pass
            else:
                raise
    else:
        raise        
