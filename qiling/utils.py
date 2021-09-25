#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

"""
This module is intended for general purpose functions that can be used
thoughout the qiling framework
"""
import importlib, os, copy, re, pefile, configparser, logging, sys
from logging import LogRecord
from typing import Container, Optional, Mapping, Sequence
from enum import EnumMeta

from unicorn import UC_ERR_READ_UNMAPPED, UC_ERR_FETCH_UNMAPPED

from .exception import *
from .const import QL_ARCH_NONEOS, QL_VERBOSE, QL_ARCH, QL_ENDIAN, QL_OS, QL_DEBUGGER, QL_ARCH_1BIT, QL_ARCH_16BIT, QL_ARCH_32BIT, QL_ARCH_64BIT
from .const import debugger_map, arch_map, os_map, arch_os_map, loader_map

FMT_STR = "%(levelname)s\t%(message)s"

# \033 -> ESC
# ESC [ -> CSI
# CSI %d;%d;... m -> SGR
class COLOR_CODE:
    WHITE   = '\033[37m'
    CRIMSON = '\033[31m'
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    ENDC    = '\033[0m'

LEVEL_COLORS = {
    'WARNING'  : COLOR_CODE.YELLOW,
    'INFO'     : COLOR_CODE.BLUE,
    'DEBUG'    : COLOR_CODE.MAGENTA,
    'CRITICAL' : COLOR_CODE.CRIMSON,
    'ERROR'    : COLOR_CODE.RED
}

class QilingColoredFormatter(logging.Formatter):
    def __init__(self, ql, *args, **kwargs):
        super(QilingColoredFormatter, self).__init__(*args, **kwargs)
        self._ql = ql

    def get_colored_level(self, record: LogRecord) -> str:
        LEVEL_NAME = {
            'WARNING'  : f"{COLOR_CODE.YELLOW}[!]{COLOR_CODE.ENDC}",
            'INFO'     : f"{COLOR_CODE.BLUE}[=]{COLOR_CODE.ENDC}",
            'DEBUG'    : f"{COLOR_CODE.MAGENTA}[+]{COLOR_CODE.ENDC}",
            'CRITICAL' : f"{COLOR_CODE.CRIMSON}[x]{COLOR_CODE.ENDC}",
            'ERROR'    : f"{COLOR_CODE.RED}[x]{COLOR_CODE.ENDC}"
        }

        return LEVEL_NAME[record.levelname]

    def format(self, record: LogRecord):
        # In case we have multiple formatters, we have to keep a copy of the record.
        record = copy.copy(record)
        record.levelname = self.get_colored_level(record)
        try:
            cur_thread = self._ql.os.thread_management.cur_thread
            if cur_thread is not None:
                record.levelname = f"{record.levelname} {COLOR_CODE.GREEN}{str(cur_thread)}{COLOR_CODE.ENDC}"
        except AttributeError:
            pass
        return super(QilingColoredFormatter, self).format(record)

class QilingPlainFormatter(logging.Formatter):
    def __init__(self, ql, *args, **kwargs):
        super(QilingPlainFormatter, self).__init__(*args, **kwargs)
        self._ql = ql

    def get_level(self, record: LogRecord) -> str:
        LEVEL_NAME = {
            'WARNING'  : "[!]",
            'INFO'     : "[=]",
            'DEBUG'    : "[+]",
            'CRITICAL' : "[x]",
            'ERROR'    : "[x]"
        }

        return LEVEL_NAME[record.levelname]

    def format(self, record: LogRecord):
        record.levelname = self.get_level(record)
        try:
            cur_thread = self._ql.os.thread_management.cur_thread
            if cur_thread is not None:
                record.levelname = f"{record.levelname} {str(cur_thread)}"
        except AttributeError:
            pass
        return super(QilingPlainFormatter, self).format(record)

class RegexFilter(logging.Filter):
    def __init__(self, regexp):
        super(RegexFilter, self).__init__()
        self.update_filter(regexp)
    
    def update_filter(self, regexp):
        self._filter = re.compile(regexp)

    def filter(self, record: LogRecord):
        msg = record.getMessage()

        return re.match(self._filter, msg) is not None

class QlFileDes:
    def __init__(self, init):
        self.__fds = init

    def __getitem__(self, idx):
        return self.__fds[idx]

    def __setitem__(self, idx, val):
        self.__fds[idx] = val

    def __iter__(self):
        return iter(self.__fds)

    def __repr__(self):
        return repr(self.__fds)
    
    def save(self):
        return self.__fds

    def restore(self, fds):
        self.__fds = fds


class QlStopOptions(object):
    def __init__(self, stackpointer=False, exit_trap=False):
        super().__init__()
        self._stackpointer = stackpointer
        self._exit_trap = exit_trap

    @property
    def stackpointer(self) -> bool:
        return self._stackpointer

    @property
    def exit_trap(self) -> bool:
        return self._exit_trap

    @property
    def any(self) -> bool:
        return self.stackpointer or self.exit_trap


def catch_KeyboardInterrupt(ql):
    def decorator(func):
        def wrapper(*args, **kw):
            try:
                return func(*args, **kw)
            except BaseException as e:
                ql.os.stop()
                ql._internal_exception = e

        return wrapper

    return decorator

def ql_get_arch_bits(arch: QL_ARCH) -> int:
    if arch in QL_ARCH_1BIT:
        return 1

    if arch in QL_ARCH_16BIT:
        return 16

    if arch in QL_ARCH_32BIT:
        return 32

    if arch in QL_ARCH_64BIT:
        return 64

    raise QlErrorArch("Invalid Arch Bit")

def enum_values(e: EnumMeta) -> Container:
    return e.__members__.values()

def ql_is_valid_ostype(ostype: QL_OS) -> bool:
    return ostype in enum_values(QL_OS)

def ql_is_valid_arch(arch: QL_ARCH) -> bool:
    return arch in enum_values(QL_ARCH)

def loadertype_convert_str(ostype: QL_OS) -> Optional[str]:
    adapter = {}
    adapter.update(loader_map)
    return adapter.get(ostype)

def __reverse_mapping(mapping: Mapping) -> Mapping:
    return {v: k for k, v in mapping.items()}

def ostype_convert_str(ostype: QL_OS) -> Optional[str]:
    return __reverse_mapping(os_map).get(ostype)

def ostype_convert(ostype: str) -> Optional[QL_OS]:
    if ostype == "darwin":
        ostype = "macos"

    return os_map.get(ostype)

def arch_convert_str(arch: QL_ARCH) -> Optional[str]:
    return __reverse_mapping(arch_map).get(arch)

def arch_convert(arch: str) -> Optional[QL_ARCH]:
    return arch_map.get(arch)

def arch_os_convert(arch):
    adapter = {}
    adapter.update(arch_os_map)
    if arch in adapter:
        return adapter[arch]
    # invalid
    return None

def os_arch_convert(arch):
    adapter = {}
    adapter.update(arch_map)
    adapter = {v: k for k, v in adapter.items()}
    return adapter.get(arch)

def debugger_convert(debugger: str) -> Optional[QL_DEBUGGER]:
    return debugger_map.get(debugger)

def debugger_convert_str(debugger_id: QL_DEBUGGER) -> Optional[str]:
    return __reverse_mapping(debugger_map).get(debugger_id)

# Call `function_name` in `module_name`.
# e.g. map_syscall in qiling.os.linux.map_syscall
def ql_get_module_function(module_name: str, function_name: str):

    try:
        imp_module = importlib.import_module(module_name)
    except ModuleNotFoundError:
        raise QlErrorModuleNotFound(f'Unable to import module {module_name}')
    except KeyError:
        raise QlErrorModuleNotFound(f'Unable to import module {module_name}')

    try:
        module_function = getattr(imp_module, function_name)
    except AttributeError:
        raise QlErrorModuleFunctionNotFound(f'Unable to import {function_name} from {imp_module}')

    return module_function

def ql_elf_parse_emu_env(path):
    def getident():
        return elfdata

    with open(path, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        if size >= 512:
            elfdata = f.read(512)
        else:
            elfdata = f.read(20)

    ident = getident()
    ostype = None
    arch = None
    archendian = None

    if ident[:4] == b'\x7fELF':
        elfbit = ident[0x4]
        endian = ident[0x5]
        osabi = ident[0x7]
        e_machine = ident[0x12:0x14]

        if osabi == 0x09:
            ostype = QL_OS.FREEBSD
        elif osabi in (0x0, 0x03) or osabi >= 0x11:
            if b"ldqnx.so" in ident:
                ostype = QL_OS.QNX
            else:
                ostype = QL_OS.LINUX

        if e_machine == b"\x03\x00":
            archendian = QL_ENDIAN.EL
            arch = QL_ARCH.X86
        elif e_machine == b"\x08\x00" and endian == 1 and elfbit == 1:
            archendian = QL_ENDIAN.EL
            arch = QL_ARCH.MIPS
        elif e_machine == b"\x00\x08" and endian == 2 and elfbit == 1:
            archendian = QL_ENDIAN.EB
            arch = QL_ARCH.MIPS
        elif e_machine == b"\x28\x00" and endian == 1 and elfbit == 1:
            archendian = QL_ENDIAN.EL
            arch = QL_ARCH.ARM
        elif e_machine == b"\x00\x28" and endian == 2 and elfbit == 1:
            archendian = QL_ENDIAN.EB
            arch = QL_ARCH.ARM
        elif e_machine == b"\xB7\x00":
            archendian = QL_ENDIAN.EL
            arch = QL_ARCH.ARM64
        elif e_machine == b"\x3E\x00":
            archendian = QL_ENDIAN.EL
            arch = QL_ARCH.X8664
        else:
            arch = None

    return arch, ostype, archendian

def ql_macho_parse_emu_env(path):
   
    def getident():
        return machodata

    with open(path, "rb") as f:
        machodata = f.read(32)

    ident = getident()

    macho_macos_sig64 = b'\xcf\xfa\xed\xfe'
    macho_macos_sig32 = b'\xce\xfa\xed\xfe'
    macho_macos_fat = b'\xca\xfe\xba\xbe'  # should be header for FAT

    ostype = None
    arch = None
    archendian = None

    if ident[: 4] in (macho_macos_sig32, macho_macos_sig64, macho_macos_fat):
        ostype = QL_OS.MACOS
    else:
        ostype = None

    if ostype:
        # if ident[0x7] == 0: # 32 bit
        #    arch = QL_ARCH.X86
        if ident[0x4] == 7 and ident[0x7] == 1:  # X86 64 bit
            archendian = QL_ENDIAN.EL
            arch = QL_ARCH.X8664
        elif ident[0x4] == 12 and ident[0x7] == 1:  # ARM64  ident[0x4] = 0x0C
            archendian = QL_ENDIAN.EL
            arch = QL_ARCH.ARM64
        else:
            arch = None

    return arch, ostype, archendian


def ql_pe_parse_emu_env(path):
    try:
        pe = pefile.PE(path, fast_load=True)
    except:
        return None, None, None

    ostype = None
    arch = None
    archendian = None

    machine_map = {
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']: QL_ARCH.X86,
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']: QL_ARCH.X8664,
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM']: QL_ARCH.ARM,
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_THUMB']: QL_ARCH.ARM,
        # pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM64']     :   QL_ARCH.ARM64       #pefile does not have the definition
        # for IMAGE_FILE_MACHINE_ARM64
        0xAA64: QL_ARCH.ARM64  # Temporary workaround for Issues #21 till pefile gets updated
    }
    # get arch
    archendian = QL_ENDIAN.EL
    arch = machine_map.get(pe.FILE_HEADER.Machine)

    if arch:
        if pe.OPTIONAL_HEADER.Subsystem >= pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_EFI_APPLICATION'] and \
        pe.OPTIONAL_HEADER.Subsystem <= pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_EFI_ROM'] :
            ostype = QL_OS.UEFI
        else:
            ostype = QL_OS.WINDOWS
    else:
        ostype = None

    return arch, ostype, archendian


def ql_guess_emu_env(path):
    arch = None
    ostype = None
    archendian = None

    if os.path.isdir(path) and (str(path)).endswith(".kext"):
        return QL_ARCH.X8664, QL_OS.MACOS, QL_ENDIAN.EL

    if os.path.isfile(path) and (str(path)).endswith(".DOS_COM"):
        return QL_ARCH.A8086, QL_OS.DOS, QL_ENDIAN.EL

    if os.path.isfile(path) and (str(path)).endswith(".DOS_MBR"):
        return QL_ARCH.A8086, QL_OS.DOS, QL_ENDIAN.EL

    if os.path.isfile(path) and (str(path)).endswith(".DOS_EXE"):
        return QL_ARCH.A8086, QL_OS.DOS, QL_ENDIAN.EL

    arch, ostype, archendian = ql_elf_parse_emu_env(path)

    if arch == None or ostype == None or archendian == None:
        arch, ostype, archendian = ql_macho_parse_emu_env(path)

    if arch == None or ostype == None or archendian == None:
        arch, ostype, archendian = ql_pe_parse_emu_env(path)
  
    if ostype not in (QL_OS):
        raise QlErrorOsType("File does not belong to either 'linux', 'windows', 'freebsd', 'macos', 'ios', 'dos', 'qnx'")

    return arch, ostype, archendian


def loader_setup(ostype, ql):
    loadertype_str = loadertype_convert_str(ostype)
    function_name = "QlLoader" + loadertype_str
    return ql_get_module_function(f"qiling.loader.{loadertype_str.lower()}", function_name)(ql)


def component_setup(component_type, component_name, ql):
    function_name = "Ql" + component_name.capitalize() + "Manager"
    return ql_get_module_function(f"qiling.{component_type}.{component_name}", function_name)(ql)


def debugger_setup(debugger, ql):
    # default remote server
    remotedebugsrv = "gdb"
    debug_opts = [None, None]

    if debugger != True and type(debugger) is str:
        debug_opts = debugger.split(":")

        if len(debug_opts) == 2 and debug_opts[0] != "qdb":
            pass
        else:  
            remotedebugsrv, *debug_opts = debug_opts

        if debugger_convert(remotedebugsrv) not in enum_values(QL_DEBUGGER):
            raise QlErrorOutput("Error: Debugger not supported")

    debugsession = ql_get_module_function(f"qiling.debugger.{remotedebugsrv}.{remotedebugsrv}", f"Ql{str.capitalize(remotedebugsrv)}")

    return debugsession(ql, *debug_opts)

def arch_setup(archtype, ql):
    if not ql_is_valid_arch(archtype):
        raise QlErrorArch("Invalid Arch")
    
    if archtype == QL_ARCH.ARM_THUMB:
        archtype =  QL_ARCH.ARM

    archmanager = arch_convert_str(archtype).upper()
    archmanager = ("QlArch" + archmanager)

    if archtype in (QL_ARCH.X8664, QL_ARCH.A8086):
        arch_str = "x86"
    else:
        arch_str = arch_convert_str(archtype)

    if archtype in QL_ARCH_NONEOS:
        return ql_get_module_function(f"qiling.arch.{arch_str.lower()}.{arch_str.lower()}", archmanager)(ql)
    else:    
        return ql_get_module_function(f"qiling.arch.{arch_str.lower()}", archmanager)(ql)


# This function is extracted from os_setup so I put it here.
def ql_syscall_mapping_function(ostype):
    ostype_str = ostype_convert_str(ostype)
    return ql_get_module_function(f"qiling.os.{ostype_str.lower()}.map_syscall", "map_syscall")


def os_setup(archtype: QL_ARCH, ostype: QL_OS, ql):
    if not ql_is_valid_ostype(ostype):
        raise QlErrorOsType("Invalid OSType")

    if not ql_is_valid_arch(archtype):
        raise QlErrorArch("Invalid Arch %s" % archtype)

    ostype_str = ostype_convert_str(ostype)
    ostype_str = ostype_str.capitalize()
    function_name = "QlOs" + ostype_str
    return ql_get_module_function(f"qiling.os.{ostype_str.lower()}.{ostype_str.lower()}", function_name)(ql)


def profile_setup(ostype, profile, ql):
    _profile = "Default"
    if profile != None:
        _profile = profile
        
    debugmsg = "Profile: %s" % _profile

    os_profile = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles", ostype_convert_str(ostype) + ".ql")

    if profile:
        profiles = [os_profile, profile]
    else:
        profiles = [os_profile]

    config = configparser.ConfigParser()
    config.read(profiles)
    return config, debugmsg

def ql_resolve_logger_level(verbose: QL_VERBOSE) -> int:
    return {
        QL_VERBOSE.OFF     : logging.WARNING,
        QL_VERBOSE.DEFAULT : logging.INFO,
        QL_VERBOSE.DEBUG   : logging.DEBUG,
        QL_VERBOSE.DISASM  : logging.DEBUG,
        QL_VERBOSE.DUMP    : logging.DEBUG
    }[verbose]

QL_INSTANCE_ID = 114514

# TODO: qltool compatibility
def ql_setup_logger(ql, log_file: Optional[str], console: bool, filters: Optional[Sequence], log_override: Optional[logging.Logger], log_plain: bool):
    global QL_INSTANCE_ID

    # If there is an override for our logger, then use it.
    if log_override is not None:
        log = log_override
    else:
        # We should leave the root logger untouched.
        log = logging.getLogger(f"qiling{QL_INSTANCE_ID}")
        QL_INSTANCE_ID += 1

        # Disable propagation to avoid duplicate output.
        log.propagate = False
        # Clear all handlers and filters.
        log.handlers = []
        log.filters = []

        # Do we have console output?
        if console:
            handler = logging.StreamHandler()

            if not log_plain and not sys.platform == "win32":
                formatter = QilingColoredFormatter(ql, FMT_STR)
            else:
                formatter = QilingPlainFormatter(ql, FMT_STR)

            handler.setFormatter(formatter)
            log.addHandler(handler)
        else:
            log.setLevel(logging.CRITICAL)

        # Do we have to write log to a file?
        if log_file is not None:
            handler = logging.FileHandler(log_file)
            formatter = QilingPlainFormatter(ql, FMT_STR)
            handler.setFormatter(formatter)
            log.addHandler(handler)

    # Remeber to add filters if necessary.
    # If there aren't any filters, we do add the filters until users specify any.
    log_filter = None

    if filters is not None and len(filters) != 0:
        log_filter = RegexFilter(filters)
        log.addFilter(log_filter)
    
    log.setLevel(logging.INFO)

    return log, log_filter


# verify if emulator returns properly
def verify_ret(ql, err):
    ql.log.debug("Got exception %u: init SP = %x, current SP = %x, PC = %x" %(err.errno, ql.os.init_sp, ql.reg.arch_sp, ql.reg.arch_pc))
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
                # 0x11626	 c3	  	ret
                # print("OK, stack balanced!")
                pass
            else:
                raise
        else:   # Win32
            if ql.os.init_sp + 12 == ql.reg.arch_sp:   # 12 = 8 + 4
                # 0x114dd	 c2 08 00	  	ret 	8
                pass
            else:
                raise
    else:
        raise        
