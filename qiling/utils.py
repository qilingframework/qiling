#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

"""
This module is intended for general purpose functions that can be used
thoughout the qiling framework
"""

from functools import partial
import importlib, os, copy, re, pefile, logging, yaml

from configparser import ConfigParser
from logging import LogRecord
from typing import Any, Container, IO, List, Optional, Sequence, TextIO, Tuple, Type, Union
from enum import Enum

from unicorn import UC_ERR_READ_UNMAPPED, UC_ERR_FETCH_UNMAPPED

from qiling.exception import *
from qiling.const import QL_VERBOSE, QL_ARCH, QL_ENDIAN, QL_OS, QL_DEBUGGER
from qiling.const import debugger_map, arch_map, os_map, arch_os_map, loader_map
from qiling.os.posix.const import NR_OPEN

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

class QlBaseFormatter(logging.Formatter):
    __level_tag = {
        'WARNING'  : '[!]',
        'INFO'     : '[=]',
        'DEBUG'    : '[+]',
        'CRITICAL' : '[x]',
        'ERROR'    : '[x]'
    }

    def __init__(self, ql, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ql = ql

    def get_level_tag(self, level: str) -> str:
        return self.__level_tag[level]

    def get_thread_tag(self, thread: str) -> str:
        return thread

    def format(self, record: LogRecord):
        # In case we have multiple formatters, we have to keep a copy of the record.
        record = copy.copy(record)

        # early logging may access ql.os when it is not yet set
        try:
            cur_thread = self.ql.os.thread_management.cur_thread
        except AttributeError:
            tid = f''
        else:
            tid = self.get_thread_tag(str(cur_thread))

        level = self.get_level_tag(record.levelname)
        record.levelname = f'{level} {tid}'

        return super().format(record)

class QlColoredFormatter(QlBaseFormatter):
    __level_color = {
        'WARNING'  : COLOR_CODE.YELLOW,
        'INFO'     : COLOR_CODE.BLUE,
        'DEBUG'    : COLOR_CODE.MAGENTA,
        'CRITICAL' : COLOR_CODE.CRIMSON,
        'ERROR'    : COLOR_CODE.RED
    }

    def get_level_tag(self, level: str) -> str:
        s = super().get_level_tag(level)

        return f'{self.__level_color[level]}{s}{COLOR_CODE.ENDC}'

    def get_thread_tag(self, tid: str) -> str:
        s = super().get_thread_tag(tid)

        return f'{COLOR_CODE.GREEN}{s}{COLOR_CODE.ENDC}'

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
    def __init__(self):
        self.__fds: List[Optional[IO]] = [None] * NR_OPEN

    def __len__(self):
        return len(self.__fds)

    def __getitem__(self, idx: int):
        return self.__fds[idx]

    def __setitem__(self, idx: int, val: Optional[IO]):
        self.__fds[idx] = val

    def __iter__(self):
        return iter(self.__fds)

    def __repr__(self):
        return repr(self.__fds)

    def save(self):
        return self.__fds

    def restore(self, fds):
        self.__fds = fds


def catch_KeyboardInterrupt(ql):
    def decorator(func):
        def wrapper(*args, **kw):
            try:
                return func(*args, **kw)
            except BaseException as e:
                ql.stop()
                ql._internal_exception = e

        return wrapper

    return decorator

def enum_values(e: Type[Enum]) -> Container:
    return e.__members__.values()

def ql_is_valid_ostype(ostype: QL_OS) -> bool:
    return ostype in enum_values(QL_OS)

def ql_is_valid_arch(arch: QL_ARCH) -> bool:
    return arch in enum_values(QL_ARCH)

def loadertype_convert_str(ostype: QL_OS) -> Optional[str]:
    return loader_map.get(ostype)

def __value_to_key(e: Type[Enum], val: Any) -> Optional[str]:
    key = e._value2member_map_[val]

    return None if key is None else key.name

def ostype_convert_str(ostype: QL_OS) -> Optional[str]:
    return __value_to_key(QL_OS, ostype)

def ostype_convert(ostype: str) -> Optional[QL_OS]:
    alias_map = {
        "darwin": "macos",
    }

    return os_map.get(alias_map.get(ostype, ostype))

def arch_convert_str(arch: QL_ARCH) -> Optional[str]:
    return __value_to_key(QL_ARCH, arch)

def arch_convert(arch: str) -> Optional[QL_ARCH]:
    alias_map = {
        "x86_64": "x8664",
        "riscv32": "riscv",
    }
    
    return arch_map.get(alias_map.get(arch, arch))

def arch_os_convert(arch: QL_ARCH) -> Optional[QL_OS]:
    return arch_os_map.get(arch)

def debugger_convert(debugger: str) -> Optional[QL_DEBUGGER]:
    return debugger_map.get(debugger)

def debugger_convert_str(debugger_id: QL_DEBUGGER) -> Optional[str]:
    return __value_to_key(QL_DEBUGGER, debugger_id)

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

def ql_elf_parse_emu_env(path: str) -> Tuple[Optional[QL_ARCH], Optional[QL_OS], Optional[QL_ENDIAN]]:
    # instead of using full-blown elffile parsing, we perform a simple parsing to avoid
    # external dependencies for target systems that do not need them.
    #
    # see: https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html

    # ei_class
    ELFCLASS32 = 1    # 32-bit
    ELFCLASS64 = 2    # 64-bit

    #ei_data
    ELFDATA2LSB = 1   # little-endian
    ELFDATA2MSB = 2   # big-endian

    # ei_osabi
    ELFOSABI_SYSV       = 0
    ELFOSABI_LINUX      = 3
    ELFOSABI_FREEBSD    = 9
    ELFOSABI_ARM_AEABI  = 64
    ELFOSABI_ARM        = 97
    ELFOSABI_STANDALONE = 255

    # e_machine
    EM_386     = 3
    EM_MIPS    = 8
    EM_ARM     = 40
    EM_X86_64  = 62
    EM_AARCH64 = 183
    EM_RISCV   = 243

    endianess = {
        ELFDATA2LSB : (QL_ENDIAN.EL, 'little'),
        ELFDATA2MSB : (QL_ENDIAN.EB, 'big')
    }

    machines32 = {
        EM_386   : QL_ARCH.X86,
        EM_MIPS  : QL_ARCH.MIPS,
        EM_ARM   : QL_ARCH.ARM,
        EM_RISCV : QL_ARCH.RISCV
    }

    machines64 = {
        EM_X86_64  : QL_ARCH.X8664,
        EM_AARCH64 : QL_ARCH.ARM64,
        EM_RISCV   : QL_ARCH.RISCV64
    }

    classes = {
        ELFCLASS32 : machines32,
        ELFCLASS64 : machines64
    }

    abis = {
        ELFOSABI_SYSV       : QL_OS.LINUX,
        ELFOSABI_LINUX      : QL_OS.LINUX,
        ELFOSABI_FREEBSD    : QL_OS.FREEBSD,
        ELFOSABI_ARM_AEABI  : QL_OS.LINUX,
        ELFOSABI_ARM        : QL_OS.LINUX,
        ELFOSABI_STANDALONE : QL_OS.BLOB
    }

    archtype = None
    ostype = None
    archendian = None

    with open(path, 'rb') as binfile:
        e_ident = binfile.read(16)
        e_type = binfile.read(2)
        e_machine = binfile.read(2)

        # qnx may be detected by the interpreter name: 'ldqnx.so'.
        # instead of properly parsing the file to locate the pt_interp
        # segment, we detect qnx fuzzily by looking for that string in
        # the first portion of the file.
        blob = binfile.read(0x200 - 20)

    if e_ident[:4] == b'\x7fELF':
        ei_class = e_ident[4]   # arch bits
        ei_data  = e_ident[5]   # arch endianess
        ei_osabi = e_ident[7]

        if ei_class in classes:
            machines = classes[ei_class]

            if ei_data in endianess:
                archendian, endian = endianess[ei_data]

                machine = int.from_bytes(e_machine, endian)

                if machine in machines:
                    archtype = machines[machine]

                if ei_osabi in abis:
                    ostype = abis[ei_osabi]

                    if blob and b'ldqnx.so' in blob:
                        ostype = QL_OS.QNX

    return archtype, ostype, archendian

def ql_macho_parse_emu_env(path: str) -> Tuple[Optional[QL_ARCH], Optional[QL_OS], Optional[QL_ENDIAN]]:
    macho_macos_sig64 = b'\xcf\xfa\xed\xfe'
    macho_macos_sig32 = b'\xce\xfa\xed\xfe'
    macho_macos_fat = b'\xca\xfe\xba\xbe'  # should be header for FAT

    arch = None
    ostype = None
    endian = None

    with open(path, 'rb') as f:
        ident = f.read(32)

    if ident[:4] in (macho_macos_sig32, macho_macos_sig64, macho_macos_fat):
        ostype = QL_OS.MACOS

        # if ident[7] == 0: # 32 bit
        #    arch = QL_ARCH.X86

        if ident[4] == 0x07 and ident[7] == 0x01:  # X86 64 bit
            endian = QL_ENDIAN.EL
            arch = QL_ARCH.X8664

        elif ident[4] == 0x0c and ident[7] == 0x01:  # ARM64
            endian = QL_ENDIAN.EL
            arch = QL_ARCH.ARM64

    return arch, ostype, endian


def ql_pe_parse_emu_env(path: str) -> Tuple[Optional[QL_ARCH], Optional[QL_OS], Optional[QL_ENDIAN]]:
    try:
        pe = pefile.PE(path, fast_load=True)
    except:
        return None, None, None

    arch = None
    ostype = None
    archendian = None

    machine_map = {
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']  : QL_ARCH.X86,
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'] : QL_ARCH.X8664,
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM']   : QL_ARCH.ARM,
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_THUMB'] : QL_ARCH.ARM,
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM64'] : QL_ARCH.ARM64
    }

    # get arch
    arch = machine_map.get(pe.FILE_HEADER.Machine)

    if arch:
        subsystem_uefi = (
            pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_EFI_APPLICATION'],
            pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER'],
            pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER'],
            pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_EFI_ROM']
        )

        if pe.OPTIONAL_HEADER.Subsystem in subsystem_uefi:
            ostype = QL_OS.UEFI
        else:
            ostype = QL_OS.WINDOWS

        archendian = QL_ENDIAN.EL

    return arch, ostype, archendian


def ql_guess_emu_env(path: str) -> Tuple[Optional[QL_ARCH], Optional[QL_OS], Optional[QL_ENDIAN]]:
    arch = None
    ostype = None
    endian = None

    if os.path.isdir(path) and path.endswith('.kext'):
        return QL_ARCH.X8664, QL_OS.MACOS, QL_ENDIAN.EL

    if os.path.isfile(path) and path.endswith('.DOS_COM'):
        return QL_ARCH.A8086, QL_OS.DOS, QL_ENDIAN.EL

    if os.path.isfile(path) and path.endswith('.DOS_MBR'):
        return QL_ARCH.A8086, QL_OS.DOS, QL_ENDIAN.EL

    if os.path.isfile(path) and path.endswith('.DOS_EXE'):
        return QL_ARCH.A8086, QL_OS.DOS, QL_ENDIAN.EL

    arch, ostype, endian = ql_elf_parse_emu_env(path)

    if arch is None or ostype is None or endian is None:
        arch, ostype, endian = ql_macho_parse_emu_env(path)

    if arch is None or ostype is None or endian is None:
        arch, ostype, endian = ql_pe_parse_emu_env(path)

    return arch, ostype, endian


def loader_setup(ql, ostype: QL_OS, libcache: bool):
    args = [libcache] if ostype == QL_OS.WINDOWS else []

    qlloader_name = loadertype_convert_str(ostype)
    qlloader_path = f'qiling.loader.{qlloader_name.lower()}'
    qlloader_class = f'QlLoader{qlloader_name.upper()}'

    obj = ql_get_module_function(qlloader_path, qlloader_class)

    return obj(ql, *args)


def component_setup(component_type: str, component_name: str, ql):
    component_path = f'qiling.{component_type}.{component_name}'
    component_class = f'Ql{component_name.capitalize()}Manager'

    obj = ql_get_module_function(component_path, component_class)

    return obj(ql)


def debugger_setup(options: Union[str, bool], ql):
    if options is True:
        options = 'gdb'

    if type(options) is str:
        objname, *args = options.split(':')

        if debugger_convert(objname) not in enum_values(QL_DEBUGGER):
            raise QlErrorOutput('Debugger not supported')

        obj = ql_get_module_function(f'qiling.debugger.{objname}.{objname}', f'Ql{str.capitalize(objname)}')

        return obj(ql, *args)

    return None

def arch_setup(archtype: QL_ARCH, endian: QL_ENDIAN, thumb: bool, ql):
    # set endianess and thumb mode for arm-based archs
    if archtype == QL_ARCH.ARM:
        args = [endian, thumb]

    # set endianess for mips arch
    elif archtype == QL_ARCH.MIPS:
        args = [endian]

    else:
        args = []

    module = {
        QL_ARCH.A8086    : r'x86',
        QL_ARCH.X86      : r'x86',
        QL_ARCH.X8664    : r'x86',
        QL_ARCH.ARM      : r'arm',
        QL_ARCH.ARM64    : r'arm64',
        QL_ARCH.MIPS     : r'mips',
        QL_ARCH.EVM      : r'evm.evm',
        QL_ARCH.CORTEX_M : r'cortex_m',
        QL_ARCH.RISCV    : r'riscv',
        QL_ARCH.RISCV64  : r'riscv64'
    }[archtype]

    qlarch_path = f'qiling.arch.{module}'
    qlarch_class = f'QlArch{arch_convert_str(archtype).upper()}'

    obj = ql_get_module_function(qlarch_path, qlarch_class)

    return obj(ql, *args)


# This function is extracted from os_setup (QlOsPosix) so I put it here.
def ql_syscall_mapping_function(ostype: QL_OS, archtype: QL_ARCH):
    qlos_name = ostype_convert_str(ostype)
    qlos_path = f'qiling.os.{qlos_name.lower()}.map_syscall'
    qlos_func = 'get_syscall_mapper'

    func = ql_get_module_function(qlos_path, qlos_func)

    return func(archtype)


def os_setup(ostype: QL_OS, ql):
    qlos_name = ostype_convert_str(ostype)
    qlos_path = f'qiling.os.{qlos_name.lower()}.{qlos_name.lower()}'
    qlos_class = f'QlOs{qlos_name.capitalize()}'

    obj = ql_get_module_function(qlos_path, qlos_class)

    return obj(ql)


def profile_setup(ql, ostype: QL_OS, filename: Optional[str]):
    ql.log.debug(f'Profile: {filename or "default"}')

    # mcu uses a yaml-based config
    if ostype == QL_OS.MCU:
        if filename:
            with open(filename) as f:
                config = yaml.load(f, Loader=yaml.Loader)
        else:
            config = {}

    else:
        qiling_home = os.path.dirname(os.path.abspath(__file__))
        os_profile = os.path.join(qiling_home, 'profiles', f'{ostype_convert_str(ostype).lower()}.ql')

        profiles = [os_profile]

        if filename:
            profiles.append(filename)

        # patch 'getint' to convert integers of all bases
        int_converter = partial(int, base=0)

        config = ConfigParser(converters={'int': int_converter})
        config.read(profiles)

    return config

def ql_resolve_logger_level(verbose: QL_VERBOSE) -> int:
    return {
        QL_VERBOSE.DISABLED: logging.CRITICAL,
        QL_VERBOSE.OFF     : logging.WARNING, 
        QL_VERBOSE.DEFAULT : logging.INFO,
        QL_VERBOSE.DEBUG   : logging.DEBUG,
        QL_VERBOSE.DISASM  : logging.DEBUG,
        QL_VERBOSE.DUMP    : logging.DEBUG
    }[verbose]

QL_INSTANCE_ID = 114514

def __is_color_terminal(stream: TextIO) -> bool:
    """Determine whether standard output is attached to a color terminal.

    see: https://stackoverflow.com/questions/53574442/how-to-reliably-test-color-capability-of-an-output-terminal-in-python3
    """

    def __handle_nt(fd: int) -> bool:
        import ctypes
        import msvcrt

        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 4

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        hstdout = msvcrt.get_osfhandle(fd)
        mode = ctypes.c_ulong()

        return kernel32.GetConsoleMode(hstdout, ctypes.byref(mode)) and (mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0)

    def __handle_posix(fd: int) -> bool:
        import curses

        try:
            curses.setupterm(fd=fd)
        except curses.error:
            return True
        else:
            return curses.tigetnum('colors') > 0

    def __default(_: int) -> bool:
        return True

    handlers = {
        'nt'    : __handle_nt,
        'posix' : __handle_posix
    }

    handler = handlers.get(os.name, __default)

    return handler(stream.fileno())

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

            if log_plain or not __is_color_terminal(handler.stream):
                formatter = QlBaseFormatter(ql, FMT_STR)
            else:
                formatter = QlColoredFormatter(ql, FMT_STR)

            handler.setFormatter(formatter)
            log.addHandler(handler)
        else:
            handler = logging.NullHandler()
            log.addHandler(handler)

        # Do we have to write log to a file?
        if log_file is not None:
            handler = logging.FileHandler(log_file)
            formatter = QlBaseFormatter(ql, FMT_STR)
            handler.setFormatter(formatter)
            log.addHandler(handler)

    # Remeber to add filters if necessary.
    # If there aren't any filters, we do add the filters until users specify any.
    log_filter = None

    if filters:
        log_filter = RegexFilter(filters)
        log.addFilter(log_filter)

    log.setLevel(logging.INFO)

    return log, log_filter


# verify if emulator returns properly
def verify_ret(ql, err):
    ql.log.debug("Got exception %u: init SP = %x, current SP = %x, PC = %x" %(err.errno, ql.os.init_sp, ql.arch.regs.arch_sp, ql.arch.regs.arch_pc))

    ql.os.RUN = False

    # timeout is acceptable in this case
    if err.errno in (UC_ERR_READ_UNMAPPED, UC_ERR_FETCH_UNMAPPED):
        if ql.os.type == QL_OS.MACOS:
            if ql.loader.kext_name:
                # FIXME: Should I push saved RIP before every method callings of IOKit object?
                if ql.os.init_sp == ql.arch.regs.arch_sp - 8:
                    pass
                else:
                    raise

        if ql.arch.type == QL_ARCH.X8664: # Win64
            if ql.os.init_sp == ql.arch.regs.arch_sp or ql.os.init_sp + 8 == ql.arch.regs.arch_sp or ql.os.init_sp + 0x10 == ql.arch.regs.arch_sp:  # FIXME
                # 0x11626	 c3	  	ret
                # print("OK, stack balanced!")
                pass
            else:
                raise
        else:   # Win32
            if ql.os.init_sp + 12 == ql.arch.regs.arch_sp:   # 12 = 8 + 4
                # 0x114dd	 c2 08 00	  	ret 	8
                pass
            else:
                raise
    else:
        raise
