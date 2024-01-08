#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

"""
This module is intended for general purpose functions that can be used
thoughout the qiling framework
"""

import importlib
import inspect
import os

from functools import partial
from configparser import ConfigParser
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any, Callable, Mapping, Optional, Tuple, TypeVar, Union

from unicorn import UC_ERR_READ_UNMAPPED, UC_ERR_FETCH_UNMAPPED

from qiling.arch.models import QL_CPU
from qiling.const import QL_ARCH, QL_ENDIAN, QL_OS, QL_DEBUGGER
from qiling.const import debugger_map, arch_map, os_map, arch_os_map
from qiling.exception import *

if TYPE_CHECKING:
    from qiling import Qiling
    from qiling.arch.arch import QlArch
    from qiling.debugger.debugger import QlDebugger
    from qiling.loader.loader import QlLoader
    from qiling.os.os import QlOs

T = TypeVar('T')
QlClassInit = Callable[['Qiling'], T]


def __name_to_enum(name: str, mapping: Mapping[str, T], aliases: Mapping[str, str] = {}) -> Optional[T]:
    key = name.casefold()

    return mapping.get(aliases.get(key) or key)


def os_convert(os: str) -> Optional[QL_OS]:
    alias_map = {
        'darwin': 'macos'
    }

    return __name_to_enum(os, os_map, alias_map)


def arch_convert(arch: str) -> Optional[QL_ARCH]:
    alias_map = {
        'x86_64':  'x8664',
        'riscv32': 'riscv'
    }

    return __name_to_enum(arch, arch_map, alias_map)


def debugger_convert(debugger: str) -> Optional[QL_DEBUGGER]:
    return __name_to_enum(debugger, debugger_map)


def arch_os_convert(arch: QL_ARCH) -> Optional[QL_OS]:
    return arch_os_map.get(arch)


def ql_get_module(module_name: str) -> ModuleType:
    try:
        module = importlib.import_module(module_name, 'qiling')
    except (ModuleNotFoundError, KeyError):
        raise QlErrorModuleNotFound(f'Unable to import module {module_name}')

    return module


def ql_get_module_function(module_name: str, member_name: str):
    module = ql_get_module(module_name)

    try:
        member = getattr(module, member_name)
    except AttributeError:
        raise QlErrorModuleFunctionNotFound(f'Unable to import {member_name} from {module_name}')

    return member


def __emu_env_from_pathname(path: str) -> Tuple[Optional[QL_ARCH], Optional[QL_OS], Optional[QL_ENDIAN]]:
    if os.path.isdir(path) and path.endswith('.kext'):
        return QL_ARCH.X8664, QL_OS.MACOS, QL_ENDIAN.EL

    if os.path.isfile(path):
        _, ext = os.path.splitext(path)

        if ext in ('.DOS_COM', '.DOS_MBR', '.DOS_EXE'):
            return QL_ARCH.A8086, QL_OS.DOS, QL_ENDIAN.EL

    return None, None, None


def __emu_env_from_elf(path: str) -> Tuple[Optional[QL_ARCH], Optional[QL_OS], Optional[QL_ENDIAN]]:
    # instead of using full-blown elffile parsing, we perform a simple parsing to avoid
    # external dependencies for target systems that do not need them.
    #
    # see: https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html

    # ei_class
    ELFCLASS32 = 1    # 32-bit
    ELFCLASS64 = 2    # 64-bit

    # ei_data
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
    EM_PPC     = 20

    endianess = {
        ELFDATA2LSB: (QL_ENDIAN.EL, 'little'),
        ELFDATA2MSB: (QL_ENDIAN.EB, 'big')
    }

    machines32 = {
        EM_386   : QL_ARCH.X86,
        EM_MIPS  : QL_ARCH.MIPS,
        EM_ARM   : QL_ARCH.ARM,
        EM_RISCV : QL_ARCH.RISCV,
        EM_PPC   : QL_ARCH.PPC
    }

    machines64 = {
        EM_X86_64  : QL_ARCH.X8664,
        EM_AARCH64 : QL_ARCH.ARM64,
        EM_RISCV   : QL_ARCH.RISCV64
    }

    classes = {
        ELFCLASS32: machines32,
        ELFCLASS64: machines64
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


def __emu_env_from_macho(path: str) -> Tuple[Optional[QL_ARCH], Optional[QL_OS], Optional[QL_ENDIAN]]:
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


def __emu_env_from_pe(path: str) -> Tuple[Optional[QL_ARCH], Optional[QL_OS], Optional[QL_ENDIAN]]:
    import pefile

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
    guessing_methods = (
        __emu_env_from_pathname,
        __emu_env_from_elf,
        __emu_env_from_macho,
        __emu_env_from_pe
    )

    for gm in guessing_methods:
        arch, ostype, endian = gm(path)

        if None not in (arch, ostype, endian):
            break
    else:
        arch, ostype, endian = (None, ) * 3

    return arch, ostype, endian


def select_loader(ostype: QL_OS, libcache: bool) -> QlClassInit['QlLoader']:
    kwargs = {}

    if ostype is QL_OS.WINDOWS:
        kwargs['libcache'] = libcache

    module = {
        QL_OS.LINUX   : r'elf',
        QL_OS.FREEBSD : r'elf',
        QL_OS.QNX     : r'elf',
        QL_OS.MACOS   : r'macho',
        QL_OS.WINDOWS : r'pe',
        QL_OS.UEFI    : r'pe_uefi',
        QL_OS.DOS     : r'dos',
        QL_OS.MCU     : r'mcu',
        QL_OS.BLOB    : r'blob'
    }[ostype]

    qlloader_path = f'.loader.{module}'
    qlloader_class = f'QlLoader{module.upper()}'

    obj = ql_get_module_function(qlloader_path, qlloader_class)

    return partial(obj, **kwargs)


def select_component(component_type: str, component_name: str, **kwargs) -> QlClassInit[Any]:
    component_path = f'.{component_type}.{component_name}'
    component_class = f'Ql{component_name.capitalize()}Manager'

    obj = ql_get_module_function(component_path, component_class)

    return partial(obj, **kwargs)


def select_debugger(options: Union[str, bool]) -> Optional[QlClassInit['QlDebugger']]:
    if options is True:
        options = 'gdb'

    if type(options) is str:
        objname, *args = options.split(':')
        dbgtype = debugger_convert(objname)

        if dbgtype == QL_DEBUGGER.GDB:
            kwargs = dict(zip(('ip', 'port'), args))

        elif dbgtype == QL_DEBUGGER.QDB:
            kwargs = {}

            def __int_nothrow(v: str, /) -> Optional[int]:
                try:
                    return int(v, 0)
                except ValueError:
                    return None

            # qdb init args are independent and may include any combination of: rr enable, init hook and script
            arg_init_hook = []
            for arg in args:
                if arg == 'rr':
                    kwargs['rr'] = True

                elif __int_nothrow(arg) is not None:
                     arg_init_hook.append(arg)

                else:
                    kwargs['script'] = arg
            else:
                kwargs['init_hook'] = arg_init_hook

        else:
            raise QlErrorOutput('Debugger not supported')

        obj = ql_get_module_function(f'.debugger.{objname}.{objname}', f'Ql{str.capitalize(objname)}')

        return partial(obj, **kwargs)

    return None


def select_arch(archtype: QL_ARCH, cputype: Optional[QL_CPU], endian: QL_ENDIAN, thumb: bool) -> QlClassInit['QlArch']:
    kwargs = {'cputype': cputype}

    # set endianess and thumb mode for arm-based archs
    if archtype is QL_ARCH.ARM:
        kwargs['endian'] = endian
        kwargs['thumb'] = thumb

    # set endianess for mips arch
    elif archtype is QL_ARCH.MIPS:
        kwargs['endian'] = endian

    module = {
        QL_ARCH.A8086    : r'x86',
        QL_ARCH.X86      : r'x86',
        QL_ARCH.X8664    : r'x86',
        QL_ARCH.ARM      : r'arm',
        QL_ARCH.ARM64    : r'arm64',
        QL_ARCH.MIPS     : r'mips',
        QL_ARCH.CORTEX_M : r'cortex_m',
        QL_ARCH.RISCV    : r'riscv',
        QL_ARCH.RISCV64  : r'riscv64',
        QL_ARCH.PPC      : r'ppc'
    }[archtype]

    qlarch_path = f'.arch.{module}'
    qlarch_class = f'QlArch{archtype.name.upper()}'

    obj = ql_get_module_function(qlarch_path, qlarch_class)

    return partial(obj, **kwargs)


def select_os(ostype: QL_OS) -> QlClassInit['QlOs']:
    qlos_name = ostype.name
    qlos_path = f'.os.{qlos_name.lower()}.{qlos_name.lower()}'
    qlos_class = f'QlOs{qlos_name.capitalize()}'

    obj = ql_get_module_function(qlos_path, qlos_class)

    return partial(obj)


def profile_setup(ostype: QL_OS, user_config: Optional[Union[str, dict]]):
    # mcu uses a yaml-based config
    if ostype is QL_OS.MCU:
        import yaml

        if user_config:
            with open(user_config) as f:
                config = yaml.load(f, Loader=yaml.SafeLoader)
        else:
            config = {}

    else:
        # patch 'getint' to convert integers of all bases
        int_converter = partial(int, base=0)
        config = ConfigParser(converters={'int': int_converter})

        qiling_home = Path(inspect.getfile(profile_setup)).parent
        os_profile = qiling_home / 'profiles' / f'{ostype.name.lower()}.ql'

        # read default profile first
        config.read(os_profile)

        # user-specified profile adds or overrides existing setting
        if isinstance(user_config, dict):
            config.read_dict(user_config)

        elif user_config:
            config.read(user_config)

    return config


# verify if emulator returns properly
def verify_ret(ql: 'Qiling', err):
    # init_sp location is not consistent; this is here to work around that
    if not hasattr(ql.os, 'init_sp'):
        ql.os.init_sp = ql.loader.init_sp

    ql.log.debug("Got exception %u: init SP = %x, current SP = %x, PC = %x" %(err.errno, ql.os.init_sp, ql.arch.regs.arch_sp, ql.arch.regs.arch_pc))

    if hasattr(ql.os, 'RUN'):
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
                # 0x11626     c3          ret
                # print("OK, stack balanced!")
                pass
            else:
                raise
        else:   # Win32
            if ql.os.init_sp + 12 == ql.arch.regs.arch_sp:   # 12 = 8 + 4
                # 0x114dd     c2 08 00          ret     8
                pass
            else:
                raise
    else:
        raise


__all__ = [
    'os_convert',
    'arch_convert',
    'debugger_convert',
    'arch_os_convert',
    'ql_get_module',
    'ql_get_module_function',
    'ql_guess_emu_env',
    'select_os',
    'select_arch',
    'select_loader',
    'select_debugger',
    'select_component',
    'profile_setup',
    'verify_ret'
]
