#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import EnumMeta, IntEnum
from typing import Mapping, TypeVar

class QL_ENDIAN(IntEnum):
    EL = 1
    EB = 2

class QL_ARCH(IntEnum):
    X86 = 101
    X8664 = 102
    ARM = 103
    ARM_THUMB = 104
    ARM64 = 105
    MIPS = 106
    A8086 = 107
    EVM = 108
    CORTEX_M = 109

class QL_OS(IntEnum):
    LINUX = 201
    FREEBSD = 202
    MACOS = 203
    WINDOWS = 204
    UEFI = 205
    DOS = 206
    EVM = 207
    QNX = 208

class QL_MCU(IntEnum):
    STM32F411 = 301

class QL_VERBOSE(IntEnum):
    OFF = 0
    DEFAULT = 1
    DEBUG = 4
    DISASM = 10
    DUMP = 20

class QL_DEBUGGER(IntEnum):
    GDB = 1
    IDAPRO = 2
    QDB = 3

class QL_INTERCEPT(IntEnum):
    CALL = 1
    ENTER = 2
    EXIT = 3

QL_DEBUGGER_ALL = (QL_DEBUGGER.IDAPRO, QL_DEBUGGER.GDB, QL_DEBUGGER.QDB)

QL_ARCH_ENDIAN = (QL_ARCH.MIPS, QL_ARCH.ARM)
QL_ARCH_1BIT   = (QL_ARCH.EVM,)
QL_ARCH_16BIT  = (QL_ARCH.A8086,)
QL_ARCH_32BIT  = (QL_ARCH.ARM, QL_ARCH.ARM_THUMB, QL_ARCH.MIPS, QL_ARCH.X86)
QL_ARCH_64BIT  = (QL_ARCH.ARM64, QL_ARCH.X8664)
QL_ARCH_MCU32   = (QL_ARCH.CORTEX_M,)
QL_ARCH_MCU    = QL_ARCH_MCU32

QL_OS_NONPID        = (QL_OS.DOS, QL_OS.UEFI)
QL_ARCH_HARDWARE    = QL_ARCH_MCU
QL_ARCH_NONEOS      = (QL_ARCH.EVM,)
QL_OS_POSIX         = (QL_OS.LINUX, QL_OS.FREEBSD, QL_OS.MACOS, QL_OS.QNX)
QL_OS_ALL           = QL_OS_POSIX + QL_OS_NONPID + (QL_OS.WINDOWS,)

QL_HOOK_BLOCK = 0b0001
QL_CALL_BLOCK = 0b0010

__QL_CE = TypeVar('__QL_CE', QL_DEBUGGER, QL_ARCH, QL_OS, QL_VERBOSE)

def __reverse_enum(e: EnumMeta) -> Mapping[str, __QL_CE]:
    '''Create a reverse mapping for an enum.
    '''

    return dict((v.name.lower(), v.value) for v in e.__members__.values())

debugger_map: Mapping[str, QL_DEBUGGER] = __reverse_enum(QL_DEBUGGER)
arch_map    : Mapping[str, QL_ARCH]     = __reverse_enum(QL_ARCH)
os_map      : Mapping[str, QL_OS]       = __reverse_enum(QL_OS)
verbose_map : Mapping[str, QL_VERBOSE]  = __reverse_enum(QL_VERBOSE)

loader_map = {
    QL_OS.LINUX   : "ELF",
    QL_OS.FREEBSD : "ELF",
    QL_OS.QNX     : "ELF",
    QL_OS.MACOS   : "MACHO",
    QL_OS.WINDOWS : "PE",
    QL_OS.UEFI    : "PE_UEFI",
    QL_OS.DOS     : "DOS",
    QL_OS.EVM     : "EVM"
}

arch_os_map = {
    QL_ARCH.EVM: QL_OS.EVM
}
