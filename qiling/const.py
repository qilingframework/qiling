#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import Enum, IntEnum
from typing import Any, Mapping, Type

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
    RISCV = 110
    RISCV64 = 111

class QL_OS(IntEnum):
    LINUX = 201
    FREEBSD = 202
    MACOS = 203
    WINDOWS = 204
    UEFI = 205
    DOS = 206
    EVM = 207
    QNX = 208
    MCU = 209
    BLOB = 210

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

QL_OS_NONPID            = (QL_OS.DOS, QL_OS.UEFI)
QL_OS_POSIX             = (QL_OS.LINUX, QL_OS.FREEBSD, QL_OS.MACOS, QL_OS.QNX)

QL_OS_BAREMETAL   = (QL_OS.MCU,)
QL_OS_INTERPRETER = (QL_OS.EVM,)

QL_HOOK_BLOCK = 0b0001
QL_CALL_BLOCK = 0b0010

def __reverse_enum(e: Type[Enum]) -> Mapping[str, Any]:
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
    QL_OS.EVM     : "EVM",
    QL_OS.MCU     : "MCU",
    QL_OS.BLOB    : "BLOB"
}

arch_os_map = {
    QL_ARCH.EVM: QL_OS.EVM,
}
