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
    DISABLED = -1 # turn off all the output
    OFF = 0       # output only warnings 
    DEFAULT = 1   # output warnings and Qiling execute process information
    DEBUG = 4     # output all logs above and debug information, include syscall information
    DISASM = 10   # output all assembly instructions during Qiling execution
    DUMP = 20     # output any log Qiling can, include instructions and registers

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
QL_ARCH_32BIT  = (QL_ARCH.ARM, QL_ARCH.ARM_THUMB, QL_ARCH.MIPS, QL_ARCH.X86, QL_ARCH.CORTEX_M, QL_ARCH.RISCV)
QL_ARCH_64BIT  = (QL_ARCH.ARM64, QL_ARCH.X8664, QL_ARCH.RISCV64)

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
