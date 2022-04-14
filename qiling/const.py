#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import Enum, Flag, IntEnum
from typing import Any, Mapping, Type

class QL_ENDIAN(IntEnum):
    EL = 1
    EB = 2

class QL_ARCH(IntEnum):
    X86 = 101
    X8664 = 102
    ARM = 103
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

class QL_STOP(Flag):
    NONE = 0
    STACK_POINTER = (1 << 0)
    EXIT_TRAP     = (1 << 1)

QL_ARCH_INTERPRETER = (QL_ARCH.EVM,)

QL_OS_NONPID      = (QL_OS.DOS, QL_OS.UEFI)
QL_OS_POSIX       = (QL_OS.LINUX, QL_OS.FREEBSD, QL_OS.MACOS, QL_OS.QNX)
QL_OS_BAREMETAL   = (QL_OS.MCU,)

QL_HOOK_BLOCK = 0b0001
QL_CALL_BLOCK = 0b0010

def __reverse_enum(e: Type[Enum]) -> Mapping[str, Any]:
    '''Create a reverse mapping for an enum.
    '''

    return dict((v.name.lower(), v) for v in e.__members__.values())

debugger_map: Mapping[str, QL_DEBUGGER] = __reverse_enum(QL_DEBUGGER)
arch_map    : Mapping[str, QL_ARCH]     = __reverse_enum(QL_ARCH)
os_map      : Mapping[str, QL_OS]       = __reverse_enum(QL_OS)
verbose_map : Mapping[str, QL_VERBOSE]  = __reverse_enum(QL_VERBOSE)

arch_os_map = {
    QL_ARCH.EVM      : QL_OS.EVM,
    QL_ARCH.CORTEX_M : QL_OS.MCU
}
