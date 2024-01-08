#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import Enum, Flag, IntEnum
from typing import Final, Mapping, Type, TypeVar


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
    CORTEX_M = 109
    RISCV = 110
    RISCV64 = 111
    PPC = 112


class QL_OS(IntEnum):
    LINUX = 201
    FREEBSD = 202
    MACOS = 203
    WINDOWS = 204
    UEFI = 205
    DOS = 206
    QNX = 208
    MCU = 209
    BLOB = 210


class QL_VERBOSE(IntEnum):
    DISABLED = -1   # turn off all the output
    OFF = 0         # output only warnings
    DEFAULT = 1     # output warnings and Qiling execute process information
    DEBUG = 4       # output all logs above and debug information, include syscall information
    DISASM = 10     # output all assembly instructions during Qiling execution
    DUMP = 20       # output any log Qiling can, include instructions and registers


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
    EXIT_TRAP = (1 << 1)


class QL_STATE(Enum):
    NOT_SET = 0
    STARTED = 1
    STOPPED = 2


QL_OS_POSIX: Final = (QL_OS.LINUX, QL_OS.FREEBSD, QL_OS.MACOS, QL_OS.QNX)
QL_OS_BAREMETAL: Final = (QL_OS.MCU,)


QL_HOOK_BLOCK = 0b0001
QL_CALL_BLOCK = 0b0010

T = TypeVar('T', bound=Enum)


def __casefold_enum(e: Type[T]) -> Mapping[str, T]:
    '''Create a casefolded mapping of an enum to allow case-insensitive lookup.
    '''

    return dict((k.casefold(), v) for k, v in e.__members__.items())


endian_map   = __casefold_enum(QL_ENDIAN)
arch_map     = __casefold_enum(QL_ARCH)
os_map       = __casefold_enum(QL_OS)
verbose_map  = __casefold_enum(QL_VERBOSE)
debugger_map = __casefold_enum(QL_DEBUGGER)

arch_os_map = {
    QL_ARCH.CORTEX_M : QL_OS.MCU
}

__all__ = [
    'QL_ENDIAN', 'QL_ARCH', 'QL_OS', 'QL_VERBOSE', 'QL_DEBUGGER', 'QL_INTERCEPT', 'QL_STOP',
    'QL_OS_POSIX', 'QL_OS_BAREMETAL', 'QL_HOOK_BLOCK', 'QL_CALL_BLOCK'
]
