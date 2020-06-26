#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from enum import IntEnum

class QL_ENDIAN(IntEnum):
    EL = 1
    EB = 2


class QL_ARCH(IntEnum):
    X86 = 1
    X8664 = 2
    ARM = 3
    ARM_THUMB = 4
    ARM64 = 5
    MIPS = 6


class QL_OS(IntEnum):
    LINUX = 1
    FREEBSD = 2
    MACOS = 3
    WINDOWS = 4
    POSIX = 5
    UEFI = 6


class QL_OUTPUT(IntEnum):
    OFF = 1
    DEFAULT = 2
    DISASM = 3
    DEBUG = 4
    DUMP = 5


class QL_DEBUGGER(IntEnum):
    GDB = 1
    IDAPRO = 2


class QL_INTERCEPT(IntEnum):
    CALL = 1
    ENTER = 2
    EXIT = 3


D_INFO = 1 # General debug information
D_PROT = 2 # Protocol level debug, print out open file flag
D_CTNT = 3 # Print out content. File content or content of a tcp stream
D_RPRT = 4 # Reporting output, main summarizing purposes

QL_DEBUGGER_ALL = [QL_DEBUGGER.IDAPRO, QL_DEBUGGER.GDB]
QL_ARCH_ALL = [QL_ARCH.X86, QL_ARCH.X8664, QL_ARCH.ARM, QL_ARCH.ARM64, QL_ARCH.MIPS]
QL_ENDINABLE = [QL_ARCH.MIPS, QL_ARCH.ARM]
QL_OS_ALL = [QL_OS.LINUX, QL_OS.FREEBSD, QL_OS.MACOS, QL_OS.WINDOWS, QL_OS.POSIX, QL_OS.UEFI]
QL_POSIX = [QL_OS.LINUX, QL_OS.FREEBSD, QL_OS.MACOS]

QL_HOOK_BLOCK = 0b1
QL_CALL_BLOCK = 0b10

debugger_map = {
        "gdb": QL_DEBUGGER.GDB,
        "ida": QL_DEBUGGER.IDAPRO,
    }

arch_map = {
        "x86": QL_ARCH.X86,
        "x8664": QL_ARCH.X8664,
        "mips": QL_ARCH.MIPS,
        "arm": QL_ARCH.ARM,
        "arm64": QL_ARCH.ARM64,
    }

os_map = {
        "linux": QL_OS.LINUX,
        "macos": QL_OS.MACOS,
        "freebsd": QL_OS.FREEBSD,
        "windows": QL_OS.WINDOWS,
        "uefi": QL_OS.UEFI,
}