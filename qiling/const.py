#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum

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


class QL_OS(IntEnum):
    LINUX = 201
    FREEBSD = 202
    MACOS = 203
    WINDOWS = 204
    UEFI = 205
    DOS = 206


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
QL_ARCH_16BIT  = (QL_ARCH.A8086,)
QL_ARCH_32BIT  = (QL_ARCH.ARM, QL_ARCH.ARM_THUMB, QL_ARCH.MIPS, QL_ARCH.X86)
QL_ARCH_64BIT  = (QL_ARCH.ARM64, QL_ARCH.X8664)
QL_ARCH_ALL    = QL_ARCH_16BIT + QL_ARCH_32BIT + QL_ARCH_64BIT

QL_OS_NONPID = (QL_OS.DOS, QL_OS.UEFI)
QL_OS_POSIX  = (QL_OS.LINUX, QL_OS.FREEBSD, QL_OS.MACOS)
QL_OS_ALL    = QL_OS_POSIX + QL_OS_NONPID + (QL_OS.WINDOWS,)

QL_HOOK_BLOCK = 0b0001
QL_CALL_BLOCK = 0b0010

debugger_map = {
    "gdb" : QL_DEBUGGER.GDB,
    "ida" : QL_DEBUGGER.IDAPRO,
    "qdb" : QL_DEBUGGER.QDB
}

arch_map = {
    "x86"       : QL_ARCH.X86,
    "x8664"     : QL_ARCH.X8664,
    "mips"      : QL_ARCH.MIPS,
    "arm"       : QL_ARCH.ARM,
    "arm_thumb" : QL_ARCH.ARM_THUMB,
    "arm64"     : QL_ARCH.ARM64,
    "a8086"     : QL_ARCH.A8086
}

os_map = {
    "linux"   : QL_OS.LINUX,
    "macos"   : QL_OS.MACOS,
    "freebsd" : QL_OS.FREEBSD,
    "windows" : QL_OS.WINDOWS,
    "uefi"    : QL_OS.UEFI,
    "dos"     : QL_OS.DOS
}