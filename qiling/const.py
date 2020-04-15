#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from enum import IntEnum

class QL_ENDIAN(IntEnum):
    EL = 1
    EB = 2

QL_X86 = 1
QL_X8664 = 2
QL_ARM = 3
QL_ARM_THUMB = 4
QL_ARM64 = 5
QL_MIPS32 = 6

QL_LINUX = 1
QL_FREEBSD = 2
QL_MACOS = 3
QL_WINDOWS = 4
QL_POSIX = 5

class QL_OUTPUT(IntEnum):
    DEFAULT = 1
    DISASM = 2
    DEBUG = 3
    DUMP = 99

QL_GDB = 1
QL_IDAPRO = 2

D_INFO = 1 # GENERAL DEBUG INFO
D_PROT = 2 # FLAG, PROTOCOL DEBUG INFO
D_CONT = 3 # Print out content
D_RPRT = 4 # Extrame OUTPUT

QL_DEBUGGER = [QL_IDAPRO, QL_GDB]
QL_ARCH = [QL_ARM, QL_ARM64, QL_MIPS32, QL_X86, QL_X8664]
QL_ENDINABLE = [QL_MIPS32, QL_ARM]
QL_OS = [QL_LINUX, QL_FREEBSD, QL_MACOS, QL_WINDOWS]
QL_POSIX = [QL_LINUX, QL_FREEBSD, QL_MACOS]
