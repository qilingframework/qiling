#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

"""
This module is intended for general purpose functions that are only used in qiling.arch
"""

from unicorn import UcError, UC_ERR_READ_UNMAPPED, UC_ERR_FETCH_UNMAPPED
from keystone import *
from capstone import *

from qiling.const import QL_ARCH, QL_ARCH_ALL, QL_ENDIAN, QL_OS, QL_OS_ALL, QL_DEBUGGER, QL_ARCH_32BIT, QL_ARCH_64BIT, QL_ARCH_16BIT
from qiling.exception import *


def ql_create_disassembler(archtype, archendian, reg_cpsr=None):
    if archtype == QL_ARCH.ARM:  # QL_ARM
        mode = CS_MODE_ARM
        if archendian == QL_ENDIAN.EB:
            # TODO: Test for big endian.
            reg_cpsr_v = 0b100000
            # reg_cpsr_v = 0b000000
        else:
            reg_cpsr_v = 0b100000

        if reg_cpsr & reg_cpsr_v != 0:
            mode = CS_MODE_THUMB

        if archendian == QL_ENDIAN.EB:
            md = Cs(CS_ARCH_ARM, mode)
            # md = Cs(CS_ARCH_ARM, mode + CS_MODE_BIG_ENDIAN)
        else:
            md = Cs(CS_ARCH_ARM, mode)

    elif archtype == QL_ARCH.ARM_THUMB:
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    elif archtype == QL_ARCH.X86:  # QL_X86
        md = Cs(CS_ARCH_X86, CS_MODE_32)

    elif archtype == QL_ARCH.X8664:  # QL_X86_64
        md = Cs(CS_ARCH_X86, CS_MODE_64)

    elif archtype == QL_ARCH.ARM64:  # QL_ARM64
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    elif archtype == QL_ARCH.A8086:  # QL_A8086
        md = Cs(CS_ARCH_X86, CS_MODE_16)

    elif archtype == QL_ARCH.MIPS:  # QL_MIPS32
        if archendian == QL_ENDIAN.EB:
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
        else:
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)

    else:
        raise QlErrorArch("Unknown arch defined in utils.py (debug output mode)")

    return md

def ql_create_assembler(archtype, archendian, reg_cpsr=None):
    if archtype == QL_ARCH.ARM:  # QL_ARM
        mode = KS_MODE_ARM
        if archendian == QL_ENDIAN.EB:
            # TODO: Test for big endian.
            reg_cpsr_v = 0b100000
            # reg_cpsr_v = 0b000000
        else:
            reg_cpsr_v = 0b100000

        if reg_cpsr & reg_cpsr_v != 0:
            mode = KS_MODE_THUMB

        if archendian == QL_ENDIAN.EB:
            ks = Ks(KS_ARCH_ARM, mode)
            # md = Cs(CS_ARCH_ARM, mode + CS_MODE_BIG_ENDIAN)
        else:
            ks = Ks(KS_ARCH_ARM, mode)

    elif archtype == QL_ARCH.ARM_THUMB:
        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

    elif archtype == QL_ARCH.X86:  # QL_X86
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

    elif archtype == QL_ARCH.X8664:  # QL_X86_64
        ks = Ks(KS_ARCH_X86, KS_MODE_64)

    elif archtype == QL_ARCH.ARM64:  # QL_ARM64
        ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

    elif archtype == QL_ARCH.A8086:  # QL_A8086
        ks = Ks(KS_ARCH_X86, KS_MODE_16)

    elif archtype == QL_ARCH.MIPS:  # QL_MIPS32
        if archendian == QL_ENDIAN.EB:
            ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)
        else:
            ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_LITTLE_ENDIAN)

    else:
        raise QlErrorArch("Unknown arch defined in utils.py (debug output mode)")

    return ks