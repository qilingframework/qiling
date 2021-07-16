#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

"""
This module is intended for general purpose functions that are only used in qiling.arch
"""

from capstone import CS_MODE_MCLASS, Cs, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_X86, CS_ARCH_MIPS, CS_MODE_16, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_MIPS32 ,CS_MODE_BIG_ENDIAN, CS_MODE_LITTLE_ENDIAN
from keystone import Ks, KS_ARCH_ARM, KS_ARCH_ARM64, KS_ARCH_X86, KS_ARCH_MIPS, KS_MODE_16, KS_MODE_32, KS_MODE_64, KS_MODE_ARM, KS_MODE_THUMB, KS_MODE_MIPS32 ,KS_MODE_BIG_ENDIAN, KS_MODE_LITTLE_ENDIAN

from qiling.const import QL_ARCH, QL_ENDIAN
from qiling.exception import QlErrorArch

__cs_endian = {
    QL_ENDIAN.EL : CS_MODE_LITTLE_ENDIAN,
    QL_ENDIAN.EB : CS_MODE_BIG_ENDIAN
}

__ks_endian = {
    QL_ENDIAN.EL : KS_MODE_LITTLE_ENDIAN,
    QL_ENDIAN.EB : KS_MODE_BIG_ENDIAN
}

__reg_cpsr_v = {
    QL_ENDIAN.EL : 0b100000,
    QL_ENDIAN.EB : 0b100000   # FIXME: should be: 0b000000
}

def ql_create_disassembler(archtype: QL_ARCH, archendian: QL_ENDIAN, reg_cpsr=None) -> Cs:
    if archtype == QL_ARCH.X86:
        md = Cs(CS_ARCH_X86, CS_MODE_32)

    elif archtype == QL_ARCH.X8664:
        md = Cs(CS_ARCH_X86, CS_MODE_64)

    elif archtype == QL_ARCH.ARM:
        mode = CS_MODE_THUMB if reg_cpsr & __reg_cpsr_v[archendian] else CS_MODE_ARM

        md = Cs(CS_ARCH_ARM, mode) # FIXME: should be: mode + __cs_endian[archendian]

    elif archtype == QL_ARCH.ARM_THUMB:
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    elif archtype == QL_ARCH.CORTEX_M:
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)

    elif archtype == QL_ARCH.ARM64:
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    elif archtype == QL_ARCH.MIPS:
        md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + __cs_endian[archendian])

    elif archtype == QL_ARCH.A8086:
        md = Cs(CS_ARCH_X86, CS_MODE_16)

    elif archtype == QL_ARCH.EVM:
        raise NotImplementedError('evm')

    else:
        raise QlErrorArch(f'{archtype:d}')

    return md

def ql_create_assembler(archtype: QL_ARCH, archendian: QL_ENDIAN, reg_cpsr=None) -> Ks:
    if archtype == QL_ARCH.X86:
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

    elif archtype == QL_ARCH.X8664:
        ks = Ks(KS_ARCH_X86, KS_MODE_64)

    elif archtype == QL_ARCH.ARM:
        mode = KS_MODE_THUMB if reg_cpsr & __reg_cpsr_v[archendian] else KS_MODE_ARM

        ks = Ks(KS_ARCH_ARM, mode) # FIXME: should be: mode + __ks_endian[archendian]

    elif archtype == QL_ARCH.ARM_THUMB:
        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

    elif archtype == QL_ARCH.ARM64:
        ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

    elif archtype == QL_ARCH.MIPS:
        ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + __ks_endian[archendian])

    elif archtype == QL_ARCH.A8086:
        ks = Ks(KS_ARCH_X86, KS_MODE_16)

    elif archtype == QL_ARCH.EVM:
        raise NotImplementedError('evm')

    else:
        raise QlErrorArch(f'{archtype:d}')

    return ks