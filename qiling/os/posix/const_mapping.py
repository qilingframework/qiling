#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from .const import *


def _invert_dict(d):
    return { v:k for k, v in d.items()}


def _constant_mapping(bits, d_map, ret=None, single_mapping=False):

    if ret is None:
        ret = []

    b_map = _invert_dict(d_map)

    if single_mapping:
        return b_map[bits]

    for val, sym in b_map.items():
        if val & bits != 0:
            bits ^= val
            ret.append(sym)

    if bits != 0:
        ret.append(str(bits))

    return " | ".join(ret)


def open_flags_mapping(flags, arch):

    arm64_open_flags = arm_open_flags

    mapping_dict = {
            QL_X86: linux_open_flags,
            QL_X8664: linux_open_flags,
            QL_ARM: arm_open_flags,
            QL_ARM64: arm64_open_flags,
            QL_MIPS32: mips32_open_flags,
            QL_MACOS: mac_open_flags,
            }.get(arch)

    ret = ["O_RDONLY"]

    return _constant_mapping(flags, mapping_dict, ret)


def mmap_flag_mapping(flags):

    mmap_flags = {
        'MAP_SHARED'    : 0x01,
        'MAP_PRIVATE'   : 0x02,
        'MAP_FIXED'     : 0x10,
        'MAP_ANONYMOUS' : 0x20,
    }

    return _constant_mapping(flags, mmap_flags)


def mmap_prot_mapping(prots):
    
    if prots is 0x0:
        return 'PROT_NONE'

    mmap_prots = {
        'PROT_READ' : 0x1,
        'PROT_WRITE': 0x2,
        'PROT_EXEC' : 0x4,
    }

    return _constant_mapping(prots, mmap_prots)


def socket_type_mapping(t, arch):
    socket_type_map = {
            QL_X86: linux_socket_types,
            QL_X8664: linux_socket_types,
            QL_ARM: arm_socket_types,
            QL_ARM_THUMB: arm_socket_types,
            QL_ARM64: arm_socket_types,
            QL_MIPS32: mips32_socket_types,
            QL_MACOS: linux_socket_types,
            }.get(arch)

    return _constant_mapping(t, socket_type_map)


def socket_domain_mapping(p, arch):
    socket_domain_map = {
            QL_X86: linux_socket_domain,
            QL_X8664: linux_socket_domain,
            QL_ARM: arm_socket_domain,
            QL_ARM_THUMB: arm_socket_domain,
            QL_ARM64: arm_socket_domain,
            QL_MIPS32: mips32_socket_domain,
            QL_MACOS: macos_socket_domain,
            }.get(arch)
    
    return _constant_mapping(p, socket_domain_map, single_mapping=True)
