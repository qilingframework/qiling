#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from .const import *
from qiling.const import *


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

#
#

def ql_open_flag_mapping(ql, flags):
    def flag_mapping(flags, mapping_name, mapping_from, mapping_to):
        ret = 0
        for n in mapping_name:
            if  (flags & mapping_from[n]) == mapping_from[n]:
                ret = ret | mapping_to[n]
        return ret

    open_flags_name = [
        "O_RDONLY",
        "O_WRONLY",
        "O_RDWR",
        "O_NONBLOCK",
        "O_APPEND",
        "O_ASYNC",
        "O_SYNC",
        "O_NOFOLLOW",
        "O_CREAT",
        "O_TRUNC",
        "O_EXCL",
        "O_NOCTTY",
        "O_DIRECTORY",
        "O_BINARY"
    ]

    mac_open_flags = {
        "O_RDONLY": 0x0000,
        "O_WRONLY": 0x0001,
        "O_RDWR": 0x0002,
        "O_NONBLOCK": 0x0004,
        "O_APPEND": 0x0008,
        "O_ASYNC": 0x0040,
        "O_SYNC": 0x0080,
        "O_NOFOLLOW": 0x0100,
        "O_CREAT": 0x0200,
        "O_TRUNC": 0x0400,
        "O_EXCL": 0x0800,
        "O_NOCTTY": 0x20000,
        "O_DIRECTORY": 0x100000,
        "O_BINARY": 0
    }

    linux_open_flags = {
        'O_RDONLY': 0,
        'O_WRONLY': 1,
        'O_RDWR': 2,
        'O_NONBLOCK': 2048,
        'O_APPEND': 1024,
        'O_ASYNC': 8192,
        'O_SYNC': 1052672,
        'O_NOFOLLOW': 131072,
        'O_CREAT': 64,
        'O_TRUNC': 512,
        'O_EXCL': 128,
        'O_NOCTTY': 256,
        'O_DIRECTORY': 65536,
        'O_BINARY': 0
    }

    mips_open_flags = {
        'O_RDONLY': 0x0,
        'O_WRONLY': 0x1,
        'O_RDWR': 0x2,
        'O_NONBLOCK': 0x80,
        'O_APPEND': 0x8,
        'O_ASYNC': 0x1000,
        'O_SYNC': 0x4000,
        'O_NOFOLLOW': 0x20000,
        'O_CREAT': 0x100,
        'O_TRUNC': 0x200,
        'O_EXCL': 0x400,
        'O_NOCTTY': 0x800,
        'O_DIRECTORY': 0x100000,
        'O_BINARY' : 0
    }

    windows_open_flags = {
        'O_RDONLY': 0,
        'O_WRONLY': 1,
        'O_RDWR': 2,
        'O_NONBLOCK': 2, # Windows doesn't have a corresponding one, assume RW
        'O_APPEND': 8,
        'O_ASYNC': 2, # Windows doesn't have a corresponding one, assume RW
        'O_SYNC': 2, # Windows doesn't have a corresponding one, assume RW
        'O_NOFOLLOW': 2, # Windows doesn't have a corresponding one, assume RW
        'O_CREAT': 256,
        'O_TRUNC': 512,
        'O_EXCL': 1024,
        'O_NOCTTY': 2,
        'O_DIRECTORY': 2, # Windows doesn't have a corresponding one, assume RW
        'O_BINARY': 32768
    }

    f = {}
    t = {}

    if ql.archtype != QL_ARCH.MIPS:
        if ql.platform == None or ql.platform == ql.ostype:
            return flags
        if ql.ostype == QL_OS.LINUX:
            f = linux_open_flags
        elif ql.ostype == QL_OS.MACOS:
            f = mac_open_flags
        elif ql.ostype == QL_OS.WINDOWS:
            f = windows_open_flags
        if ql.platform == QL_OS.WINDOWS:
            t = windows_open_flags
        elif ql.platform == QL_OS.MACOS:
            t = mac_open_flags
        elif ql.platform == QL_OS.LINUX:
            t = linux_open_flags
    elif ql.archtype == QL_ARCH.MIPS and ql.platform == QL_OS.LINUX:
        f = mips_open_flags
        t = linux_open_flags
    elif ql.archtype == QL_ARCH.MIPS and ql.platform == QL_OS.MACOS:
        f = mips_open_flags
        t = mac_open_flags

    return flag_mapping(flags, open_flags_name, f, t)


def open_flags_mapping(flags, arch):

    arm64_open_flags = arm_open_flags

    mapping_dict = {
            QL_ARCH.X86: linux_open_flags,
            QL_ARCH.X8664: linux_open_flags,
            QL_ARCH.ARM: arm_open_flags,
            QL_ARCH.ARM64: arm64_open_flags,
            QL_ARCH.MIPS: mips_open_flags,
            QL_OS.MACOS: mac_open_flags,
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

    if prots == 0x0:
        return 'PROT_NONE'

    mmap_prots = {
        'PROT_READ' : 0x1,
        'PROT_WRITE': 0x2,
        'PROT_EXEC' : 0x4,
    }

    return _constant_mapping(prots, mmap_prots)


def socket_type_mapping(t, arch):
    socket_type_map = {
            QL_ARCH.X86: linux_socket_types,
            QL_ARCH.X8664: linux_socket_types,
            QL_ARCH.ARM: arm_socket_types,
            QL_ARCH.ARM_THUMB: arm_socket_types,
            QL_ARCH.ARM64: arm_socket_types,
            QL_ARCH.MIPS: mips_socket_types,
            QL_OS.MACOS: linux_socket_types,
            }.get(arch)

    return _constant_mapping(t, socket_type_map)


def socket_domain_mapping(p, arch):
    socket_domain_map = {
            QL_ARCH.X86: linux_socket_domain,
            QL_ARCH.X8664: linux_socket_domain,
            QL_ARCH.ARM: arm_socket_domain,
            QL_ARCH.ARM_THUMB: arm_socket_domain,
            QL_ARCH.ARM64: arm_socket_domain,
            QL_ARCH.MIPS: mips_socket_domain,
            QL_OS.MACOS: "macos_socket_domain",
            }.get(arch)

    return _constant_mapping(p, socket_domain_map, single_mapping=True)
