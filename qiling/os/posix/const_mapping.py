#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from .const import *
from qiling.const import *


def _invert_dict(d):
    return {v: k for k, v in d.items()}


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


def ql_open_flag_mapping(ql, flags):
    def flag_mapping(flags, mapping_name, mapping_from, mapping_to):
        ret = 0
        for n in mapping_name:
            if mapping_from[n] is None or mapping_to[n] is None:
                continue
            if (flags & mapping_from[n]) == mapping_from[n]:
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
        "O_BINARY",
        "O_LARGEFILE",
    ]

    mac_open_flags = {
        "O_RDONLY": 0x0,
        "O_WRONLY": 0x1,
        "O_RDWR": 0x2,
        "O_NONBLOCK": 0x4,
        "O_APPEND": 0x8,
        "O_ASYNC": 0x40,
        "O_SYNC": 0x80,
        "O_NOFOLLOW": 0x100,
        "O_CREAT": 0x200,
        "O_TRUNC": 0x400,
        "O_EXCL": 0x800,
        "O_NOCTTY": 0x20000,
        "O_DIRECTORY": 0x100000,
        "O_BINARY": None,
        "O_LARGEFILE": None,
    }

    linux_x86_open_flags = {
        "O_RDONLY": 0x0,
        "O_WRONLY": 0x1,
        "O_RDWR": 0x2,
        "O_NONBLOCK": 0x800,
        "O_APPEND": 0x400,
        "O_ASYNC": 0x2000,
        "O_SYNC": 0x101000,
        "O_NOFOLLOW": 0x20000,
        "O_CREAT": 0x40,
        "O_TRUNC": 0x200,
        "O_EXCL": 0x80,
        "O_NOCTTY": 0x100,
        "O_DIRECTORY": 0x10000,
        "O_BINARY": None,
        "O_LARGEFILE": 0x0,
    }

    linux_arm_open_flags = {
        "O_RDONLY": 0x0,
        "O_WRONLY": 0x1,
        "O_RDWR": 0x2,
        "O_NONBLOCK": 0x800,
        "O_APPEND": 0x400,
        "O_ASYNC": 0x2000,
        "O_SYNC": 0x101000,
        "O_NOFOLLOW": 0x8000,
        "O_CREAT": 0x40,
        "O_TRUNC": 0x200,
        "O_EXCL": 0x80,
        "O_NOCTTY": 0x100,
        "O_DIRECTORY": 0x4000,
        "O_BINARY": None,
        "O_LARGEFILE": 0x20000,
    }

    linux_mips_open_flags = {
        "O_RDONLY": 0x0,
        "O_WRONLY": 0x1,
        "O_RDWR": 0x2,
        "O_NONBLOCK": 0x80,
        "O_APPEND": 0x8,
        "O_ASYNC": 0x1000,
        "O_SYNC": 0x4010,
        "O_NOFOLLOW": 0x20000,
        "O_CREAT": 0x100,
        "O_TRUNC": 0x200,
        "O_EXCL": 0x400,
        "O_NOCTTY": 0x800,
        "O_DIRECTORY": 0x10000,
        "O_BINARY": None,
        "O_LARGEFILE": 0x2000,
    }

    freebsd_open_flags = {
        "O_RDONLY": 0x0,
        "O_WRONLY": 0x1,
        "O_RDWR": 0x2,
        "O_NONBLOCK": 0x4,
        "O_APPEND": 0x8,
        "O_ASYNC": 0x40,
        "O_SYNC": 0x80,
        "O_NOFOLLOW": 0x100,
        "O_CREAT": 0x200,
        "O_TRUNC": 0x400,
        "O_EXCL": 0x800,
        "O_NOCTTY": 0x8000,
        "O_DIRECTORY": 0x20000,
        "O_BINARY": None,
        "O_LARGEFILE": None,
    }

    windows_open_flags = {
        "O_RDONLY": 0x0,
        "O_WRONLY": 0x1,
        "O_RDWR": 0x2,
        "O_NONBLOCK": None,
        "O_APPEND": 0x8,
        "O_ASYNC": None,
        "O_SYNC": None,
        "O_NOFOLLOW": None,
        "O_CREAT": 0x100,
        "O_TRUNC": 0x200,
        "O_EXCL": 0x400,
        "O_NOCTTY": None,
        "O_DIRECTORY": None,
        "O_BINARY": 0x8000,
        "O_LARGEFILE": None,
    }

    f = {}
    t = {}

    if ql.platform == None:
        return flags

    if ql.ostype == QL_OS.LINUX:
        if ql.archtype in (QL_ARCH.X86, QL_ARCH.X8664):
            f = linux_x86_open_flags
        elif ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB, QL_ARCH.ARM64):
            f = linux_arm_open_flags
        elif ql.archtype == QL_ARCH.MIPS:
            f = linux_mips_open_flags
    elif ql.ostype == QL_OS.MACOS:
        f = mac_open_flags
    elif ql.ostype == QL_OS.FREEBSD:
        f = freebsd_open_flags
    elif ql.ostype == QL_OS.WINDOWS:
        f = windows_open_flags

    if ql.platform == QL_OS.LINUX:
        t = linux_x86_open_flags
    elif ql.platform == QL_OS.MACOS:
        t = mac_open_flags
    elif ql.platform == QL_OS.FREEBSD:
        t = freebsd_open_flags
    elif ql.platform == QL_OS.WINDOWS:
        t = windows_open_flags

    if f == t:
        return flags

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
        "MAP_SHARED": 0x00000001,
        "MAP_PRIVATE": 0x00000002,
        "MAP_FIXED": 0x00000010,
        "MAP_ANONYMOUS": 0x00000020,
        # QNX (openqnx)
        # lib/c/public/sys/mman.h
        "MAP_NOINIT": 0x00004000,
        "MAP_PHYS": 0x00010000,
        "MAP_NOX64K": 0x00020000,
        "MAP_BELOW16M": 0x00040000,
        "MAP_ANON": 0x00080000,
        "MAP_SYSRAM": 0x01000000,
    }

    return _constant_mapping(flags, mmap_flags)


def mmap_prot_mapping(prots):

    if prots == 0x0:
        return "PROT_NONE"

    # QNX (openqnx)
    # lib/c/public/sys/mman.h
    if prots >= 0x100:
        mmap_prots = {
            "PROT_READ": 0x100,
            "PROT_WRITE": 0x200,
            "PROT_EXEC": 0x400,
        }
    else:
        mmap_prots = {
            "PROT_READ": 0x1,
            "PROT_WRITE": 0x2,
            "PROT_EXEC": 0x4,
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
