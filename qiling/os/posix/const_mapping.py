#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Mapping, MutableSequence

from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS

from .const import *

def _invert_dict(d: Mapping) -> Mapping:
    return { v:k for k, v in d.items()}


def _constant_mapping(bits: int, d_map: Mapping[str, int], ret: MutableSequence[str] = None, single_mapping: bool = False) -> str:
    b_map = _invert_dict(d_map)

    if single_mapping:
        return b_map[bits]

    if ret is None:
        ret = []

    for val, sym in b_map.items():
        if val & bits:
            bits ^= val
            ret.append(sym)

    if bits:
        ret.append(f'{bits:#x}')

    return " | ".join(ret)


def ql_open_flag_mapping(ql: Qiling, flags):
    def flag_mapping(flags, mapping_name, mapping_from, mapping_to, host_os, virt_os):
        ret = 0
        for n in mapping_name:
            if mapping_from[n] is None or mapping_to[n] is None:
                continue
            if (flags & mapping_from[n]) == mapping_from[n]:
                ret = ret | mapping_to[n]
            if (host_os == QL_OS.WINDOWS and virt_os != QL_OS.WINDOWS):
                ret = ret | mapping_to['O_BINARY']
        return ret

    f = {}
    t = {}

    host_os = ql.host.os
    virt_os = ql.os.type

    if host_os is None:
        return flags

    if virt_os == QL_OS.LINUX:
        if ql.arch.type in (QL_ARCH.X86, QL_ARCH.X8664):
            f = linux_x86_open_flags
        elif ql.arch.type in (QL_ARCH.ARM, QL_ARCH.ARM64):
            f = linux_arm_open_flags
        elif ql.arch.type == QL_ARCH.MIPS:
            f = linux_mips_open_flags
        elif ql.arch.type in (QL_ARCH.RISCV, QL_ARCH.RISCV64):
            f = linux_riscv_open_flags
        elif ql.arch.type == QL_ARCH.PPC:
            f = linux_ppc_open_flags

    elif virt_os == QL_OS.MACOS:
        if ql.arch.type in (QL_ARCH.X86, QL_ARCH.X8664):
            f = macos_x86_open_flags
    elif virt_os == QL_OS.FREEBSD:
        f = freebsd_x86_open_flags
    elif virt_os == QL_OS.WINDOWS:
        f = windows_x86_open_flags
    elif virt_os == QL_OS.QNX:
        f = qnx_arm64_open_flags

    if host_os == QL_OS.LINUX:
        t = linux_x86_open_flags
    elif host_os == QL_OS.MACOS:
        t = macos_x86_open_flags
    elif host_os == QL_OS.FREEBSD:
        t = freebsd_x86_open_flags
    elif host_os == QL_OS.WINDOWS:
        t = windows_x86_open_flags

    if f == t:
        return flags

    return flag_mapping(flags, open_flags_name, f, t, host_os, virt_os)


def mmap_flag_mapping(flags):
    mmap_flags = {
        'MAP_SHARED'    : 0x00000001,
        'MAP_PRIVATE'   : 0x00000002,
        'MAP_FIXED'     : 0x00000010,
        'MAP_ANONYMOUS' : 0x00000020,

        # QNX (openqnx)
        # lib/c/public/sys/mman.h
        'MAP_NOINIT'    : 0x00004000,
        'MAP_PHYS'      : 0x00010000,
        'MAP_NOX64K'    : 0x00020000,
        'MAP_BELOW16M'  : 0x00040000,
        'MAP_ANON'      : 0x00080000,
        'MAP_SYSRAM'    : 0x01000000
    }
    return _constant_mapping(flags, mmap_flags)


def mmap_prot_mapping(prots):
    if prots == 0x0:
        return 'PROT_NONE'

    mmap_prots = {
        'PROT_READ' : 0x1,
        'PROT_WRITE': 0x2,
        'PROT_EXEC' : 0x4,

        # not supported by unicorn
        'PROT_GROWSDOWN' : 0x01000000,
        'PROT_GROWSUP'   : 0x02000000
    }
    return _constant_mapping(prots, mmap_prots)


def socket_type_mapping(t, archtype, ostype):
    if ostype == QL_OS.MACOS:    
        socket_type_map = {
            QL_ARCH.X8664: linux_x86_socket_types,
            QL_ARCH.ARM64: linux_arm_socket_types,
        }[archtype]
    else:
        socket_type_map = {
            QL_ARCH.X86: linux_x86_socket_types,
            QL_ARCH.X8664: linux_x86_socket_types,
            QL_ARCH.ARM: linux_arm_socket_types,
            QL_ARCH.ARM64: linux_arm_socket_types,
            QL_ARCH.MIPS: linux_mips_socket_types,
        }[archtype]

    # https://code.woboq.org/linux/linux/net/socket.c.html#1363
    t &= SOCK_TYPE_MASK
    return _constant_mapping(t, socket_type_map, single_mapping=True)

def socket_domain_mapping(p, archtype, ostype):
    if ostype == QL_OS.MACOS:
        socket_domain_map = {
            QL_ARCH.X8664: macos_x86_socket_domain,
            QL_ARCH.ARM64: linux_arm_socket_domain,
        }[archtype]        
    else:     
        socket_domain_map = {
            QL_ARCH.X86: linux_x86_socket_domain,
            QL_ARCH.X8664: linux_x86_socket_domain,
            QL_ARCH.ARM: linux_arm_socket_domain,
            QL_ARCH.ARM64: linux_arm_socket_domain,
            QL_ARCH.MIPS: linux_mips_socket_domain,
        }[archtype]
    return _constant_mapping(p, socket_domain_map, single_mapping=True)

def socket_level_mapping(t, archtype, ostype):
    if ostype == QL_OS.MACOS:    
        socket_level_map = {
            QL_ARCH.X8664: linux_x86_socket_level,
            QL_ARCH.ARM64: linux_arm_socket_level,
        }[archtype]
    else:    
        socket_level_map = {
            QL_ARCH.X86: linux_x86_socket_level,
            QL_ARCH.X8664: linux_x86_socket_level,
            QL_ARCH.ARM: linux_arm_socket_level,
            QL_ARCH.ARM64: linux_arm_socket_level,
            QL_ARCH.MIPS: linux_mips_socket_level,
        }[archtype]
    return _constant_mapping(t, socket_level_map, single_mapping=True)


def socket_ip_option_mapping(t, archtype, ostype):
    if ostype == QL_OS.MACOS: 
        socket_option_map = {
            QL_ARCH.X8664: macos_socket_ip_options,
            QL_ARCH.ARM64: macos_socket_ip_options,
        }[archtype]
    else:      
        socket_option_map = {
            QL_ARCH.X86: linux_socket_ip_options,
            QL_ARCH.X8664: linux_socket_ip_options,
            QL_ARCH.ARM: linux_socket_ip_options,
            QL_ARCH.ARM64: linux_socket_ip_options,
            QL_ARCH.MIPS: linux_socket_ip_options,
        }[archtype]
    return _constant_mapping(t, socket_option_map, single_mapping=True)


def socket_option_mapping(t, archtype, ostype):
    if ostype == QL_OS.MACOS:
        socket_option_map = {
            QL_ARCH.X8664: linux_x86_socket_options,
            QL_ARCH.ARM64: linux_arm_socket_options,
        }[archtype]
    else: 
        socket_option_map = {
            QL_ARCH.X86: linux_x86_socket_options,
            QL_ARCH.X8664: linux_x86_socket_options,
            QL_ARCH.ARM: linux_arm_socket_options,
            QL_ARCH.ARM64: linux_arm_socket_options,
            QL_ARCH.MIPS: linux_mips_socket_options,
        }[archtype]
    return _constant_mapping(t, socket_option_map, single_mapping=True)