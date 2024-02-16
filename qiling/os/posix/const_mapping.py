#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import TYPE_CHECKING, Dict, Mapping, Type, Union

from qiling.const import QL_ARCH, QL_OS
from qiling.os.posix.const import *

if TYPE_CHECKING:
    from qiling import Qiling


def _flags_mapping(value: int, flags_map: Mapping[str, int]) -> str:
    names = []

    for name, flag in flags_map.items():
        if value & flag:
            value ^= flag
            names.append(name)

    if value:
        names.append(f'{value:#x}')

    return ' | '.join(names)


def get_open_flags_class(archtype: QL_ARCH, ostype: QL_OS) -> Union[Type[Flag], None]:
    """Retrieve the appropriate open flags class for given architecture and OS.

    Args:
        archtype: architecture type
        otype: operating system type

    Returns: appropriate flags class, or `None` if the specified arch and OS combination
    is not supported
    """

    flags_by_os: Dict[QL_OS, Dict[QL_ARCH, Type[Flag]]] = {
        QL_OS.LINUX: {
            QL_ARCH.X86:     linux_x86_open_flags,
            QL_ARCH.X8664:   linux_x86_open_flags,
            QL_ARCH.ARM:     linux_arm_open_flags,
            QL_ARCH.ARM64:   linux_arm_open_flags,
            QL_ARCH.MIPS:    linux_mips_open_flags,
            QL_ARCH.RISCV:   linux_riscv_open_flags,
            QL_ARCH.RISCV64: linux_riscv_open_flags,
            QL_ARCH.PPC:     linux_ppc_open_flags
        },

        QL_OS.FREEBSD: {
            QL_ARCH.X86:   freebsd_x86_open_flags,
            QL_ARCH.X8664: freebsd_x86_open_flags
        },

        QL_OS.MACOS: {
            QL_ARCH.X86:   macos_x86_open_flags,
            QL_ARCH.X8664: macos_x86_open_flags
        },

        QL_OS.WINDOWS: {
            QL_ARCH.X86:   windows_x86_open_flags,
            QL_ARCH.X8664: windows_x86_open_flags
        },

        QL_OS.QNX: {
            QL_ARCH.ARM:   qnx_arm_open_flags,
            QL_ARCH.ARM64: qnx_arm_open_flags
        }
    }

    cls = None

    if ostype in flags_by_os:
        flags_by_arch = flags_by_os[ostype]

        if archtype in flags_by_arch:
            cls = flags_by_arch[archtype]

    return cls


def ql_open_flag_mapping(ql: Qiling, flags: int) -> int:
    """Convert emulated OS 'open' flags to the hosting OS flags.
    """

    archtype = ql.host.arch
    ostype = ql.host.os

    if archtype is None or ostype is None:
        return flags

    host_flags = get_open_flags_class(archtype, ostype)

    if host_flags is None:
        raise NotImplementedError(f'flags were not defined for hosting {archtype.name} {ostype.name}')

    archtype = ql.arch.type
    ostype = ql.os.type

    emul_flags = get_open_flags_class(archtype, ostype)

    if emul_flags is None:
        raise NotImplementedError(f'flags were not defined for emulated {archtype.name} {ostype.name}')

    # both hosting and emulated os are using the same flags set; no need to convert
    if emul_flags is host_flags:
        return flags

    ret = 0

    # convert emulated os flags to hosting os flags.
    # flags names are consistent across all classes, even if they are not supported, to maintain compatibility
    for k, v in emul_flags.__members__.items():
        # test whether flag i set, excluding unsupported flags and 0 values
        if v and flags & v.value:
            hv = host_flags.__members__[k]

            # if flag is also supported on the host, set it
            if hv:
                ret |= hv.value

    # NOTE: not sure why this one is needed
    if ql.host.os is QL_OS.WINDOWS:
        ret |= getattr(host_flags, 'O_BINARY')

    return ret


def mmap_flag_mapping(flags: int) -> str:
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

    return _flags_mapping(flags, mmap_flags)


def mmap_prot_mapping(prots: int) -> str:
    if prots == 0:
        return 'PROT_NONE'

    mmap_prots = {
        'PROT_READ' : 0b001,
        'PROT_WRITE': 0b010,
        'PROT_EXEC' : 0b100,

        # not supported by unicorn
        'PROT_GROWSDOWN' : 0x01000000,
        'PROT_GROWSUP'   : 0x02000000
    }

    return _flags_mapping(prots, mmap_prots)


def socket_type_mapping(value: int, archtype: QL_ARCH) -> str:
    socket_types: Type[Enum] = {
        QL_ARCH.X86:   linux_x86_socket_types,
        QL_ARCH.X8664: linux_x86_socket_types,
        QL_ARCH.ARM:   linux_arm_socket_types,
        QL_ARCH.ARM64: linux_arm_socket_types,
        QL_ARCH.MIPS:  linux_mips_socket_types
    }[archtype]

    # https://code.woboq.org/linux/linux/net/socket.c.html#1363
    return socket_types(value & SOCK_TYPE_MASK).name


def socket_domain_mapping(value: int, archtype: QL_ARCH, ostype: QL_OS) -> str:
    socket_domain: Type[Enum] = {
        QL_ARCH.X86:   linux_x86_socket_domain,
        QL_ARCH.X8664: macos_x86_socket_domain if ostype is QL_OS.MACOS else linux_x86_socket_domain,
        QL_ARCH.ARM:   linux_arm_socket_domain,
        QL_ARCH.ARM64: linux_arm_socket_domain,
        QL_ARCH.MIPS:  linux_mips_socket_domain
    }[archtype]

    return socket_domain(value).name


def socket_tcp_option_mapping(value: int, archtype: QL_ARCH) -> str:
    socket_option: Type[Enum] = {
        QL_ARCH.X86:   linux_socket_tcp_options,
        QL_ARCH.X8664: linux_socket_tcp_options,
        QL_ARCH.ARM:   linux_socket_tcp_options,
        QL_ARCH.ARM64: linux_socket_tcp_options,
        QL_ARCH.MIPS:  linux_socket_tcp_options,
    }[archtype]

    return socket_option(value).name


def socket_level_mapping(value: int, archtype: QL_ARCH) -> str:
    socket_level: Type[Enum] = {
        QL_ARCH.X86:   linux_x86_socket_level,
        QL_ARCH.X8664: linux_x86_socket_level,
        QL_ARCH.ARM:   linux_arm_socket_level,
        QL_ARCH.ARM64: linux_arm_socket_level,
        QL_ARCH.MIPS:  linux_mips_socket_level
    }[archtype]

    return socket_level(value).name


def socket_ip_option_mapping(value: int, archtype: QL_ARCH, ostype: QL_OS) -> str:
    socket_ip_option: Type[Enum] = {
        QL_ARCH.X86:   linux_socket_ip_options,
        QL_ARCH.X8664: macos_socket_ip_options if ostype is QL_OS.MACOS else linux_socket_ip_options,
        QL_ARCH.ARM:   linux_socket_ip_options,
        QL_ARCH.ARM64: macos_socket_ip_options if ostype is QL_OS.MACOS else linux_socket_ip_options,
        QL_ARCH.MIPS:  linux_mips_socket_ip_options
    }[archtype]

    return socket_ip_option(value).name


def socket_option_mapping(value: int, archtype: QL_ARCH) -> str:
    socket_option: Type[Enum] = {
        QL_ARCH.X86:   linux_x86_socket_options,
        QL_ARCH.X8664: linux_x86_socket_options,
        QL_ARCH.ARM:   linux_arm_socket_options,
        QL_ARCH.ARM64: linux_arm_socket_options,
        QL_ARCH.MIPS:  linux_mips_socket_options
    }[archtype]

    return socket_option(value).name
