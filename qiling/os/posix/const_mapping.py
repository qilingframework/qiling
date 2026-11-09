#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

import errno
from typing import TYPE_CHECKING, Dict, Mapping, Type, Union

from qiling.const import QL_ARCH, QL_OS
from qiling.os.posix.const import *

if TYPE_CHECKING:
    from qiling import Qiling


def flags_mapping(value: int, flags_map: Mapping[str, int]) -> str:
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
    for ef in emul_flags:
        # test whether flag is set, excluding unsupported flags
        if (ef.value != FLAG_UNSUPPORTED) and (flags & ef.value):
            hf = host_flags[ef.name or '']

            # if flag is also supported on the host, set it
            if hf.value != FLAG_UNSUPPORTED:
                ret |= hf.value

    # NOTE: not sure why this one is needed
    if ql.host.os is QL_OS.WINDOWS:
        ret |= host_flags['O_BINARY'].value

    return ret


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


def get_errno_class(archtype: QL_ARCH, ostype: QL_OS) -> Union[Type[Enum], None]:
    """Retrieve the appropriate errno class for given architecture and OS.

    Args:
        archtype: architecture type
        ostype: operating system type

    Returns: appropriate errno class, or `None` if the specified arch and OS combination
    is not supported
    """

    errno_by_os: Dict[QL_OS, Dict[QL_ARCH, Type[Enum]]] = {
        QL_OS.LINUX: {
            QL_ARCH.X86:     linux_errno,
            QL_ARCH.X8664:   linux_errno,
            QL_ARCH.ARM:     linux_errno,
            QL_ARCH.ARM64:   linux_errno,
            QL_ARCH.MIPS:    linux_mips_errno,
            QL_ARCH.RISCV:   linux_errno,
            QL_ARCH.RISCV64: linux_errno,
            QL_ARCH.PPC:     linux_errno
        },

        QL_OS.FREEBSD: {
            QL_ARCH.X86:   freebsd_errno,
            QL_ARCH.X8664: freebsd_errno
        },

        QL_OS.MACOS: {
            QL_ARCH.X86:   macos_errno,
            QL_ARCH.X8664: macos_errno,
            QL_ARCH.ARM64: macos_errno
        },

        QL_OS.QNX: {
            QL_ARCH.ARM:   qnx_errno,
            QL_ARCH.ARM64: qnx_errno
        }
    }

    cls = None

    if ostype in errno_by_os:
        errno_by_arch = errno_by_os[ostype]

        if archtype in errno_by_arch:
            cls = errno_by_arch[archtype]

    return cls


def ql_errno_mapping(ql: Qiling, err: int) -> int:
    """Convert a hosting OS errno to the emulated OS errno.

    Errors are matched by name. Hosting errors that have no equivalent on the emulated OS
    are reported as the emulated OS `EIO`.

    Args:
        ql: qiling instance
        err: positive hosting OS errno

    Returns: positive emulated OS errno
    """

    # the host may give one errno several names; prefer the canonical one
    name = next((n for n in ('EAGAIN', 'EDEADLK', 'EOPNOTSUPP') if getattr(errno, n, None) == err), None)

    if name is None:
        name = errno.errorcode.get(err, '').replace('WSAE', 'E', 1)

    archtype = ql.arch.type
    ostype = ql.os.type

    emul_errno = get_errno_class(archtype, ostype)

    if emul_errno is None:
        raise NotImplementedError(f'errno was not defined for emulated {archtype.name} {ostype.name}')

    members = emul_errno.__members__

    # linux spells the missing extended attribute error ENODATA, bsd systems spell it ENOATTR
    if name not in members:
        name = {'ENODATA': 'ENOATTR', 'ENOATTR': 'ENODATA'}.get(name, name)

    return members.get(name, members['EIO']).value


__all__ = [
    'flags_mapping', 'get_open_flags_class', 'ql_open_flag_mapping', 'socket_type_mapping', 'socket_domain_mapping',
    'socket_tcp_option_mapping', 'socket_level_mapping', 'socket_ip_option_mapping', 'socket_option_mapping',
    'get_errno_class', 'ql_errno_mapping'
]
