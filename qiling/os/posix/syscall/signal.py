#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING, Type

from qiling.const import QL_ARCH
from qiling.os import struct
from qiling.os.posix.const import NSIG

# TODO: MIPS differs in too many details around signals; MIPS implementation is better extracted out

if TYPE_CHECKING:
    from qiling import Qiling
    from qiling.arch.arch import QlArch


@struct.cache
def __make_sigset(arch: QlArch):
    native_type = struct.get_native_type(arch.bits)

    sigset_type = {
        QL_ARCH.X86:      native_type,
        QL_ARCH.X8664:    native_type,
        QL_ARCH.ARM:      native_type,
        QL_ARCH.ARM64:    native_type,
        QL_ARCH.MIPS:     ctypes.c_uint32 * (128 // (4 * 8)),
        QL_ARCH.CORTEX_M: native_type
    }

    if arch.type not in sigset_type:
        raise NotImplementedError(f'sigset definition is missing for {arch.type.name}')

    return sigset_type[arch.type]


@struct.cache
def __make_sigaction(arch: QlArch) -> Type[struct.BaseStruct]:
    native_type = struct.get_native_type(arch.bits)
    Struct = struct.get_aligned_struct(arch.bits, arch.endian)

    sigset_type = __make_sigset(arch)

    # # FIXME: untill python 3.11 ctypes Union does not support an endianess that is different from
    # the hosting paltform. if a LE system is emulating a BE one or vice versa, this will fail. to
    # work around that we avoid using a union and refer to the inner field as 'sa_handler' regardless.
    #
    # Union = struct.get_aligned_union(arch.bits)
    #
    # class sighandler_union(Union):
    #     _fields_ = (
    #         ('sa_handler',   native_type),
    #         ('sa_sigaction', native_type)
    #     )

    # <WORKAROUND> see FIXME above
    class sighandler_union(Struct):
        _fields_ = (
            ('sa_handler',   native_type),
        )
    # </WORKAROUND>

    # see: https://elixir.bootlin.com/linux/v5.19.17/source/arch/arm/include/uapi/asm/signal.h
    class arm_sigaction(Struct):
        _anonymous_ = ('_u',)

        _fields_ = (
            ('_u',          sighandler_union),
            ('sa_mask',     sigset_type),
            ('sa_flags',    native_type),
            ('sa_restorer', native_type)
        )

    # see: https://elixir.bootlin.com/linux/v5.19.17/source/arch/x86/include/uapi/asm/signal.h
    class x86_sigaction(Struct):
        _anonymous_ = ('_u',)

        _fields_ = (
            ('_u',          sighandler_union),
            ('sa_mask',     sigset_type),
            ('sa_flags',    native_type),
            ('sa_restorer', native_type)
        )

    class x8664_sigaction(Struct):
        _fields_ = (
            ('sa_handler',  native_type),
            ('sa_flags',    native_type),
            ('sa_restorer', native_type),
            ('sa_mask',     sigset_type)
        )

    # see: https://elixir.bootlin.com/linux/v5.19.17/source/arch/mips/include/uapi/asm/signal.h
    class mips_sigaction(Struct):
        _fields_ = (
            ('sa_flags',    ctypes.c_uint32),
            ('sa_handler',  native_type),
            ('sa_mask',     sigset_type)
        )

    sigaction_struct = {
        QL_ARCH.X86:      x86_sigaction,
        QL_ARCH.X8664:    x8664_sigaction,
        QL_ARCH.ARM:      arm_sigaction,
        QL_ARCH.ARM64:    arm_sigaction,
        QL_ARCH.MIPS:     mips_sigaction,
        QL_ARCH.CORTEX_M: arm_sigaction
    }

    if arch.type not in sigaction_struct:
        raise NotImplementedError(f'sigaction definition is missing for {arch.type.name}')

    return sigaction_struct[arch.type]


def ql_syscall_rt_sigaction(ql: Qiling, signum: int, act: int, oldact: int):
    SIGKILL = 9
    SIGSTOP = 23 if ql.arch.type is QL_ARCH.MIPS else 19

    if signum not in range(NSIG) or signum in (SIGKILL, SIGSTOP):
        return -1   # EINVAL

    sigaction = __make_sigaction(ql.arch)

    if oldact:
        old = ql.os.sig[signum] or sigaction()

        old.save_to(ql.mem, oldact)

    if act:
        ql.os.sig[signum] = sigaction.load_from(ql.mem, act)

    return 0


def __sigprocmask(ql: Qiling, how: int, newset: int, oldset: int):
    SIG_BLOCK = 0
    SIG_UNBLOCK = 1
    SIG_SETMASK = 2

    SIGKILL = 9
    SIGSTOP = 19

    if oldset:
        ql.mem.write_ptr(newset, ql.os.blocked_signals)

    if newset:
        set_mask = ql.mem.read_ptr(newset)

        if how == SIG_BLOCK:
            ql.os.blocked_signals |= set_mask

        elif how == SIG_UNBLOCK:
            ql.os.blocked_signals &= ~set_mask

        elif how == SIG_SETMASK:
            ql.os.blocked_signals = set_mask

        else:
            return -1  # EINVAL

        # silently drop attempts to block SIGKILL and SIGSTOP
        ql.os.blocked_signals &= ~((1 << SIGKILL) | (1 << SIGSTOP))

    return 0


def __sigprocmask_mips(ql: Qiling, how: int, newset: int, oldset: int):
    SIG_BLOCK = 1
    SIG_UNBLOCK = 2
    SIG_SETMASK = 3

    SIGKILL = 9
    SIGSTOP = 23

    # TODO: to implement
    return 0


def ql_syscall_rt_sigprocmask(ql: Qiling, how: int, newset: int, oldset: int):
    impl = __sigprocmask_mips if ql.arch.type is QL_ARCH.MIPS else __sigprocmask

    return impl(ql, how, newset, oldset)


def ql_syscall_signal(ql: Qiling, sig: int, sighandler: int):
    return 0
