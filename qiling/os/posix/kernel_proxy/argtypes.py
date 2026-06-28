#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

"""
Argument type descriptors for forwarded syscalls.

When forwarding a syscall whose arguments are not all plain integers, the user
declares each argument's role so the forwarder knows how to marshal it:

    INT       — pass through unchanged (the default).
    FD        — guest file descriptor; translate to the proxy-side FD before
                forwarding. If the FD does not refer to a ql_proxy_fd, an error
                is raised.
    PtrIn(s)  — pointer to a buffer of `s` bytes. Read from guest memory and
                copied to the proxy.
    PtrOut(s) — pointer to a buffer of `s` bytes. Allocated on the proxy and
                copied back to guest memory after the syscall.
    PtrInOut  — both directions.

`s` may be an integer or a callable taking the raw arg tuple and returning the
buffer length (e.g. for syscalls where the size depends on another argument).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Tuple, Union


INT = 'int'
FD = 'fd'

SizeSpec = Union[int, Callable[[Tuple[int, ...]], int]]


def _resolve_size(size: SizeSpec, args: Tuple[int, ...]) -> int:
    if callable(size):
        return int(size(args))

    return int(size)


@dataclass(frozen=True)
class PtrIn:
    """Input pointer — buffer of `size` bytes is read from guest memory."""
    size: SizeSpec

    def resolve(self, args: Tuple[int, ...]) -> int:
        return _resolve_size(self.size, args)


@dataclass(frozen=True)
class PtrOut:
    """Output pointer — buffer of `size` bytes is written to guest memory."""
    size: SizeSpec

    def resolve(self, args: Tuple[int, ...]) -> int:
        return _resolve_size(self.size, args)


@dataclass(frozen=True)
class PtrInOut:
    """In/out pointer — buffer is read from guest, then written back."""
    size: SizeSpec

    def resolve(self, args: Tuple[int, ...]) -> int:
        return _resolve_size(self.size, args)


def is_pointer(spec) -> bool:
    return isinstance(spec, (PtrIn, PtrOut, PtrInOut))
