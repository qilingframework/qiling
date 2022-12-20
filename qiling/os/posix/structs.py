#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.const import QL_ENDIAN
from qiling.os import struct


# FIXME: freebsd socket structures differ from the unix ones by specifying the
# sa_len and sa_family fields, one byte each, instead of using one short int
# for sa_family.
#
# using the sturcutres as they defined here causes freebsd socket structures to
# show high (hence unrecognized) values for sa_family. messing all sturctures
# with "if ql.os.type == QL_OS.FREEBSD" is a cumbersome workaround and not
# maintainable, let alone the code should also refer to sa_len and populate it
# appropriately.
#
# unfortunately, until there is an elegant implemetation that takes freebsd
# sockets into account freebsd sockets are broken.
#
# for more details: https://docs.freebsd.org/en/books/developers-handbook/sockets/


def make_sockaddr(archbits: int, endian: QL_ENDIAN):
    Struct = struct.get_aligned_struct(archbits, endian)

    class sockaddr(Struct):
        _pack_ = 1

        _fields_ = (
            ('sa_family', ctypes.c_uint16),
        )

    return sockaddr


def make_sockaddr_un(archbits: int, endian: QL_ENDIAN, pathlen: int):
    Struct = struct.get_aligned_struct(archbits, endian)

    class sockaddr_un(Struct):
        _fields_ = (
            ('sun_family', ctypes.c_int16),
            ('sun_path',   ctypes.c_char * pathlen)
        )

    return sockaddr_un


def make_sockaddr_in(archbits: int, endian: QL_ENDIAN):
    Struct = struct.get_aligned_struct(archbits, endian)

    class in_addr(Struct):
        _fields_ = (
            ('s_addr', ctypes.c_uint32),
        )

    class sockaddr_in(Struct):
        _fields_ = (
            ('sin_family', ctypes.c_int16),
            ('sin_port',   ctypes.c_uint16),
            ('sin_addr',   in_addr),
            ('sin_zero',   ctypes.c_byte * 8)
        )

    return sockaddr_in


def make_sockaddr_in6(archbits: int, endian: QL_ENDIAN):
    Struct = struct.get_aligned_struct(archbits, endian)

    class in6_addr(Struct):
        _fields_ = (
            ('s6_addr', ctypes.c_uint8 * 16),
        )

    class sockaddr_in6(Struct):
        _fields_ = (
            ('sin6_family',   ctypes.c_int16),
            ('sin6_port',     ctypes.c_uint16),
            ('sin6_flowinfo', ctypes.c_uint32),
            ('sin6_addr',     in6_addr),
            ('sin6_scope_id', ctypes.c_uint32)
        )

    return sockaddr_in6


def make_msghdr(archbits: int, endian: QL_ENDIAN):
    Struct = struct.get_aligned_struct(archbits, endian)

    class msghdr(Struct):
        _fields_ = (
            ('msg_name',       ctypes.c_uint64),
            ('msg_namelen',    ctypes.c_int32),
            ('msg_iov',        ctypes.c_uint64),
            ('msg_iovlen',     ctypes.c_int32),
            ('msg_control',    ctypes.c_uint64),
            ('msg_controllen', ctypes.c_int32),
            ('msg_flags',      ctypes.c_int32)
        )

    return msghdr


def make_cmsghdr(archbits: int, endian: QL_ENDIAN):
    Struct = struct.get_aligned_struct(archbits, endian)

    class cmsghdr(Struct):
        _fields_ = (
            ('cmsg_len',   ctypes.c_int32),
            ('cmsg_level', ctypes.c_int32),
            ('cmsg_type',  ctypes.c_int32)
        )

    return cmsghdr


def make_iovec(archbits: int, endian: QL_ENDIAN):
    Struct = struct.get_aligned_struct(archbits, endian)

    class iovec(Struct):
        _fields_ = (
            ('iov_base', ctypes.c_uint64),
            ('iov_len',  ctypes.c_uint64)
        )

    return iovec


def make_pollfd(archbits: int, endian: QL_ENDIAN):
    Struct = struct.get_aligned_struct(archbits, endian)

    class pollfd(Struct):
        _fields_ = (
            ('fd', ctypes.c_int32),
            ('events', ctypes.c_int16),
            ('revents', ctypes.c_int16)
        )

    return pollfd
