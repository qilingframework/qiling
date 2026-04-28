#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.arch.x86_const import *
from qiling.const import QL_ARCH
from qiling.os.posix.const import AT_FDCWD, AT_SYMLINK_NOFOLLOW
from qiling.os.posix.structs import *
from qiling.os.posix.syscall import *
from datetime import datetime
from math import floor
import os
import ctypes


def __get_timespec_struct(archbits: int):
    long = getattr(ctypes, f"c_int{archbits}")
    ulong = getattr(ctypes, f"c_uint{archbits}")

    class timespec(ctypes.Structure):
        _pack_ = archbits // 8

        _fields_ = (("tv_sec", ulong), ("tv_nsec", long))

    return timespec


def __get_timespec_obj(archbits: int):
    now = datetime.now().timestamp()

    tv_sec = floor(now)
    tv_nsec = floor((now - floor(now)) * 1e6)
    ts_cls = __get_timespec_struct(archbits)

    return ts_cls(tv_sec=tv_sec, tv_nsec=tv_nsec)


def ql_syscall_set_thread_area(ql: Qiling, u_info_addr: int):
    if ql.arch.type == QL_ARCH.X86:
        u_info = ql.mem.read(u_info_addr, 4 * 4)
        index = ql.unpack32s(u_info[0:4])
        base = ql.unpack32(u_info[4:8])
        limit = ql.unpack32(u_info[8:12])

        ql.log.debug("set_thread_area base : 0x%x limit is : 0x%x" % (base, limit))

        if index == -1:
            index = ql.os.gdtm.get_free_idx(12)

        if index in (12, 13, 14):
            access = (
                QL_X86_A_PRESENT
                | QL_X86_A_PRIV_3
                | QL_X86_A_DESC_DATA
                | QL_X86_A_DATA
                | QL_X86_A_DATA_E
                | QL_X86_A_DATA_W
            )

            ql.os.gdtm.register_gdt_segment(index, base, limit, access)
            ql.mem.write_ptr(u_info_addr, index, 4)
        else:
            ql.log.warning(f"Wrong index {index} from address {hex(u_info_addr)}")
            return -1

    elif ql.arch.type == QL_ARCH.MIPS:
        CONFIG3_ULR = 1 << 13
        ql.arch.regs.cp0_config3 = CONFIG3_ULR
        ql.arch.regs.cp0_userlocal = u_info_addr
        ql.arch.regs.v0 = 0
        ql.arch.regs.a3 = 0
        ql.log.debug("set_thread_area(0x%x)" % u_info_addr)

    return 0


def ql_syscall_set_tls(ql: Qiling, address: int):
    if ql.arch.type is QL_ARCH.ARM:
        ql.arch.cpr.TPIDRURO = address
        ql.mem.write_ptr(ql.arch.arm_get_tls_addr + 16, address, 4)
        ql.arch.regs.r0 = address

        ql.log.debug("settls(%#x)", address)


def ql_syscall_clock_gettime(ql: Qiling, clock_id: int, tp: int):
    ts_obj = __get_timespec_obj(ql.arch.bits)
    ql.mem.write(tp, bytes(ts_obj))

    return 0


def ql_syscall_gettimeofday(ql: Qiling, tv: int, tz: int):
    if tv:
        ts_obj = __get_timespec_obj(ql.arch.bits)
        ql.mem.write(tv, bytes(ts_obj))

    if tz:
        ql.mem.write(tz, b"\x00" * 8)

    return 0


# Handle seconds conversions 'in house'
def microseconds_to_nanoseconds(s):
    return s * 1000


def seconds_to_nanoseconds(s):
    return s * 1000000000


"""
Actual implmentation of utime(s)
Rather than repeat work based on different
precision  requirements, just convert seconds/microseconds
to ns and pass to os.utime()
"""


def handle_null_times(path):
    try:
        curr_time = datetime.now() # See https://docs.python.org/3/library/datetime.html#examples-of-usage-datetime for format
        actime = modtime = microseconds_to_nanoseconds(curr_time[6]) # curr_time[6] is microseconds
        os.utime(path, ns=(actime, modtime))
    except Exception as ex:
        return -ex.errno
    return 0


'''
's' means whether or not to use the timeval struct
'has_dfd' determines whether to interpret the path relative to our CWD
'''
def do_utime(ql: Qiling, filename: ctypes.POINTER, times: ctypes.POINTER, s:bool, has_dfd: bool):
    real_file = ""
    try:
        # get path inside of qiling rootfs
        if has_dfd:
            real_file = ql.os.path.transform_to_relative_path(ql.mem.string(filename))
        else:
            real_file = ql.os.path.transform_to_real_path(ql.mem.string(filename))
    except Exception as ex:  # return errors appropriately, don't try to handle
        # everything ourselves
        return -ex.errno
    actime = modtime = 0
    """
    times is nullable for utime(2), utimes(2), and utimensat(2)
    """
    if times is None:
        return handle_null_times(real_file)


    """
    times[0] specifies the new access time, and times[1] specifies the new modification time.  
    If times is NULL, then analogously to utime(), the access and modification times of the file are set to the
    current time.
    """
    if s:  # utimes, times[0] == new access time, times[1] == modification
        data = make_timeval_buf(ql.arch.bits, ql.arch.endian)
        with data.ref(ql.mem, times) as ref_atime:  # times[0]
            actime = seconds_to_nanoseconds(ref_atime.tv_sec)
            actime += microseconds_to_nanoseconds(ref_atime.tv_usec)
        with data.ref(
            ql.mem, times + ctypes.sizeof(data)
        ) as ref_mtime:  # increment by ctypes.sizeof() to get times[1]
            modtime = seconds_to_nanoseconds(ref_mtime.tv_sec)
            modtime += microseconds_to_nanoseconds(ref_mtime.tv_usec)

    else:
        # utime uses utimbuf, so different data handling needs to be done
        data = make_utimbuf(ql.arch.bits, ql.arch.endian)
        with data.ref(ql.mem, times) as ref:
            actime = seconds_to_nanoseconds(ref.actime)
            modtime = seconds_to_nanoseconds(ref.modtime)
    try:
        os.utime(real_file, ns=(actime, modtime))
    except Exception as ex:
        return -ex.errno
    return 0


"""
https://www.man7.org/linux/man-pages/man2/utimes.2.html
       int utime(const char *filename,
                 const struct utimbuf *_Nullable times);
"""


def ql_syscall_utime(ql: Qiling, filename: ctypes.POINTER, times: ctypes.POINTER):
    return do_utime(ql, filename, times, s=False, has_dfd=False)  # False for 's' means
    # do plain utime


"""
https://www.man7.org/linux/man-pages/man2/utimes.2.html
        int utimes(const char *filename,
                 const struct timeval times[_Nullable 2]);
"""


def ql_syscall_utimes(ql: Qiling, filename: ctypes.POINTER, times: ctypes.POINTER):
    return do_utime(ql, filename, times, s=True, has_dfd=False)  # True for 's' means the
    # we want 'utimes', which has a different prototype, and consequently,
    # struct unpacking requirements, than utime


"""
Not re-using the do_utime implementation so we can handle
the dfd and timespec unpacking here
"""


def do_utime_fd_ns(
    ql: Qiling,
    dfd: int,
    filename: ctypes.POINTER,
    utimes: ctypes.POINTER,
    flags: int,
    symlinks,
):
    # transform to real path, which ensures that we are
    # operating inside of the qiling root
    unpacked_filename = ql.os.path.transform_to_real_path(ql.mem.string(filename))
    if utimes is None:
        return handle_null_times(unpacked_filename)
    timespec_struct = make_timespec_buf(ql.arch.bits, ql.arch.endian)
    atime_nsec = mtime_nsec = 0
    if dfd is not None:
        dfd = ql.os.fd[dfd].fileno
    with timespec_struct.ref(ql.mem, utimes) as atime_ref:
        atime_nsec = atime_ref.tv_nsec
        atime_nsec += seconds_to_nanoseconds(atime_ref.tv_sec)
    with timespec_struct.ref(
        ql.mem, utimes + ctypes.sizeof(timespec_struct)
    ) as mtime_ref:
        mtime_nsec = mtime_ref.tv_nsec
        mtime_nsec += seconds_to_nanoseconds(mtime_ref.tv_sec)
    ql.log.debug(f"Got filename {unpacked_filename} for utimensat syscall ")
    try:
        os.utime(
            unpacked_filename,
            ns=(atime_nsec, mtime_nsec),
            dir_fd=dfd,
            follow_symlinks=symlinks,
        )
    except Exception as ex:
        return -ex.errno
    return 0


"""
https://www.man7.org/linux/man-pages/man2/utimensat.2.html
	sys_utimensat	int dfd	const char *filename	struct timespec *utimes	int flags
"""


def ql_syscall_utimensat(
    ql: Qiling, dfd: int, filename: ctypes.POINTER, utimes: ctypes.POINTER, flags: int
):
    if filename == 0:
        return EACCES
    # do not check `utimes` value at this point 
    if dfd == AT_FDCWD:
        dfd = None
    if flags == AT_SYMLINK_NOFOLLOW:
        follow_symlink = False
    else:
        follow_symlink = True
    return do_utime_fd_ns(ql, dfd, filename, utimes, flags, follow_symlink)


"""
This is considered deprecated,
https://www.man7.org/linux/man-pages/man2/futimesat.2.html
but including here in case some legacy code needs it
int futimesat(int dirfd, const char *pathname,
                                    const struct timeval times[2]);


If the pathname given in pathname is relative, then it is interpreted relative to the directory referred to by the file descriptor dirfd (rather than relative to the current work‐
ing directory of the calling process, as is done by utimes(2) for a relative pathname).

If pathname is relative and dirfd is the special value AT_FDCWD, then pathname is interpreted relative to the current working directory of the calling process (like utimes(2)).

If pathname is absolute, then dirfd is ignored.  (See openat(2) for an explanation of why the dirfd argument is useful.)      
"""


def ql_syscall_futimesat(
    ql: Qiling, dfd: int, pathname: ctypes.POINTER, timeval: ctypes.POINTER
):

    return do_utime(ql, filename, timeval, True, True)
