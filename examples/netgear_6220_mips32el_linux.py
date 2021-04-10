#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# After mapping /proc there will be a /dev/mtdblock11 missing and crash
# To fix this,
#   - cd $yourfirmware_rootfs/dev
#   - dd if=/dev/zero of=mtdblock11 bs=1024 count=129030
#   - mkfs.ext4 mtdblock11
# 
# This firmware will more or less alive now.

from colorama import Back
import struct
import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_INTERCEPT, QL_VERBOSE
from qiling.os.posix import syscall
from qiling.os.const import UINT, POINTER

def my_syscall_write(ql, write_fd, write_buf, write_count, *rest):
    if write_fd == 2 and ql.os.fd[2].__class__.__name__ == 'ql_pipe':
        return -1
    else:
        return syscall.ql_syscall_write(ql, write_fd, write_buf, write_count, *rest)


def my_bind(ql: Qiling):
    params = ql.os.resolve_fcall_params({
        'fd': UINT,
        'addr': POINTER,
        'addrlen': UINT
    })

    bind_fd = params['fd']
    bind_addr = params['addr']
    bind_addrlen = params['addrlen']

    print(Back.GREEN + f'Hijack bind({bind_fd}, {bind_addr:#x}, {bind_addrlen})' + Back.RESET)
    # read from memory (start_address, len)
    data = ql.mem.read(bind_addr, bind_addrlen)
    # custom unpack (your own ql.unpack) of a C struct from memory
    # https://linux.die.net/man/7/ip -> struct
    sin_family = struct.unpack("<h", data[:2])[0] or ql.os.fd[bind_fd].family
    # little-endian short -> format_string -> https://docs.python.org/3/library/struct.html#format-strings
    port, host = struct.unpack(">HI", data[2:8])
    # big-endian unsigned short, unsigned int -> format_string
    print(Back.RED + f'[*] Socket Infos:' + Back.RESET)
    print(f'''
    Family: {sin_family}
    Port: {port} (no root: +8000)
    Host-interface?: {host}
    ''')
    return 0  # from syscall.ql_syscall_bind(ql, bind_fd, bind_addr, bind_addrlen)

def my_netgear(path, rootfs):
    ql = Qiling(path, rootfs, verbose=QL_VERBOSE.DEBUG, profile="netgear_6220.ql", multithread=False)
    ql.root = False

    ql.add_fs_mapper('/proc', '/proc')
    ql.set_syscall(4004, my_syscall_write)
    ql.set_api('bind', my_bind, QL_INTERCEPT.ENTER)  # intercepting the bind call on enter

    ql.run()

if __name__ == "__main__":
    my_netgear(["rootfs/netgear_r6220/bin/mini_httpd",
                "-d", "/www",
                "-r", "NETGEAR R6220",
                "-c", "**.cgi",
                "-t", "300"],
               "rootfs/netgear_r6220")
