#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

# After mapping /proc there will be a /dev/mtdblock11 missing and crash
# To fix this,
#   - cd $yourfirmware_rootfs/dev
#   - dd if=/dev/zero of=mtdblock11 bs=1024 count=129030
#   - mkfs.ext4 mtdblock11
# 
# This firmware will more or less alive now.


from qiling import *
from qiling.os.posix import syscall
from qiling.const import *
from colorama import Back
import struct
import sys
sys.path.append("..")


def my_syscall_write(ql, write_fd, write_buf, write_count, *rest):
    if write_fd == 2 and ql.os.fd[2].__class__.__name__ == 'ql_pipe':
        ql.os.definesyscall_return(-1)
    else:
        syscall.ql_syscall_write(ql, write_fd, write_buf, write_count, *rest)


def my_bind(ql, *args, **kw):
    bind_fd = ql.os.function_arg[0]
    bind_addr = ql.os.function_arg[1]
    bind_addrlen = ql.os.function_arg[2]
    print(Back.GREEN + "Hijack bind(%d, %d, %d)" % (bind_fd, bind_addr, bind_addrlen) + Back.RESET)
    # read from memory (start_address, len)
    data = ql.mem.read(bind_addr, bind_addrlen)
    # custom unpack (your own ql.unpack) of a C struct from memory
    # https://linux.die.net/man/7/ip -> struct
    sin_family = struct.unpack("<h", data[:2])[0] or ql.os.fd[bind_fd].family
    # little-endian short -> format_string -> https://docs.python.org/3/library/struct.html#format-strings
    port, host = struct.unpack(">HI", data[2:8])
    # big-endian unsigned short, unsigned int -> format_string
    print(Back.RED+"[*] Socket Infos:"+Back.RESET+"\nFamily: %d\nPort: %d (no root: +8000)\nHost-interface?: %d\n" % (sin_family, port, host))
    return 0  # from syscall.ql_syscall_bind(ql, bind_fd, bind_addr, bind_addrlen)

def my_netgear(path, rootfs):
    ql = Qiling(
                path, 
                rootfs, 
                output      = "debug", 
                profile     = "netgear_6220.ql"
                )

    ql.root             = False
    ql.multithread      = False
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
