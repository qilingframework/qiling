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

import sys
sys.path.append("..")
from qiling import *
from qiling.os.posix import syscall


def my_syscall_write(ql, write_fd, write_buf, write_count, *rest):
    if write_fd == 2 and ql.os.file_des[2].__class__.__name__ == 'ql_pipe':
        ql.os.definesyscall_return(-1)
    else:
        syscall.ql_syscall_write(ql, write_fd, write_buf, write_count, *rest)


def my_netgear(path, rootfs):
    ql = Qiling(
                path, 
                rootfs, 
                output      = "debug", 
                profile     = "netgear_6220.ql"
                )

    ql.root             = False
    ql.bindtolocalhost  = True
    ql.multithread      = False
    ql.add_fs_mapper('/proc', '/proc')
    ql.set_syscall(4004, my_syscall_write)
    ql.run()


if __name__ == "__main__":
    my_netgear(["rootfs/netgear_r6220/bin/mini_httpd",
                "-d","/www",
                "-r","NETGEAR R6220",
                "-c","**.cgi",
                "-t","300"], 
                "rootfs/netgear_r6220")
