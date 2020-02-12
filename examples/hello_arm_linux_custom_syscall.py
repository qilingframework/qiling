#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import sys
sys.path.append("..")
from qiling import *

def my_syscall_write(ql, write_fd, write_buf, write_count, null0, null1, null2):
    regreturn = 0
    buf = None
    
    try:
        buf = ql.mem_read(write_buf, write_count)
        ql.nprint("\n+++++++++\nmy write(%d,%x,%i) = %d\n+++++++++" % (write_fd, write_buf, write_count, regreturn))
        ql.file_des[write_fd].write(buf)
        regreturn = write_count
    except:
        regreturn = -1
        ql.nprint("\n+++++++++\nmy write(%d,%x,%i) = %d\n+++++++++" % (write_fd, write_buf, write_count, regreturn))
        if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
            raise
    ql_definesyscall_return(ql, regreturn)


if __name__ == "__main__":
    ql = Qiling(["rootfs/arm_linux/bin/arm_hello"], "rootfs/arm_linux")
    ql.set_syscall(0x04, my_syscall_write)
    ql.run()
