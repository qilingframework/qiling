#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE

# customized system calls always use the same arguments list as the original ones,
# but with a Qiling instance as first argument
def my_syscall_write(ql: Qiling, fd: int, buf: int, count: int):
    try:
        # read data from emulated memory
        data = ql.mem.read(buf, count)

        # select the emulated file object that corresponds to the requested
        # file descriptor
        fobj = ql.os.fd[fd]

        # write the data into the file object, if it supports write operations
        if hasattr(fobj, 'write'):
            fobj.write(data)
    except:
        ret = -1
    else:
        ret = count

    ql.log.info(f'my_syscall_write({fd}, {buf:#x}, {count}) = {ret}')

    return ret

if __name__ == "__main__":
    ql = Qiling([r'rootfs/arm_linux/bin/arm_hello'], r'rootfs/arm_linux', verbose=QL_VERBOSE.DEBUG)

    # replacing a system call with a custom implementation.
    # note that system calls may be referred to either by their name or number.
    ql.os.set_syscall(0x04, my_syscall_write)

    # an possible alternative: refer to a syscall by its name
    #ql.os.set_syscall('write', my_syscall_write)

    ql.run()
