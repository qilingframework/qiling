#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append('..')

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.r2 import R2


def func(ql: Qiling, *args, **kwargs):
    ql.os.stdout.write(b"=====hooked main=====!\n")
    return

def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, verbose=QL_VERBOSE.DEFAULT)
    r2 = R2(ql)
    assert(ql.loader.images[0].base == r2.baddr)
    addrs = ql.mem.search(b'Hello world!')
    addr = r2.strings['Hello world!'].vaddr
    assert(addr == addrs[0])
    ql.mem.write(addr, b"No hello, Bye!\x00")
    ql.hook_address(func, r2.functions['main'].offset)
    ql.run()

if __name__ == "__main__":
    my_sandbox(["rootfs/x86_windows/bin/x86_hello.exe"], "rootfs/x86_windows")
