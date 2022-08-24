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
    ql = Qiling(path, rootfs, verbose=QL_VERBOSE.DISASM)
    # QL_VERBOSE.DISASM will be monkey-patched when r2 is available
    r2 = R2(ql)

    # search bytes sequence using ql.mem.search
    addrs = ql.mem.search(b'llo worl')  # return all matching results
    print(r2.at(addrs[0]))  # find corresponding flag at the address and the offset to the flag
    # search string using r2
    addr = r2.strings['Hello world!'].vaddr  # key must be exactly same
    print(addrs[0], addr)
    # print xref to string "Hello world!"
    print(r2.refto(addr))
    # write to string using ql.mem.write
    ql.mem.write(addr, b"No hello, Bye!\x00")

    # get function address and hook it
    ql.hook_address(func, r2.functions['main'].offset)
    # enable trace powered by r2 symsmap
    # r2.enable_trace()
    ql.run()

if __name__ == "__main__":
    my_sandbox(["rootfs/x86_windows/bin/x86_hello.exe"], "rootfs/x86_windows")

    # test shellcode mode
    ARM64_LIN = bytes.fromhex('420002ca210080d2400080d2c81880d2010000d4e60300aa01020010020280d2681980d2010000d4410080d2420002cae00306aa080380d2010000d4210400f165ffff54e0000010420002ca210001caa81b80d2010000d4020004d27f0000012f62696e2f736800')
    print("\nLinux ARM 64bit Shellcode")
    ql = Qiling(code=ARM64_LIN, archtype="arm64", ostype="linux", verbose=QL_VERBOSE.DEBUG)
    r2 = R2(ql)
    # disassemble 32 instructions
    print(r2._cmd('pd 32'))
    ql.run()
