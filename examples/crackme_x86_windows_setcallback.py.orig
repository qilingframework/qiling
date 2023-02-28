#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling

def force_call_dialog_func(ql: Qiling):
    # this hook is invoked after returning from DialogBoxParamA, so its
    # stack frame content is still available to us.

    # get DialogFunc address
    lpDialogFunc = ql.stack_read(-8)

    # setup stack for DialogFunc
    ql.stack_push(0)
    ql.stack_push(1001)
    ql.stack_push(273)
    ql.stack_push(0)
    ql.stack_push(0x0401018)

    # force EIP to DialogFunc
    ql.arch.regs.eip = lpDialogFunc

def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs)

    # patch the input validation code: overwrite all its breaking points
    # denoted with "jne 0x401135", so it would keep going even if there
    # is an error
    ql.patch(0x004010B5, b'\x90\x90')
    ql.patch(0x004010CD, b'\x90\x90')
    ql.patch(0x0040110B, b'\x90\x90')
    ql.patch(0x00401112, b'\x90\x90')

    # hook the instruction after returning from DialogBoxParamA
    ql.hook_address(force_call_dialog_func, 0x00401016)

    ql.run()

if __name__ == "__main__":
    my_sandbox(["rootfs/x86_windows/bin/Easy_CrackMe.exe"], "rootfs/x86_windows")
