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

def our_sandbox(path, rootfs):
    ql = Qiling(path, rootfs)

    # hook the instruction after returning from DialogBoxParamA
    ql.hook_address(force_call_dialog_func, 0x00401016)

    ql.run()

if __name__ == "__main__":
    # Flag is : Ea5yR3versing
    our_sandbox(["rootfs/x86_windows/bin/Easy_CrackMe.exe"], "rootfs/x86_windows")
