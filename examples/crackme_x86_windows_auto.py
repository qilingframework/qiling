#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.extensions import pipe
from qiling.const import QL_INTERCEPT, QL_VERBOSE
from qiling.os.windows.api import HWND, UINT, LONG

def hook_DialogBoxParamA_onexit(ql: Qiling, address: int, params, retval: int):
    # extract lpDialogFunc value
    # [see arguments list at 'qiling/os/windows/dlls/user32.py' -> 'hook_DialogBoxParamA']
    lpDialogFunc = params['lpDialogFunc']

    def call_DialogFunc(ql: Qiling):
        # we would like to resume from the exact same address that used to invoke
        # this hook. in order to prevent an endless loop of hook invocations, we
        # remove the hook through its handle.
        hh.remove()

        WM_COMMAND = 0x111
        IDS_APPNAME = 1001

        # [steps #3 and #4]
        # set up the arguments and call the address passed through the lpDialogFunc
        # param. make sure it resumes back to where we were.
        ql.os.fcall.call_native(lpDialogFunc, (
            (HWND, 0),
            (UINT, WM_COMMAND),
            (UINT, IDS_APPNAME),
            (LONG, 0),
        ), ql.arch.regs.arch_pc)

    # get DialogBoxParamA return address; should be the first item on the stack
    retaddr = ql.arch.stack_read(0)

    # we would like to call DialogFunc as soon as DialogBoxParamA returns, so we
    # hook its return address. once it returns, 'call_DialogFunc' will be invoked.
    hh = ql.hook_address(call_DialogFunc, retaddr)

def our_sandbox(path: str, rootfs: str):
    ql = Qiling([path], rootfs, verbose=QL_VERBOSE.DEFAULT)

    # this crackme's logic lies within the function passed to DialogBoxParamA through
    # the lpDialogFunc parameter. normally DialogBoxParamA would call the function
    # passed through that parameter, but Qiling's implementation for it doesn't do
    # that.
    #
    # to solve this crackme and force the "success" dialog to show, we will:
    #  1. set up a mock stdin and feed it with the correct flag
    #  1. hook DialogBoxParamA to see where its lpDialogFunc param points to
    #  2. set up a valid set of arguments DialogFunc expects to see
    #  3. call it and see it greets us with a "success" message

    # [step #1]
    # set up a mock stdin and feed it with mocked keystrokes
    ql.os.stdin = pipe.SimpleInStream(sys.stdin.fileno())
    ql.os.stdin.write(b'Ea5yR3versing\n')

    # [step #2]
    # intercept DialogBoxParamA on exit
    ql.os.set_api('DialogBoxParamA', hook_DialogBoxParamA_onexit, QL_INTERCEPT.EXIT)

    ql.run()

if __name__ == "__main__":
    our_sandbox(r"rootfs/x86_windows/bin/Easy_CrackMe.exe", r"rootfs/x86_windows")
