#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from .utils import *

def hook_EndOfExecution(ql):
    if check_and_notify_protocols(ql):
        return
    if len(ql.loader.modules) < 1:
        if ql.loader.unload_modules():
            return
        ql.nprint(f'[+] No more modules to run')
        ql.emu_stop()
    else:
        ql.loader.execute_next_module()

def hook_EndOfNotify(ql):
    ql.nprint(f'Back from event notify returning to:{ql.os.notify_return_address:x}')
    ql.reg.arch_pc = ql.os.notify_return_address
    return 0  