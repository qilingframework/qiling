#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from .utils import *

def hook_EndOfExecution(ql):
    if check_and_notify_protocols(ql):
        return
    if len(ql.loader.modules) < 1:
        ql.nprint(f'No more modules to run')
        ql.emu_stop()
    else:
        path, entry_point, pe = ql.loader.modules.pop(0)
        ql.stack_push(ql.loader.end_of_execution_ptr)
        ql.reg.rdx = ql.loader.system_table_ptr
        ql.nprint(f'Running {path} module entrypoint: 0x{entry_point:x}')
        ql.reg.arch_pc = entry_point

def hook_EndOfNotify(ql):
    ql.nprint(f'Back from event notify returning to:{ql.os.notify_return_address:x}')
    ql.reg.arch_pc = ql.os.notify_return_address
    return 0  