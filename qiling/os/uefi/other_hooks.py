from unicorn.x86_const import *

def check_and_notify_protocols(ql):
    if len(ql.notify_list) > 0:
        event_id, notify_func, notify_context = ql.notify_list.pop(0)
        ql.nprint(f'Notify event:{event_id} calling:{notify_func:x} context:{notify_context:x}')
        ql.stack_push(ql.end_of_execution_ptr)
        ql.reg.rcx = notify_context
        ql.reg.arch_pc = notify_func
        return True
    return False

def hook_EndOfExecution(ql):
    if check_and_notify_protocols(ql):
        return
    if len(ql.modules) < 1:
        ql.nprint(f'No more modules to run')
        ql.emu_stop()
    else:
        path, entry_point, pe = ql.modules.pop(0)
        ql.stack_push(ql.end_of_execution_ptr)
        ql.reg.rdx = ql.os.system_table_ptr
        ql.nprint(f'Running {path} module entrypoint: 0x{entry_point:x}')
        ql.reg.arch_pc = entry_point

def hook_EndOfNotify(ql):
    ql.nprint(f'Back from event notify returning to:{ql.notify_return_address:x}')
    ql.reg.arch_pc = ql.notify_return_address
    return 0