#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


from .utils import execute_protocol_notifications

def hook_EndOfExecution(ql):
    if ql.os.notify_after_module_execution(ql, len(ql.loader.modules)):
        return

    ql.loader.restore_runtime_services()

    if execute_protocol_notifications(ql):
        return

    if ql.loader.modules:
        ql.loader.execute_next_module()
    else:
        if ql.loader.unload_modules():
            return

        ql.log.info(f'No more modules to run')
        ql.emu_stop()
        ql.os.PE_RUN = False
