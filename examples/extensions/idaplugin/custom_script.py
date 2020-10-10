from qiling import *
import logging

class QILING_IDA():
    def __init__(self):
        pass

    def _show_context(self, ql:Qiling):
        registers = [ k for k in ql.reg.register_mapping.keys() if type(k) is str ]
        for idx in range(0, len(registers), 3):
            regs = registers[idx:idx+3]
            s = "\t".join(map(lambda v: f"{v:4}: {ql.reg.__getattribute__(v):016x}", regs))
            logging.info(s)

    def custom_prepare(self, ql:Qiling):
        logging.info('Context before starting emulation:')
        self._show_context(ql)

    def custom_continue(self, ql:Qiling):
        logging.info('custom_continue hook.')
        self._show_context(ql)
        hook = []
        return hook

    def custom_step(self, ql:Qiling):
        def step_hook(ql, addr, size):
            logging.info(f"Executing: {hex(addr)}")
            self._show_context(ql)

        logging.info('custom_step hook')
        hook = []
        hook.append(ql.hook_code(step_hook))
        return hook
    
    def custom_execute_selection(self, ql:Qiling):
        logging.info('custom execute selection hook')
        hook = []
        return hook