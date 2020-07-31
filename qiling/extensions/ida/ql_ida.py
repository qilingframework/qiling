from .ida import IDA
from qiling import Qiling
from qiling.const import arch_map
from unicorn import *

class QLIDA:
    def __init__(self, ql):
        self._ql = ql

    @property
    def ql(self):
        return self._ql

    def _override_registers(self, registers):
        for reg, val in registers.items():
            self.ql.reg.__setattr__(reg, val)

    def run(self, begin=1, end=0, registers={}, instruction_hook=None, call_hook=None, memaccess_hook=None, hook_data=None, timeout=0, count=0):
        self._override_registers(registers)
        if instruction_hook:
            self.ql.hook_code(instruction_hook, hook_data)
        if memaccess_hook:
            self.ql.ql_hook(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, memaccess_hook, hook_data)
        self.ql.run(begin=begin, end=end, timeout=timeout, count=count)

    def run_from_cursor(self):
        addr = IDA.get_current_address()
        self.run(begin=addr)

    def run_selection(self):
        _, begin, end = IDA.get_last_selection()
        self.run(begin=begin, end=end)

    @staticmethod
    def create_qida(fname=[IDA.get_input_file_path()], *args, **kwargs):
        return QLIDA(Qiling(fname, *args, **kwargs))
    
    @staticmethod
    def get_arch():
        return arch_map[IDA.get_ql_arch_string()]