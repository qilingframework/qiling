from .ida import IDA
from qiling import Qiling
from qiling.const import arch_map

class QLIDA:
    def __init__(self, ql):
        self._ql = ql

    @property
    def ql(self):
        return self._ql

    def _override_registers(self, registers):
        for reg, val in registers.items():
            self.ql.reg.__setattr__(reg, val)

    def run(self, begin, end, registers={}, instruction_hook=None, call_hook=None, memaccess_hook=None, hook_data=None, skipCall=True):
        self._override_registers(registers)
        pass

    def run_from_cursor(self):
        pass

    def run_selection(self):
        _, start, end = IDA.get_last_selection()
        self.ql.run(begin=start, end=end)

    @staticmethod
    def create_qida(fname=[IDA.get_input_file_path()], *args, **kwargs):
        return QLIDA(Qiling(fname, *args, **kwargs))
    
    @staticmethod
    def get_arch():
        return arch_map[IDA.get_ql_arch_string()]