# This code structure is copied and modified from the coverage extension

import qiling
from qiling.const import QL_ENDIAN
from .base import QlBaseTrace
from .registers import ArchRegs
from unicorn.unicorn_const import UC_MEM_READ, UC_MEM_WRITE

class QlDrTrace(QlBaseTrace):
    """
    Traces emulation and puts it into a format viewable in Tenet
    IDAPro plugin Tenet: https://github.com/gaasedelen/tenet
    """

    FORMAT_NAME = "tenet"

    def __init__(self, ql: qiling.Qiling):
        super().__init__()
        self.ql             = ql
        self.deltas         = []
        self.current_delta  = []
        self.current_pc     = 0x0

        self.arch_regs = ArchRegs(ql.arch)
        self.register_values= dict()

        # Initialize with ridiculous value so first delta isn't missed
        for register in self.arch_regs.registers:
            self.register_values[register] = 0xFEEDBABE


    def _add_delta(self):
        # Cover glitch cases where nothing changed
        if self.current_delta != []:
            # Join all delta fragments into delta line and append 
            self.deltas.append(",".join(self.current_delta))
            self.current_delta = []
        return


    @staticmethod
    def mem_access_callback(ql, access, address, size, value, self):
        access_type = None
        # Set delta based on access type
        if access == UC_MEM_READ:
            # Since we are reading memory, we just read it ourselves
            access_type = "mr"
            value = ql.mem.read(address, size)
            delta = f"{access_type}={hex(address)}:{value.hex()}"
        elif access == UC_MEM_WRITE:
            # Hook is before it's written, so we have to use the "value"
            access_type = "mw"
            if ql.arch.endian == QL_ENDIAN.EL:
                endian = 'little'
            else:
                endian = 'big'
            if value < 0:
                sign = True
            else:
                sign = False
            value = int.to_bytes(value, size, endian, signed=sign)
            delta = f"{access_type}={hex(address)}:{value.hex()}"
        else:
            print("Invalid access type")
            return
        # <ACCESS_TYPE>=<ACCESS_ADDRESS>:<HEX_BYTE_0><HEX_BYTE_1><HEX_BYTE_2>... 
        self.current_delta.append(delta)
        return

    @staticmethod
    def code_callback(ql, address, size, self):
        # Check if PC changed for next delta
        pc = ql.arch.regs.read(self.arch_regs.registers[self.arch_regs.pc_key])
        if pc != self.current_pc:
            self._add_delta()
            self.current_pc = pc
        # Go through each register and see if it changed
        for register in self.arch_regs.registers:
            value = ql.arch.regs.read(self.arch_regs.registers[register])
            if value != self.register_values[register]:
                # <REG_NAME>=<REG_VALUE_AS_BASE_16>
                delta = f"{register[1::]}={hex(value)}"
                self.current_delta.append(delta)
                # Update value
                self.register_values[register] = value
        
        return
        
    def activate(self):
        self.code_callback = self.ql.hook_code(self.code_callback, user_data=self)
        self.mem_write_callback = self.ql.hook_mem_read(self.mem_access_callback, user_data=self)
        self.mem_read_callback = self.ql.hook_mem_write(self.mem_access_callback, user_data=self)

    def deactivate(self):
        self.ql.hook_del(self.code_callback)
        self.ql.hook_del(self.mem_write_callback)
        self.ql.hook_del(self.mem_read_callback)
    
    def dump_trace(self, trace_file: str):
        with open(trace_file, "w") as trace:
            # Write out each delta on a separate line
            for delta in self.deltas:
                trace.write(delta + "\n")
