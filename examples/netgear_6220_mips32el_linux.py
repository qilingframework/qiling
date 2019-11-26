#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


"""
Example on how to run a Netgear firmware, firmware image not included
"""

import sys
sys.path.append("..")
from qiling import *
from unicorn.mips_const import *
from capstone.mips_const import *
from capstone import *

md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)

def dump_everything(uc, address, size, ql):
    V0 = ql.uc.reg_read(UC_MIPS_REG_V0)
    V1 = ql.uc.reg_read(UC_MIPS_REG_V1)
    A0 = ql.uc.reg_read(UC_MIPS_REG_A0)
    A1 = ql.uc.reg_read(UC_MIPS_REG_A1)
    A2 = ql.uc.reg_read(UC_MIPS_REG_A2)
    A3 = ql.uc.reg_read(UC_MIPS_REG_A3)
    SP = ql.uc.reg_read(UC_MIPS_REG_SP)
    PC = ql.uc.reg_read(UC_MIPS_REG_PC)
    

    buf = ql.uc.mem_read(address, size)
    for i in md.disasm(buf, address):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        print(">>> V0= 0x%x , V1= 0x%x, A0= 0x%x, A1= 0x%x, A2= 0x%x, A3= 0x%x, SP= 0x%x, PC= 0x%x" % (V0, V1, A0, A1, A2, A3, SP, PC))
    
    
def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, output="debug", log_file = 'logfile', separate_log_file = True, consolelog = True)
    ql.root = False
    ql.add_fs_mapper('/proc', '/proc')
    #ql.hook_code(dump_everything)
    ql.run()


if __name__ == "__main__":
    my_sandbox(["rootfs/netgear_r6220/bin/mini_httpd","-d","/www","-r","NETGEAR R6220","-c","**.cgi","-t","300"], "rootfs/netgear_r6220")
