#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import sys
sys.path.append("..")
from qiling import *

from capstone import *
from unicorn.x86_const import *

sys.path.append("..")

md = Cs(CS_ARCH_X86, CS_MODE_64)


breakOn = False

def my_syscall_write(ql, write_fd, write_buf, write_count, null0, null1, null2):
    regreturn = 0
    buf = None
    
    try:
        buf = ql.uc.mem_read(write_buf, write_count)
        ql.nprint("\n+++++++++\nmy write(%d,%x,%i) = %d\n+++++++++" % (write_fd, write_buf, write_count, regreturn))
        ql.file_des[write_fd].write(buf)
        regreturn = write_count
    except:
        regreturn = -1
        ql.nprint("\n+++++++++\nmy write(%d,%x,%i) = %d\n+++++++++" % (write_fd, write_buf, write_count, regreturn))
        if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
            raise
    ql_definesyscall_return(ql, regreturn)


def dump_everything(ql, address, size, user_data):
    global breakOn
    flag = False
    buf = ql.uc.mem_read(address, size)
    for i in md.disasm(buf, address):
        print("PC :: 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        if i.address - 0x3000000000000000 in user_data:
            flag = True
    rax = uc.reg_read(UC_X86_REG_RAX)
    rbx = uc.reg_read(UC_X86_REG_RBX)
    rcx = uc.reg_read(UC_X86_REG_RCX)
    ddx = uc.reg_read(UC_X86_REG_RDX)
    rdi = uc.reg_read(UC_X86_REG_RDI)
    rsi = uc.reg_read(UC_X86_REG_RSI)
    rbp = uc.reg_read(UC_X86_REG_RBP)
    rsp = uc.reg_read(UC_X86_REG_RSP)
    ds = uc.reg_read(UC_X86_REG_DS)
    gs = uc.reg_read(UC_X86_REG_GS)
    ss = uc.reg_read(UC_X86_REG_SS)
    cs = uc.reg_read(UC_X86_REG_CS)

    if flag:
        breakOn = True

    if breakOn:
        print(">>> RAX= 0x%lx, RBX= 0x%lx, RCX= 0x%lx, RDX= 0x%lx, RDI= 0x%lx, RSI= 0x%lx, RBP= 0x%lx, RSP= 0x%lx, DS= 0x%lx, GS= 0x%lx, SS= 0x%lx, CS= 0x%lx " % (rax, rbx, rcx, rdx, rdi, rsi, rbp, rsp, ds, gs, ss, cs))
        stack_info = uc.mem_read(esp, 20)
        # print(stack_info)
        print ("")
        c = input()
        if c == 'c':
            breakOn = False

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_macos/bin/x8664_hello"], "rootfs/x8664_macos", output = "debug")
    break_point = [
        # 0x1276,
        # 0x4320
        # 0x0182A,
        0x5B7B,
    ]
    # ql.hook_code(dump_everything, break_point)
    ql.set_syscall(0x01, my_syscall_write)
    ql.run()
