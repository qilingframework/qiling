#!/usr/bin/env python3
from qiling.const import *
from functools import partial




# class for color decoration
class color:
   CYAN =      '\033[96m'
   PURPLE =    '\033[95m'
   BLUE =      '\033[94m'
   YELLOW =    '\033[93m'
   GREEN =     '\033[92m'
   RED =       '\033[91m'
   DARKGRAY =  '\033[90m'
   DARKCYAN =  '\033[36m'
   BLACK =     '\033[35m'
   UNDERLINE = '\033[4m'
   BOLD =      '\033[1m'
   END =       '\033[0m'


def dump_regs(ql, *args, **kwargs):
    
    if ql.archtype == QL_ARCH.MIPS:

        print(color.DARKCYAN, "gp: 0x%08x \t at: 0x%08x \t v0: 0x%08x \t v1: 0x%08x" % (ql.reg.gp, ql.reg.at, ql.reg.v0, ql.reg.v1), color.END, sep="")
        print(color.BLUE,     "a0: 0x%08x \t a1: 0x%08x \t a2: 0x%08x \t a3: 0x%08x" % (ql.reg.a0, ql.reg.a1, ql.reg.a2, ql.reg.a3), color.END, sep="")
        print(color.RED,      "t0: 0x%08x \t t1: 0x%08x \t t2: 0x%08x \t t3: 0x%08x" % (ql.reg.t0, ql.reg.t1, ql.reg.t2, ql.reg.t3), color.END, sep="")
        print(color.YELLOW,   "t4: 0x%08x \t t5: 0x%08x \t t6: 0x%08x \t t7: 0x%08x" % (ql.reg.t4, ql.reg.t5, ql.reg.t6, ql.reg.t7), color.END, sep="")
        print(color.GREEN,    "t8: 0x%08x \t t9: 0x%08x \t sp: 0x%08x \t fp: 0x%08x" % (ql.reg.t8, ql.reg.t9, ql.reg.sp, ql.reg.s8), color.END, sep="")
        print(color.PURPLE,   "s0: 0x%08x \t s1: 0x%08x \t s2: 0x%08x \t s3: 0x%08x" % (ql.reg.s0, ql.reg.s1, ql.reg.s2, ql.reg.s3), color.END, sep="")
        print(color.CYAN,     "s4: 0x%08x \t s5: 0x%08x \t s6: 0x%08x \t s7: 0x%08x" % (ql.reg.s4, ql.reg.s5, ql.reg.s6, ql.reg.s7), color.END, sep="")
        print(color.DARKGRAY, "ra: 0x%08x \t k0: 0x%08x \t k1: 0x%08x \t pc: 0x%08x" % (ql.reg.ra, ql.reg.k0, ql.reg.k1, ql.reg.pc), color.END, sep="")


def dump_stack(ql, *args, **kwargs):

    for idx in range(8):
        _addr = ql.reg.arch_sp + idx * 4
        _val = ql.mem.read(_addr, ql.archbit // 8)
        print("$sp+0x%02x|[0x%08x]=> 0x%08x" % (idx*4, _addr, ql.unpack(_val)), end="")

        try: # try to deference wether its a pointer
            _deref = ql.mem.read(_addr, 4)
        except:
            _deref = None

        if _deref:
            print(" => 0x%08x" % ql.unpack(_deref))


# parse unsigned integer from string 
def parse_int(s):
    return int(s, 16) if s.startswith("0x") else int(s)


# check wether negative value or not
def is_negative(i):
    return i & (1 << 31)


# convert valu to signed
def signed_val(i):
    val = i

    if is_negative(val):
        val -= 1 << 32

    return val


# handle braches and jumps so we can set berakpoint properly
def handle_bnj(ql, cur_addr):
    return {
            QL_ARCH.MIPS: handle_bnj_mips,
            }.get(ql.archtype)(ql, cur_addr)


def handle_bnj_mips(ql, cur_addr):
    MIPS_INST_SIZE = 4

    def _read_reg(regs, _reg):
        return getattr(regs, _reg.strip('$').replace("fp", "s8"))

    read_reg_val = partial(_read_reg, ql.reg)
    md = ql.os.create_disassembler()
    _cur_ops = ql.mem.read(cur_addr, MIPS_INST_SIZE)
    _tmp = md.disasm(_cur_ops, cur_addr)
    line = next(_tmp)

    # default breakpoint address if no jumps and branches here
    ret_addr = cur_addr + MIPS_INST_SIZE

    if line.mnemonic.startswith('j') or line.mnemonic.startswith('b'):
        # make sure at least delay slot executed
        ret_addr += MIPS_INST_SIZE

        # get registers or memory address from op_str
        targets = [
                _read_reg(ql.reg, each)
                if '$' in each else parse_int(each)
                for each in line.op_str.split(", ")
                ]

        to_jump = {
                "j"     : (lambda _: True),             # uncontitional jump
                "jr"    : (lambda _: True),             # uncontitional jump
                "jal"   : (lambda _: True),             # uncontitional jump
                "jalr"  : (lambda _: True),             # uncontitional jump
                "b"     : (lambda _: True),             # unconditional branch
                "bl"    : (lambda _: True),             # unconditional branch
                "bal"   : (lambda _: True),             # unconditional branch
                "beq"   : (lambda r0, r1, _: r0 == r1), # branch on equal
                "bne"   : (lambda r0, r1, _: r0 != r1), # branch on not equal
                "beqz"  : (lambda r, _: r == 0),        # branch on equal to zero
                "bnez"  : (lambda r, _: r != 0),        # branch on not equal to zero
                "bgtz"  : (lambda r, _: r > 0),         # branch on greater than zero
                "bltz"  : (lambda r, _: r < 0),         # branch on less than zero
                "bltzal": (lambda r, _: r < 0),         # branch on less than zero and link
                "blez"  : (lambda r, _: r <= 0),        # branch on less than or equal to zero
                "bgez"  : (lambda r, _: r >= 0),        # branch on greater than or equal to zero
                "bgezal"  : (lambda r, _: r >= 0),      # branch on greater than or equal to zero and link
                }.get(line.mnemonic, None)(*targets)

        if to_jump:
            # target address is always the rightmost one
            ret_addr = targets[-1]

    return ret_addr



if __name__ == "__main__":
    pass
