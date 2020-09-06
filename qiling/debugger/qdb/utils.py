#!/usr/bin/env python3

from functools import partial

from qiling.const import *

CODE_END = True 



def dump_regs(ql):

    if ql.archtype == QL_ARCH.MIPS:

        _reg_order = (
                "gp", "at", "v0", "v1",
                "a0", "a1", "a2", "a3",
                "t0", "t1", "t2", "t3",
                "t4", "t5", "t6", "t7",
                "t8", "t9", "sp", "s8",
                "s0", "s1", "s2", "s3",
                "s4", "s5", "s6", "s7",
                "ra", "k0", "k1", "pc",
                )

    elif ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB):

        _reg_order = (
                "r0", "r1", "r2", "r3",
                "r4", "r5", "r6", "r7",
                "r8", "r9", "r10", "r11",
                "r12", "sp", "lr", "pc",
                )

    return {reg_name: getattr(ql.reg, reg_name) for reg_name in _reg_order}


def get_arm_flags(bits):
    def _get_mode(bits):
        return {
                0b10000: "User",
                0b10001: "FIQ",
                0b10010: "IRQ",
                0b10011: "Supervisor",
                0b10110: "Monitor",
                0b10111: "Abort",
                0b11010: "Hypervisor",
                0b11011: "Undefined",
                0b11111: "System",
                }.get(bits & 0x00001f)

    return {
            "mode":     _get_mode(bits),
            "thumb":    bits & 0x00000020 != 0,
            "fiq":      bits & 0x00000040 != 0,
            "irq":      bits & 0x00000080 != 0,
            "neg":      bits & 0x80000000 != 0,
            "zero":     bits & 0x40000000 != 0,
            "carry":    bits & 0x20000000 != 0,
            "overflow": bits & 0x10000000 != 0,
            }


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
            QL_ARCH.MIPS     : handle_bnj_mips,
            QL_ARCH.ARM      : handle_bnj_arm,
            QL_ARCH.ARM_THUMB: handle_bnj_arm,
            }.get(ql.archtype)(ql, cur_addr)


def get_cpsr(bits):
    return (
            bits & 0x10000000 != 0, # V, overflow flag
            bits & 0x20000000 != 0, # C, carry flag
            bits & 0x40000000 != 0, # Z, zero flag
            bits & 0x80000000 != 0, # N, sign flag
            )


def is_thumb(bits):
    return bits & 0x00000020 != 0


def disasm(ql, address):
    md = ql.os.create_disassembler()
    return next(md.disasm(_read_inst(ql, address), address))


def _read_inst(ql, addr):

    if ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB):
        result = ql.mem.read(addr, 4) # default option for arm instruction
        if is_thumb(ql.reg.cpsr):

            first_two = ql.unpack16(ql.mem.read(addr, 2))
            result = ql.pack16(first_two)

            if any([
                first_two & 0xf000 == 0xf000,
                first_two & 0xf800 == 0xf800,
                first_two & 0xe800 == 0xe800,
                ]):

                latter_two = ql.unpack16(ql.mem.read(addr+2, 2))
                result += ql.pack16(latter_two)

    elif ql.archtype == QL_ARCH.MIPS:
        result = ql.mem.read(addr, 4)

    return result


def handle_bnj_arm(ql, cur_addr):

    def _read_reg_val(regs, _reg):
        return getattr(ql.reg, _reg.replace("ip", "r12"))

    def regdst_eq_pc(op_str):
        return op_str.partition(", ")[0] == "pc"


    read_inst = partial(_read_inst, ql)
    read_reg_val = partial(_read_reg_val, ql.reg)

    ARM_INST_SIZE = 4
    ARM_THUMB_INST_SIZE = 2

    line = disasm(ql, cur_addr)
    ret_addr = cur_addr + line.size

    if line.mnemonic == "udf": # indicates program exited
        return CODE_END

    jump_table = {
            # unconditional branch
            "b"    : (lambda *_: True),
            "bl"   : (lambda *_: True),
            "bx"   : (lambda *_: True),
            "blx"  : (lambda *_: True),
            "b.w"  : (lambda *_: True),

            # branch on equal, Z == 1
            "beq"  : (lambda V, C, Z, N: Z == 1),
            "bxeq" : (lambda V, C, Z, N: Z == 1),
            "beq.w": (lambda V, C, Z, N: Z == 1),

            # branch on not equal, Z == 0
            "bne"  : (lambda V, C, Z, N: Z == 0),
            "bxne" : (lambda V, C, Z, N: Z == 0),
            "bne.w": (lambda V, C, Z, N: Z == 0),

            # branch on signed greater than, Z == 0 and N == V
            "bgt"  : (lambda V, C, Z, N: (Z == 0 and N == V)),
            "bgt.w": (lambda V, C, Z, N: (Z == 0 and N == V)),

            # branch on signed less than, N != V
            "blt"  : (lambda V, C, Z, N: N != V),

            # branch on signed greater than or equal, N == V
            "bge"  : (lambda V, C, Z, N: N == V),

            # branch on signed less than or queal
            "ble"  : (lambda V, C, Z, N: Z == 1 or N != V),

            # branch on unsigned higher or same (or carry set), C == 1
            "bhs"  : (lambda V, C, Z, N: C == 1),
            "bcs"  : (lambda V, C, Z, N: C == 1),

            # branch on unsigned lower (or carry clear), C == 0
            "bcc"  : (lambda V, C, Z, N: C == 0),
            "blo"  : (lambda V, C, Z, N: C == 0),
            "bxlo" : (lambda V, C, Z, N: C == 0),
            "blo.w": (lambda V, C, Z, N: C == 0),

            # branch on negative or minus, N == 1
            "bmi"  : (lambda V, C, Z, N: N == 1),

            # branch on positive or plus, N == 0
            "bpl"  : (lambda V, C, Z, N: N == 0),

            # branch on signed overflow
            "bvs"  : (lambda V, C, Z, N: V == 1),

            # branch on no signed overflow
            "bvc"  : (lambda V, C, Z, N: V == 0),

            # branch on unsigned higher
            "bhi"  : (lambda V, C, Z, N: (Z == 0 and C == 1)),
            "bxhi" : (lambda V, C, Z, N: (Z == 0 and C == 1)),
            "bhi.w": (lambda V, C, Z, N: (Z == 0 and C == 1)),

            # branch on unsigned lower
            "bls"  : (lambda V, C, Z, N: (C == 0 or Z == 1)),
            "bls.w": (lambda V, C, Z, N: (C == 0 or Z == 1)),
            }

    cb_table = {
            # branch on equal to zero
            "cbz" : (lambda r: r == 0),

            # branch on not equal to zero
            "cbnz": (lambda r: r != 0),
            }

    to_jump = False
    if line.mnemonic in jump_table:
        to_jump = jump_table.get(line.mnemonic)(*get_cpsr(ql.reg.cpsr))

    elif line.mnemonic in cb_table:
        to_jump = cb_table.get(line.mnemonic)(read_reg_val(line.op_str.split(", ")[0]))

    if to_jump:
        if '#' in line.op_str:
            ret_addr = parse_int(line.op_str.split('#')[-1])
        else:
            ret_addr = read_reg_val(line.op_str)

            if regdst_eq_pc(line.op_str):
                next_addr = cur_addr + line.size
                n2_addr = next_addr + len(read_inst(next_addr))
                ret_addr += len(read_inst(n2_addr)) + len(read_inst(next_addr))

    elif line.mnemonic.startswith("it"):
        # handle IT block here

        cond_met = {
                "eq": lambda V, C, Z, N: (Z == 1),
                "ne": lambda V, C, Z, N: (Z == 0),
                "ge": lambda V, C, Z, N: (N == V),
                "hs": lambda V, C, Z, N: (C == 1),
                "lo": lambda V, C, Z, N: (C == 0),
                "mi": lambda V, C, Z, N: (N == 1),
                "pl": lambda V, C, Z, N: (N == 0),
                "ls": lambda V, C, Z, N: (C == 0 or Z == 1),
                "le": lambda V, C, Z, N: (Z == 1 or N != V),
                "hi": lambda V, C, Z, N: (Z == 0 and C == 1),
                }.get(line.op_str)(*get_cpsr(ql.reg.cpsr))
        
        it_block_range = [each_char for each_char in line.mnemonic[1:]]

        next_addr = cur_addr + ARM_THUMB_INST_SIZE
        for each in it_block_range:
            _inst = read_inst(next_addr)
            n2_addr = handle_bnj_arm(ql, next_addr)

            if (cond_met and each == "t") or (not cond_met and each == "e"):
                if n2_addr != (next_addr+len(_inst)): # branch detected
                    break

            next_addr += len(_inst)

        ret_addr = next_addr

        return ret_addr

    elif line.mnemonic in ("ldr",):
        if regdst_eq_pc(line.op_str):
            _pc, _, rn_offset = line.op_str.partition(", ")

            if "]" in rn_offset.split(", ")[1]: # pre-indexed immediate
                _, r, imm = line.op_str.replace("[", "").replace("]", "").replace("!", "").replace("#", "").split(", ")
                ret_addr = ql.unpack32(ql.mem.read(parse_int(imm) + read_reg_val(r), 4))

            else: # post-indexed immediate
                # FIXME: weired behavior, immediate here does not apply
                _, r, imm = line.op_str.replace("[", "").replace("]", "").replace("!", "").replace("#", "").split(", ")
                ret_addr = ql.unpack32(ql.mem.read(read_reg_val(r), 4))

    elif line.mnemonic in ("addls", "addne", "add") and regdst_eq_pc(line.op_str):
        V, C, Z, N = get_cpsr(ql.reg.cpsr)

        if line.mnemonic == "addls" and (C == 0 or Z == 1):
            r0, r1, r2, imm = line.op_str.split(", ")
            # program counter is awalys 8 bytes ahead , when it comes with pc need to add extra 8 bytes
            ret_addr = 8 + read_reg_val(r1) + read_reg_val(r2) * 4

        elif line.mnemonic == "addne" and Z == 0:
            r0, r1, r2, *rest = line.op_str.split(", ")
            ret_addr = 8 + read_reg_val(r1) + (read_reg_val(r2) * 4 if rest else read_reg_val(r2))

        elif line.mnemonic == "add":
            r0, r1, r2 = line.op_str.split(", ")
            ret_addr = 8 + sum(map(read_reg_val, [r1, r2]))

    elif line.mnemonic in ("tbh", "tbb"):

        cur_addr += ARM_INST_SIZE

        if line.mnemonic == "tbh":
            r0, r1, _ = line.op_str.strip("[").strip("]").split(", ")
            r1 = read_reg_val(r1) * 2

        elif line.mnemonic == "tbb":
            r0, r1 = line.op_str.strip("[").strip("]").split(", ")
            r1 = read_reg_val(r1)

        to_add = int.from_bytes(ql.mem.read(cur_addr+r1, 2 if line.mnemonic == "tbh" else 1), byteorder="little") * 2
        ret_addr = cur_addr + to_add

    elif line.mnemonic.startswith("pop") and "pc" in line.op_str:

        ret_addr = ql.stack_read(line.op_str.strip("{").strip("}").split(", ").index("pc") * 4)
        if not { # step to next instruction if cond does not meet
                "pop"  : lambda *_: True,
                "pop.w": lambda *_: True,
                "popeq": lambda V, C, Z, N: (Z == 1),
                "popne": lambda V, C, Z, N: (Z == 0),
                "pophi": lambda V, C, Z, N: (C == 1),
                "popge": lambda V, C, Z, N: (N == V),
                "poplt": lambda V, C, Z, N: (N != V),
                }.get(line.mnemonic)(*get_cpsr(ql.reg.cpsr)):

            ret_addr = cur_addr + ARM_INST_SIZE

    elif line.mnemonic == "sub" and regdst_eq_pc(line.op_str):
        _, r, imm = line.op_str.split(", ")
        ret_addr = read_reg_val(r) - parse_int(imm.strip("#"))

    elif line.mnemonic == "mov" and regdst_eq_pc(line.op_str):
        _, r = line.op_str.split(", ")
        ret_addr = read_reg_val(r)

    if ret_addr & 1:
        ret_addr -= 1

    return ret_addr


def handle_bnj_mips(ql, cur_addr):
    MIPS_INST_SIZE = 4

    def _read_reg(regs, _reg):
        return signed_val(getattr(regs, _reg.strip('$').replace("fp", "s8")))

    read_reg_val = partial(_read_reg, ql.reg)

    line = disasm(ql, cur_addr)

    # default breakpoint address if no jumps and branches here
    ret_addr = cur_addr + MIPS_INST_SIZE

    if line.mnemonic.startswith('j') or line.mnemonic.startswith('b'):
        if line.mnemonic == "break": # indicates program extied
            return CODE_END

        # make sure at least delay slot executed
        ret_addr += MIPS_INST_SIZE

        # get registers or memory address from op_str
        targets = [
                read_reg_val(each)
                if '$' in each else parse_int(each)
                for each in line.op_str.split(", ")
                ]

        to_jump = {
                "j"       : (lambda _: True),             # uncontitional jump
                "jr"      : (lambda _: True),             # uncontitional jump
                "jal"     : (lambda _: True),             # uncontitional jump
                "jalr"    : (lambda _: True),             # uncontitional jump
                "b"       : (lambda _: True),             # unconditional branch
                "bl"      : (lambda _: True),             # unconditional branch
                "bal"     : (lambda _: True),             # unconditional branch
                "beq"     : (lambda r0, r1, _: r0 == r1), # branch on equal
                "bne"     : (lambda r0, r1, _: r0 != r1), # branch on not equal
                "blt"     : (lambda r0, r1, _: r0 < r1),  # branch on r0 less than r1
                "bgt"     : (lambda r0, r1, _: r0 > r1),  # branch on r0 greater than r1
                "ble"     : (lambda r0, r1, _: r0 <= r1), # brach on r0 less than or equal to r1
                "bge"     : (lambda r0, r1, _: r0 >= r1), # branch on r0 greater than or equal to r1
                "beqz"    : (lambda r, _: r == 0),        # branch on equal to zero
                "bnez"    : (lambda r, _: r != 0),        # branch on not equal to zero
                "bgtz"    : (lambda r, _: r > 0),         # branch on greater than zero
                "bltz"    : (lambda r, _: r < 0),         # branch on less than zero
                "bltzal"  : (lambda r, _: r < 0),         # branch on less than zero and link
                "blez"    : (lambda r, _: r <= 0),        # branch on less than or equal to zero
                "bgez"    : (lambda r, _: r >= 0),        # branch on greater than or equal to zero
                "bgezal"  : (lambda r, _: r >= 0),        # branch on greater than or equal to zero and link
                }.get(line.mnemonic)(*targets)

        if to_jump:
            # target address is always the rightmost one
            ret_addr = targets[-1]

    return ret_addr


def diff_snapshot_save(current_state_dicts, prev_states):

    result = {}
    cur_cpu_ctx_set = {(idx, val) for idx, val in enumerate(current_state_dicts["cpu_context"])}

    cur_mem_set = set()
    for region_idx, mem_region_info in current_state_dicts["mem"].items():
        raw_bytes = bytes(mem_region_info[-1])
        cur_mem_set.update({(region_idx, *(mem_region_info[:-1]), raw_bytes)})

    if prev_states is not None:
        cur_cpu_ctx_set -= prev_states["cpu_context"]
        result.update({"cpu_context": cur_cpu_ctx_set})

        if "mem" in prev_states and cur_mem_set != prev_states["mem"]:
            # save changes if its different
            cur_mem_set -= prev_states["mem"]
            result.update({"mem": cur_mem_set})

    else:
        # store everything since its the first snapshot
        result.update({"cpu_context": cur_cpu_ctx_set, "mem": cur_mem_set})

    return result


def diff_snapshot_restore(current_state_dicts, prev_states):

    result = {}
    _cur_cpu_ctx_dict = {idx: val for idx, val in enumerate(current_state_dicts["cpu_context"])}
    _cur_mem_dict = current_state_dicts["mem"]

    last_cpu_ctx_set = prev_states["cpu_context"]
    last_mem_set = prev_states.pop("mem", None)

    # restore diff snapshot from last cpu_context
    _cur_cpu_ctx_dict.update({addr: raw_byte for addr, raw_byte in last_cpu_ctx_set})
    result.update({"cpu_context": bytes(_cur_cpu_ctx_dict.values())})

    # restore diff snapshot from last memory dump
    if last_mem_set is not None and len(last_mem_set) > 0:
        last_mem_dict = {}
        for region_idx, *region_info, raw_bytes in last_mem_set:
            _region = _cur_mem_dict.get(region_idx, None)
            if _region:
                last_mem_dict.update({region_idx: (*_region[:-1], raw_bytes)})
            else:
                last_mem_dict.update({region_idx: (*region_info, raw_bytes)})

        result.update({"mem": last_mem_dict})

    return result


if __name__ == "__main__":
    pass
