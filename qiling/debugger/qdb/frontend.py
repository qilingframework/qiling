#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import Optional, Mapping, Iterable, Union

import copy, math, os
from contextlib import contextmanager

from qiling.const import QL_ARCH

import unicorn

from .utils import dump_regs, get_arm_flags, disasm, _parse_int, handle_bnj
from .const import *


# read data from memory of qiling instance
def examine_mem(ql: Qiling, line: str) -> Union[bool, (str, int, int)]:

    _args = line.split()
    DEFAULT_FMT = ('x', 4, 1)

    if line.startswith("/"):  # followed by format letter and size letter

        def get_fmt(text):
            def extract_count(t):
                return "".join([s for s in t if s.isdigit()])

            f, s, c = DEFAULT_FMT
            if extract_count(text):
                c = int(extract_count(text))

            for char in text.strip(str(c)):
                if char in SIZE_LETTER.keys():
                    s = SIZE_LETTER.get(char)

                elif char in FORMAT_LETTER:
                    f = char

            return (f, s, c)


        fmt, *rest = line.strip("/").split()

        rest = "".join(rest)

        fmt = get_fmt(fmt)

    elif len(_args) == 1:  # only address
        rest = _args[0]
        fmt = DEFAULT_FMT

    else:
        rest = _args

    if ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB):
        rest = rest.replace("fp", "r11")

    elif ql.archtype == QL_ARCH.MIPS:
        rest = rest.replace("fp", "s8")

    # for supporting addition of register with constant value
    elems = rest.split("+")
    elems = [elem.strip("$") for elem in elems]

    items = []
    for elem in elems:
        if elem in ql.reg.register_mapping.keys():
            items.append(getattr(ql.reg, elem, None))
        else:
            items.append(_parse_int(elem))

    addr = sum(items)

    def unpack(bs, sz):
        return {
                1: lambda x: x[0],
                2: ql.unpack16,
                4: ql.unpack32,
                8: ql.unpack64,
                }.get(sz)(bs)

    ft, sz, ct = fmt

    if ft == "i":

        for offset in range(addr, addr+ct*4, 4):
            line = disasm(ql, offset)
            if line:
                print(f"0x{line.address:x}: {line.mnemonic}\t{line.op_str}")

        print()

    else:
        lines = 1 if ct <= 4 else math.ceil(ct / 4)

        mem_read = []
        for offset in range(ct):
            # append data if read successfully, otherwise return error message
            if (data := _try_read(ql, addr+(offset*sz), sz))[0] is not None:
                mem_read.append(data[0])

            else:
                return data[1]

        for line in range(lines):
            offset = line * sz * 4
            print(f"0x{addr+offset:x}:\t", end="")

            idx = line * ql.pointersize
            for each in mem_read[idx:idx+ql.pointersize]:
                data = unpack(each, sz)
                prefix = "0x" if ft in ("x", "a") else ""
                pad = '0' + str(sz*2) if ft in ('x', 'a', 't') else ''
                ft = ft.lower() if ft in ("x", "o", "b", "d") else ft.lower().replace("t", "b").replace("a", "x")
                print(f"{prefix}{data:{pad}{ft}}\t", end="")

            print()

    return True


# get terminal window height and width
def get_terminal_size() -> Iterable:
    return map(int, os.popen('stty size', 'r').read().split())


# try to read data from ql memory
def _try_read(ql: Qiling, address: int, size: int) -> Optional[bytes]:

    result = None
    err_msg = ""
    try:
        result = ql.mem.read(address, size)

    except unicorn.unicorn.UcError as err:
        if err.errno == 6: # Invalid memory read (UC_ERR_READ_UNMAPPED)
            err_msg = f"Can not access memory at address 0x{address:08x}"

    except:
        pass

    return (result, err_msg)


# divider printer
@contextmanager
def context_printer(ql: Qiling, field_name: str, ruler: str = "─") -> None:
    height, width = get_terminal_size()
    bar = (width - len(field_name)) // 2 - 1
    print(ruler * bar, field_name, ruler * bar)
    yield
    if "DISASM" in field_name:
        print(ruler * width)


def context_reg(ql: Qiling, saved_states: Optional[Mapping[str, int]] = None, /, *args, **kwargs) -> None:

    # context render for registers
    with context_printer(ql, "[ REGISTERS ]"):

        _cur_regs = dump_regs(ql)

        _colors = (color.DARKCYAN, color.BLUE, color.RED, color.YELLOW, color.GREEN, color.PURPLE, color.CYAN, color.WHITE)

        if ql.archtype == QL_ARCH.MIPS:

            _cur_regs.update({"fp": _cur_regs.pop("s8")})

            if saved_states is not None:
                _saved_states = copy.deepcopy(saved_states)
                _saved_states.update({"fp": _saved_states.pop("s8")})
                _diff = [k for k in _cur_regs if _cur_regs[k] != _saved_states[k]]

            else:
                _diff = None

            lines = ""
            for idx, r in enumerate(_cur_regs, 1):
                line = "{}{}: 0x{{:08x}} {}\t".format(_colors[(idx-1) // 4], r, color.END)

                if _diff and r in _diff:
                    line = f"{color.UNDERLINE}{color.BOLD}{line}"

                if idx % 4 == 0 and idx != 32:
                    line += "\n"

                lines += line

            print(lines.format(*_cur_regs.values()))

        elif ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB, QL_ARCH.CORTEX_M):


            _cur_regs.update({"sl": _cur_regs.pop("r10")})
            _cur_regs.update({"ip": _cur_regs.pop("r12")})
            _cur_regs.update({"fp": _cur_regs.pop("r11")})

            regs_in_row = 4
            if ql.archtype == QL_ARCH.CORTEX_M:
                regs_in_row = 3

                # for re-order
                _cur_regs.update({"xpsr": _cur_regs.pop("xpsr")})
                _cur_regs.update({"control": _cur_regs.pop("control")})
                _cur_regs.update({"primask": _cur_regs.pop("primask")})
                _cur_regs.update({"faultmask": _cur_regs.pop("faultmask")})
                _cur_regs.update({"basepri": _cur_regs.pop("basepri")})

            _diff = None
            if saved_states is not None:
                _saved_states = copy.deepcopy(saved_states)
                _saved_states.update({"sl": _saved_states.pop("r10")})
                _saved_states.update({"ip": _saved_states.pop("r12")})
                _saved_states.update({"fp": _saved_states.pop("r11")})
                _diff = [k for k in _cur_regs if _cur_regs[k] != _saved_states[k]]

            lines = ""
            for idx, r in enumerate(_cur_regs, 1):

                line = "{}{:}: 0x{{:08x}} {}  ".format(_colors[(idx-1) // regs_in_row], r, color.END)

                if _diff and r in _diff:
                    line = "{}{}".format(color.UNDERLINE, color.BOLD) + line

                if idx % regs_in_row == 0:
                    line += "\n"

                lines += line

            print(lines.format(*_cur_regs.values()))
            print(color.GREEN, "[{cpsr[mode]} mode], Thumb: {cpsr[thumb]}, FIQ: {cpsr[fiq]}, IRQ: {cpsr[irq]}, NEG: {cpsr[neg]}, ZERO: {cpsr[zero]}, Carry: {cpsr[carry]}, Overflow: {cpsr[overflow]}".format(cpsr=get_arm_flags(ql.reg.cpsr)), color.END, sep="")

    if ql.archtype != QL_ARCH.CORTEX_M:
    # context render for Stack, skip this for CORTEX_M
        with context_printer(ql, "[ STACK ]", ruler="─"):

            for idx in range(10):
                addr = ql.reg.arch_sp + idx * ql.pointersize
                val = ql.mem.read(addr, ql.pointersize)
                print(f"$sp+0x{idx*ql.pointersize:02x}│ [0x{addr:08x}] —▸ 0x{ql.unpack(val):08x}", end="")

                # try to dereference wether it's a pointer
                if (buf := _try_read(ql, addr, ql.pointersize))[0] is not None:

                    if (addr := ql.unpack(buf[0])):

                        # try to dereference again
                        if (buf := _try_read(ql, addr, ql.pointersize))[0] is not None:
                            try:
                                s = ql.mem.string(addr)
                            except:
                                s = None

                            if s and s.isprintable():
                                print(f" ◂— {ql.mem.string(addr)}", end="")
                            else:
                                print(f" ◂— 0x{ql.unpack(buf[0]):08x}", end="")
                print()


def print_asm(ql: Qiling, insn: CsInsn, to_jump: Optional[bool] = None, address: int = None) -> None:

    opcode = "".join(f"{b:02x}" for b in insn.bytes)
    trace_line = f"0x{insn.address:08x} │ {opcode:10s} {insn.mnemonic:10} {insn.op_str:35s}"

    cursor = " "
    if ql.reg.arch_pc == insn.address:
        cursor = "►"

    jump_sign = " "
    if to_jump and address != ql.reg.arch_pc+4:
        jump_sign = f"{color.RED}✓{color.END}"

    print(f"{jump_sign}  {cursor}   {color.DARKGRAY}{trace_line}{color.END}")


def context_asm(ql: Qiling, address: int) -> None:

    with context_printer(ql, field_name="[ DISASM ]"):

        # assembly before current location

        past_list = []

        line = disasm(ql, address-0x10)

        while line:
            if line.address == address:
                break

            addr = line.address + line.size
            line = disasm(ql, addr)

            if not line:
                break

            past_list.append(line)

        # print four insns before current location
        for line in past_list[:-1][:4]:
            print_asm(ql, line)

        # assembly for current location

        cur_ins = disasm(ql, address)
        to_jump, next_stop = handle_bnj(ql, address)
        print_asm(ql, cur_ins, to_jump=to_jump)

        # assembly after current location

        forward_insn_size = cur_ins.size
        for _ in range(5):
            forward_insn = disasm(ql, address+forward_insn_size)
            if forward_insn:
                print_asm(ql, forward_insn)
                forward_insn_size += forward_insn.size
