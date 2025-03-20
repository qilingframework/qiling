#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

import re

from typing import TYPE_CHECKING, List, Tuple

from qiling.const import QL_ARCH
from .context import Context
from .arch import ArchCORTEX_M, ArchARM, ArchMIPS, ArchX86, ArchX64


if TYPE_CHECKING:
    from re import Match
    from qiling import Qiling
    from .misc import InsnLike


def setup_command_helper(ql: Qiling):
    atypes = {
        QL_ARCH.X86:      ArchX86,
        QL_ARCH.X8664:    ArchX64,
        QL_ARCH.MIPS:     ArchMIPS,
        QL_ARCH.ARM:      ArchARM,
        QL_ARCH.CORTEX_M: ArchCORTEX_M
    }

    ret = type('CommandHelper', (CommandHelper, atypes[ql.arch.type]), {})

    return ret(ql)


# pre-compile the safe arithmetics and bitwise pattern
__arith_pattern = re.compile(r'^(0[xX][0-9a-fA-F]+|0[0-7]+|\d+|[\+\-\*/\(\)|&^~\s])+$')


def safe_arith(expr: str) -> int:
    """Safely evaluate an arithmetic expression. The expression may include only
    digits, arithmetic and bitwise operators, parantheses, whitespaces, hexadecimal
    and octal values.

    Args:
        expr: arithmetic expression to evaluate

    Returns: integer result

    Raises:
        ValueError: if disallowed tokens are included in `expr`
        SyntaxError: in case the arithmetic expression does not make sense
    """

    if not __arith_pattern.fullmatch(expr):
        raise ValueError

    # adjust gdb-style octal values to python: 0644 -> 0o644
    re.sub(r'0([0-7]+)', r'0o\1', expr)

    # safely evaluate the expression
    return eval(expr, {}, {})


class CommandHelper(Context):
    """
    memory manager for handing memory access
    """

    def __init__(self, ql: Qiling):
        super().__init__(ql)

        # default values for the examine ('x') command
        self.x_defaults = {
            'n': '1',   # number of units to read
            'f': 'x',   # output format
            'u': 'w'    # unit type
        }

    def sub_reg_values(self, expr: str) -> str:
        def __sub_reg(m: Match[str]) -> str:
            reg = m.group(1).lower()

            return f'{self.read_reg(self.unalias(reg)):#x}'

        # replace reg names with their actual values
        return re.sub(r'\$(\w+)', __sub_reg, expr)

    def resolve_expr(self, expr: str) -> int:
        """Resolve an arithmetic expression that might include register names.

        Registers names will be substituted with their current value before
        proceeding to evaluate the expression.

        Args:
            expr: an expression to evaluate

        Returns:
            final evaluation result

        Raises:
            KeyError: if `expr` contains an unrecognized register name
            ValueError: if `expr` contains disallowed tokens
            SyntaxError: if `expr` contains a broken arithmetic syntax
        """

        try:
            # look for registers names  and replace them with their actual values
            expr = self.sub_reg_values(expr)

        # expr contains an unrecognized register name
        except KeyError as ex:
            raise KeyError(f'unrecognized register name: {ex.args[0]}') from ex

        try:
            # expr should contain only values and aithmetic tokens by now; attempt to evaluate it
            res = safe_arith(expr)

        # expr contains a disallowed token
        except ValueError as ex:
            raise ValueError('only integers, hexadecimals, octals, arithmetic and bitwise operators are allowed') from ex

        # arithmetic syntax is broken
        except SyntaxError as ex:
            raise SyntaxError('error evaluating arithmetic expression') from ex

        return res

    def handle_set(self, line: str) -> Tuple[str, int]:
        """
        set register value of current context
        """
        # set $a = b

        m = re.match(r'\s*\$(?P<reg>\w+)\s*=\s*(?P<expr>.+)', line)

        if m is None:
            raise SyntaxError('illegal command syntax')

        if not m['reg']:
            raise KeyError('error parsing input: invalid lhand expression')

        if not m['expr']:
            raise SyntaxError('error parsing input: invalid rhand expression')

        reg = self.unalias(m['reg'])
        expr = self.resolve_expr(m['expr'])

        self.write_reg(reg, expr)

        return (reg, expr)

    def handle_i(self, addr: int, count: int) -> List[InsnLike]:
        result = []

        for _ in range(count):
            insn = self.disasm(addr)
            addr += insn.size

            result.append(insn)

        return result

    def handle_examine(self, line: str) -> None:
        # examples:
        #   x/xw address
        #   x/4xw $esp
        #   x/4xg $rsp
        #   x/i $eip - 0x10
        #   x $sp
        #   x $sp + 0xc

        m = re.match(r'(?:/(?P<n>\d+)?(?P<f>[oxdutfacis])?(?P<u>[bhwg])?)?\s*(?P<target>.+)?', line)

        # there should be always a match, at least for target, but let's be on the safe side
        if m is None:
            raise ValueError('unexpected examine command syntax')

        n = m['n'] or self.x_defaults['n']
        f = m['f'] or self.x_defaults['f']
        u = m['u'] or self.x_defaults['u']

        target = m['target']

        # if target was specified, determine its value. otherwise use the current address
        target = self.resolve_expr(target) if target else self.cur_addr

        n = int(n)

        if f == r'i':
            for insn in self.handle_i(target, n):
                print(f"{insn.address:#010x}: {insn.mnemonic:10s} {insn.op_str}")

        # handle read c-style string
        elif f == r's':
            s = self.try_read_string(target)

            if s is None:
                raise ValueError(f'error reading c-style string at {target:#010x}')

            print(f"{target:#010x}: {s}")

        else:
            def __to_size(u: str) -> int:
                """Convert a gdb unit name to its corresponding size in bytes.
                """

                sizes = {
                    'b': 1,  # byte
                    'h': 2,  # halfword
                    'w': 4,  # word
                    'g': 8   # giant
                }

                # assume u is in sizes
                return sizes[u]

            def __to_py_spec(f: str, size: int) -> Tuple[str, str, str]:
                """Convert a gdb format specifier to its corresponding python format,
                prefix and padding specifiers.
                """

                specs = {
                    'o': ('o', '0',  ''),              # octal
                    'x': ('x', '0x', f'0{size * 2}'),  # hex
                    'd': ('d', '',   ''),              # decimal
                    'u': ('u', '',   ''),              # unsigned decimal
                    't': ('b', '',   f'0{size * 8}'),  # binary
                    'f': ('f', '',   ''),              # float
                    'a': ('x', '0x', f'0{size * 2}'),  # address
                    'c': ('c', '',   ''),              # char
                }

                # assume f is in specs
                return specs[f]

            size = __to_size(u)
            pyfmt, prefix, pad = __to_py_spec(f, size)
            values = [self.try_read_pointer(target + (i * size), size) for i in range(n)]

            ipr = 4  # number of items to display per row

            for i in range(0, len(values), ipr):
                vset = values[i:i + ipr]

                print(f'{target + i * size:#10x}:', end='\t')

                for v in vset:
                    print('?' if v is None else f'{prefix}{v:{pad}{pyfmt}}', end='\t')

                print()
