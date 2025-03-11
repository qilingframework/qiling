
import re
from typing import TYPE_CHECKING, Optional, Sequence

from unicorn import UcError

if TYPE_CHECKING:
    from capstone import CsInsn
    from qiling import Qiling


class StateView:
    LZ_PATTERN = re.compile(r'^((?:00)+)')

    @staticmethod
    def __dim_leading_zeros(hexstr: str) -> str:
        """Dim leading zero nibble pairs in a specified hexadecimal string.

        Args:
            hexstr : hexadecimal string

        Returns: a colored version of `hexstr`
        """

        dim = '\x1b[90m'
        undim = '\x1b[39m'

        return StateView.LZ_PATTERN.sub(fr'{dim}\1{undim}', hexstr, 1)

    def __init__(self, ql: 'Qiling') -> None:
        self.ql = ql

    def get_cpu_state(self, reg_groups):
        def __format_row(row):
            for size, reg in row:
                value = self.ql.arch.regs.read(reg.strip())

                if not hasattr(value, '__len__'):
                    value = [value]

                nibbles = size * 2
                hexstr = ' '.join(self.__dim_leading_zeros(f'{v:0{nibbles}x}') for v in value)

                yield f'{reg:s} = {hexstr:{nibbles}s}'

        return [' | '.join(__format_row(row)) for row in reg_groups]

    def get_hex_dump(self, address: int, data: bytearray, num_cols: int = 16):
        # align hexdump to numbers of columns
        pre_padding = [None] * (address % num_cols)
        post_padding = [None] * ((num_cols - len(pre_padding)) % num_cols)
        chars = pre_padding + list(data) + post_padding
        address = address & ~(num_cols - 1)

        def __gen_hex_dump():
            for i in range(0, len(chars), num_cols):
                row = chars[i: i + num_cols]

                hexstr = ' '.join(f'  ' if ch is None else self.__dim_leading_zeros(f'{ch:02x}') for ch in row)
                ascstr = ''.join(f' ' if ch is None else (f'{ch:c}' if f'{ch:c}'.isprintable() else '.') for ch in row)

                yield f'{address + i:08x} : {hexstr} : {ascstr}'

        return list(__gen_hex_dump())

    def get_disasm(self, address: int, data: bytearray, max_insns: int = 8):
        disasm = tuple(self.ql.arch.disassembler.disasm(data, address))[:max_insns]

        def __format_row(insn: 'CsInsn'):
            return f'{insn.address:08x} : {insn.bytes.hex():24s} {insn.mnemonic:10s} {insn.op_str:s}'

        return [__format_row(insn) for insn in disasm]

    def get_stack_dump(self, before: int = 4, after: int = 4):
        def __read_stack_item(offset: int) -> Optional[int]:
            try:
                item = self.ql.arch.stack_read(offset)
            except UcError:
                item = None

            return item

        sp = self.ql.arch.regs.arch_sp
        asize = self.ql.arch.pointersize
        nibbles = asize * 2

        def __gen_stack_dump():
            for i in range(-after, before + 1):
                offset = i * asize
                address = sp + offset
                marker = ' <-' if offset == 0 else ''

                item = __read_stack_item(offset)
                hexstr = '(unavailable)' if item is None else self.__dim_leading_zeros(f'{item:0{nibbles}x}')

                yield f'{address:08x} (sp {offset:=+4d}) : {hexstr} {marker}'

        return list(__gen_stack_dump())

    def get_memory_map(self):
        mapinfo = self.ql.mem.get_mapinfo()

        # determine columns sizes based on the longest value for each field
        lengths = ((len(f'{ubound:#x}'), len(label)) for _, ubound, _, label, _ in mapinfo)
        grouped = tuple(zip(*lengths))

        len_addr = max(grouped[0])
        len_label = max(grouped[1])

        # pre-allocate table
        table = [''] * (len(mapinfo) + 1)

        # add title row
        table[0] = f'{"Start":{len_addr}s}   {"End":{len_addr}s}   {"Perm":5s}   {"Label":{len_label}s}   {"Image"}'

        # add table rows
        for i, (lbound, ubound, perms, label, container) in enumerate(mapinfo, 1):
            table[i] = f'{lbound:0{len_addr}x} - {ubound:0{len_addr}x}   {perms:5s}   {label:{len_label}s}   {container}'

        return table

    def __emit(self, caption: str, seq: Sequence[str]) -> None:
        if caption:
            self.ql.log.error(f'{caption}:')

        for line in seq:
            self.ql.log.error(line)

        self.ql.log.error('')

    def dump(self, reg_groups):
        pc = self.ql.arch.regs.arch_pc

        self.__emit('CPU State', self.get_cpu_state(reg_groups))
        self.__emit('Stack',     self.get_stack_dump())

        try:
            data = self.ql.mem.read(pc, size=64)
        except UcError:
            pc_info = ' (unreachable)'
        else:
            self.__emit('Hexdump',     self.get_hex_dump(pc, data))
            self.__emit('Disassembly', self.get_disasm(pc, data))

            containing_image = self.ql.loader.find_containing_image(pc)
            pc_info = f' ({containing_image.path} + {pc - containing_image.base:#x})' if containing_image else ''

        self.__emit('', [f'PC = {pc:#010x}{pc_info}'])
        self.__emit('Memory Map', self.get_memory_map())
