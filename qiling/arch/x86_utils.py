
from abc import abstractmethod

from qiling import Qiling
from qiling.arch.x86 import QlArchIntel
from qiling.arch.x86_const import *
from qiling.exception import QlGDTError, QlMemoryMappedError
from qiling.os.memory import QlMemoryManager

class GDTArray:
    entsize = QL_X86_GDT_ENTRY_SIZE

    def __init__(self, mem: QlMemoryManager, base: int, num_entries: int):
        self.mem = mem
        self.base = base
        self.num_entries = num_entries

    def __in_bounds(self, index: int) -> bool:
        return (0 < index < self.num_entries)

    def __getitem__(self, index: int) -> bytes:
        if not self.__in_bounds(index):
            raise QlGDTError('invalid GDT entry index')

        return bytes(self.mem.read(self.base + (index * self.entsize), self.entsize))

    def __setitem__(self, index: int, data: bytes) -> None:
        assert len(data) == self.entsize

        if not self.__in_bounds(index):
            raise QlGDTError('invalid GDT entry index')

        self.mem.write(self.base + (index * self.entsize), data)

    def get_next_free(self, start: int = None, end: int = None) -> int:
        # The Linux kernel determines whether the segment is empty by judging whether the content in the current GDT segment is 0.
        null_entry = b'\x00' * self.entsize

        # first gdt entry is always null, start from 1
        if start is None:
            start = 1

        if end is None:
            end = self.num_entries

        return next((i for i in range(start, end) if self[i] == null_entry), -1)


class GDTManager:
    def __init__(self, ql: Qiling, base = QL_X86_GDT_ADDR, limit = QL_X86_GDT_LIMIT, num_entries = 16):
        ql.log.debug(f'Mapping GDT at {base:#x} with limit {limit:#x}')

        if not ql.mem.is_available(base, limit):
            raise QlMemoryMappedError('cannot map GDT, memory location is taken')

        ql.mem.map(base, limit, info="[GDT]")

        # setup GDT by writing to GDTR
        ql.arch.regs.write(UC_X86_REG_GDTR, (0, base, limit, 0x0))

        self.array = GDTArray(ql.mem, base, num_entries)

    @staticmethod
    def make_entry(base: int, limit: int, access: int, flags: int) -> bytes:
        """Encode specified arguments into a new GDT entry.
        """

        maxbits = lambda val, nbits: val & ~((1 << nbits) - 1) == 0

        assert maxbits(base,  32)
        assert maxbits(limit, 20)
        assert maxbits(access, 8)
        assert maxbits(flags,  4)

        # base: 8 + 24 bits
        base_hi = (base >> 24) & 0xff
        base_lo = base & ((1 << 24) - 1)

        # limit: 4 + 16 bits
        limit_hi = (limit >> 16) & 0xf
        limit_lo = limit & ((1 << 16) - 1)

        entry = base_hi << 56 | flags << 52 | limit_hi << 48 | access << 40 | base_lo << 16 | limit_lo

        return entry.to_bytes(8, 'little', signed=False)

    @staticmethod
    def make_selector(idx: int, rpl: int) -> int:
        assert rpl & ~0b11 == 0

        return (idx << 3) | QL_X86_S_GDT | rpl

    def register_gdt_segment(self, index: int, seg_base: int, seg_limit: int, access: int) -> int:
        flags = QL_X86_F_PROT_32

        # is this a huge segment?
        if seg_limit > (1 << 16):
            # on 4K granularity the lower 12 bits are implicitly all set
            assert seg_limit & ((1 << 12) - 1) == 0xfff

            seg_limit >>= 12
            flags |= QL_X86_F_GRANULARITY

        # create GDT entry, then write GDT entry into GDT table
        self.array[index] = GDTManager.make_entry(seg_base, seg_limit, access, flags)

        return GDTManager.make_selector(index, (access >> 5) & 0b11)

    def get_entry(self, index: int) -> bytes:
        return self.array[index]

    def set_entry(self, index: int, data: bytes) -> None:
        self.array[index] = data

    def get_free_idx(self, start: int = None, end: int = None) -> int:
        return self.array.get_next_free(start, end)


class SegmentManager:
    def __init__(self, arch: QlArchIntel, gdtm: GDTManager):
        self.arch = arch
        self.gdtm = gdtm

    @abstractmethod
    def setup_cs_ds_ss_es(self, base: int, size: int) -> None:
        pass

    @abstractmethod
    def setup_fs(self, base: int, size: int) -> None:
        pass

    @abstractmethod
    def setup_gs(self, base: int, size: int) -> None:
        pass


class SegmentManager86(SegmentManager):
    def setup_cs_ds_ss_es(self, base: int, size: int) -> None:
        # While debugging the linux kernel segment, the cs segment was found on the third segment of gdt.
        access = QL_X86_A_PRESENT | QL_X86_A_CODE | QL_X86_A_CODE_READABLE | QL_X86_A_PRIV_3 | QL_X86_A_EXEC | QL_X86_A_DIR_CON_BIT
        selector = self.gdtm.register_gdt_segment(3, base, size - 1, access)

        self.arch.regs.cs = selector

        # TODO : The section permission here should be QL_X86_A_PRIV_3, but I do n’t know why it can only be set to QL_X86_A_PRIV_0.
        # While debugging the Linux kernel segment, I found that the three segments DS, SS, and ES all point to the same location in the GDT table. 
        # This position is the fifth segment table of GDT.
        access = QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_0 | QL_X86_A_DIR_CON_BIT
        selector = self.gdtm.register_gdt_segment(5, base, size - 1, access)

        self.arch.regs.ds = selector
        self.arch.regs.ss = selector
        self.arch.regs.es = selector

    def setup_fs(self, base: int, size: int) -> None:
        access = QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_3 | QL_X86_A_DIR_CON_BIT
        selector = self.gdtm.register_gdt_segment(14, base, size - 1, access)

        self.arch.regs.fs = selector

    def setup_gs(self, base: int, size: int) -> None:
        access = QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_3 | QL_X86_A_DIR_CON_BIT
        selector = self.gdtm.register_gdt_segment(15, base, size - 1, access)

        self.arch.regs.gs = selector


class SegmentManager64(SegmentManager):
    def setup_cs_ds_ss_es(self, base: int, size: int) -> None:
        # While debugging the linux kernel segment, the cs segment was found on the sixth segment of gdt.
        access = QL_X86_A_PRESENT | QL_X86_A_CODE | QL_X86_A_CODE_READABLE | QL_X86_A_PRIV_3 | QL_X86_A_EXEC | QL_X86_A_DIR_CON_BIT
        selector = self.gdtm.register_gdt_segment(6, base, size - 1, access)

        self.arch.regs.cs = selector

        # TODO : The section permission here should be QL_X86_A_PRIV_3, but I do n’t know why it can only be set to QL_X86_A_PRIV_0.
        # When I debug the Linux kernel, I find that only the SS is set to the fifth segment table, and the rest are not set.
        access = QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_0 | QL_X86_A_DIR_CON_BIT
        selector = self.gdtm.register_gdt_segment(5, base, size - 1, access)

        # self.arch.regs.ds = selector
        self.arch.regs.ss = selector
        # self.arch.regs.es = selector

    def setup_fs(self, base: int, size: int) -> None:
        self.arch.msr.write(IA32_FS_BASE_MSR, base)

    def setup_gs(self, base: int, size: int) -> None:
        self.arch.msr.write(IA32_GS_BASE_MSR, base)
