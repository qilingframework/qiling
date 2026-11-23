import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from qiling.const import QL_ARCH, QL_ENDIAN, QL_OS
from qiling.loader.elf import AUXV, QlLoaderELF


class _Segment:
    def __getitem__(self, name):
        return {
            'p_vaddr': 0x1000,
            'p_memsz': 0x100,
            'p_filesz': 4,
            'p_flags': 5,
        }[name]

    @staticmethod
    def data():
        return b'\x13\x00\x00\x00'


class _ELF:
    def __getitem__(self, name):
        return {
            'e_entry': 0x1000,
            'e_phoff': 0x40,
            'e_phentsize': 56,
            'e_phnum': 1,
        }[name]

    def iter_segments(self, type=None):
        return iter([_Segment()] if type == 'PT_LOAD' else [])


class _Memory:
    pagesize = 4096

    def __init__(self):
        self.writes = []
        self.bytes = {}

    @staticmethod
    def align(value, alignment=4096):
        return value & ~(alignment - 1)

    @staticmethod
    def align_up(value, alignment=4096):
        return (value + alignment - 1) & ~(alignment - 1)

    def map(self, *_args):
        pass

    def write(self, address, data):
        data = bytes(data)
        self.writes.append((address, data))
        for offset, byte in enumerate(data):
            self.bytes[address + offset] = byte

    def read(self, address, count):
        return bytes(self.bytes.get(address + offset, 0) for offset in range(count))

    def cstring(self, address):
        result = bytearray()
        while self.bytes.get(address, 0):
            result.append(self.bytes[address])
            address += 1
        return bytes(result)


class ElfHwcapProjectionTests(unittest.TestCase):
    @staticmethod
    def load_auxv(arch_type, misa, os_type=QL_OS.LINUX):
        memory = _Memory()
        ql = SimpleNamespace(
            arch=SimpleNamespace(
                type=arch_type,
                bits=64,
                endian=QL_ENDIAN.EL,
                pointersize=8,
                regs=SimpleNamespace(arch_sp=0, misa=misa),
            ),
            mem=memory,
            log=SimpleNamespace(debug=lambda *_args: None, exception=lambda *_args: None),
            os=SimpleNamespace(
                type=os_type,
                uid=1000,
                euid=1000,
                gid=1000,
                egid=1000,
                entry_point=0,
                function_hook=None,
            ),
            pack=lambda value: int(value).to_bytes(8, 'little'),
            env={},
            argv=['guest'],
        )
        loader = QlLoaderELF(ql)
        loader.path = '/tmp/guest.elf'
        loader.images = []
        loader.profile = SimpleNamespace(getint=lambda _name: 0x3000000)
        with patch('qiling.loader.elf.FunctionHook', return_value=object()):
            loader.load_with_ld(_ELF(), 0x8000, 0x10000, ['guest'], {})

        stack = next(data for address, data in memory.writes if address == loader.stack_address)
        offset = loader.auxv - loader.stack_address
        entries = {}
        while True:
            tag, value = struct.unpack_from('<QQ', stack, offset)
            offset += 16
            entries[tag] = value
            if tag == AUXV.AT_NULL:
                return entries, memory

    def test_rv64_hwcap_tracks_only_verified_misa_bits(self):
        cases = ((0x20112D, 0x112D), (0x1105, 0x1105), (0x1125, 0x1105))
        for misa, expected in cases:
            with self.subTest(misa=hex(misa)):
                entries, _memory = self.load_auxv(QL_ARCH.RISCV64, misa)
                self.assertEqual(entries[AUXV.AT_HWCAP], expected)

    def test_rv64_linux_hwcap_projection_does_not_change_other_os(self):
        entries, _memory = self.load_auxv(QL_ARCH.RISCV64, 0x20112D, QL_OS.FREEBSD)
        self.assertEqual(entries[AUXV.AT_HWCAP], 0)


if __name__ == '__main__':
    unittest.main()
