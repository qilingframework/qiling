#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
import unittest

from typing import Optional

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS
from qiling.os.struct import BaseStruct


class DummyInternalStruct(BaseStruct):
    _fields_ = [
        ('X', ctypes.c_uint32)
    ]

    # this is defined to let 'assertEqual' work as expected
    def __eq__(self, other) -> bool:
        return isinstance(other, DummyInternalStruct) and self.X == other.X


class DummyStruct(BaseStruct):
    _fields_ = [
        ('A', ctypes.c_uint32),
        ('B', ctypes.c_uint64),
        ('C', DummyInternalStruct),
        ('D', ctypes.c_char * 16)
    ]


# we only need context and not going to run anything anyway, so just use whatever
NOPSLED = b'\x90' * 8


class Wrapper:
    class StructTest(unittest.TestCase):
        OSTYPE: QL_OS
        ROOTFS: str

        def setUp(self) -> None:
            ql = Qiling(code=NOPSLED, rootfs=self.ROOTFS, archtype=QL_ARCH.X8664, ostype=self.OSTYPE)

            self.ptr = 0x100000
            self.mem = ql.mem

            self.expected = {
                'A': 0xdeadface,
                'B': 0x1020304050607080,
                'C': DummyInternalStruct(0x11213141),
                'D': b'Hello World!',
            }

            # create a dummy structure with expected values
            dummy = DummyStruct(**self.expected)

            # emit dummy structure to memory
            ql.mem.map(self.ptr, ql.mem.align_up(dummy.sizeof()))
            ql.mem.write(self.ptr, bytes(dummy))

        def __read_data(self, offset: int = 0, size: Optional[int] = None) -> bytearray:
            return self.mem.read(self.ptr + offset, size or DummyStruct.sizeof())

        def __write_data(self, offset: int, data: bytes) -> None:
            self.mem.write(self.ptr + offset, data)

        @staticmethod
        def __to_uint(data: bytearray) -> int:
            return int.from_bytes(data, 'little', signed=False)

        def test_load_from(self):
            dummy = DummyStruct.load_from(self.mem, self.ptr)

            self.assertEqual(self.expected['A'], dummy.A)
            self.assertEqual(self.expected['B'], dummy.B)
            self.assertEqual(self.expected['C'], dummy.C)
            self.assertEqual(self.expected['D'], dummy.D)

        def test_save_to(self):
            dummy = DummyStruct(
                A=0x0c0a0f0e,
                B=0x1828384858687888,
                C=DummyInternalStruct(0x19293949),
                D=b'Goodbye World!'
            )

            dummy.save_to(self.mem, self.ptr)

            obj_data = bytes(dummy)
            mem_data = self.__read_data()

            self.assertEqual(obj_data, mem_data)

        def test_ref_discard(self):
            data_before = self.__read_data()

            unused = []
            with DummyStruct.ref(self.mem, self.ptr) as dummy:
                print(f'B = {dummy.B:#x}')
                print(f'C = {dummy.C}')

                unused.append(dummy.A + 1337)

            data_after = self.__read_data()

            self.assertEqual(data_before, data_after)

        def test_ref_save(self):
            expected = 0x10303070

            with DummyStruct.ref(self.mem, self.ptr) as dummy:
                print(f'B = {dummy.B:#x}')
                print(f'C = {dummy.C}')

                dummy.A = expected

            data = self.__read_data(DummyStruct.offsetof('A'), 4)
            self.assertEqual(expected, Wrapper.StructTest.__to_uint(data))

        def test_ref_save_internal(self):
            expected = 0x16363676

            with DummyStruct.ref(self.mem, self.ptr) as dummy:
                dummy.C.X = expected

            data = self.__read_data(DummyStruct.offsetof('C') + DummyInternalStruct.offsetof('X'), 4)
            self.assertEqual(expected, Wrapper.StructTest.__to_uint(data))

        def test_volatile_ref(self):
            dummy = DummyStruct.volatile_ref(self.mem, self.ptr)

            expected = 0x01030307
            dummy.A = expected
            data = self.__read_data(DummyStruct.offsetof('A'), 4)
            self.assertEqual(expected, Wrapper.StructTest.__to_uint(data))

            self.assertEqual(self.expected['B'], dummy.B)
            self.assertEqual(self.expected['C'], dummy.C)

            expected = b'Volatility Test!'
            self.__write_data(DummyStruct.offsetof('D'), expected)
            self.assertEqual(expected, dummy.D)

        def test_volatile_ref_internal(self):
            dummy = DummyStruct.volatile_ref(self.mem, self.ptr)

            expected = 0x51535357
            dummy.C.X = expected
            data = self.__read_data(DummyStruct.offsetof('C') + DummyInternalStruct.offsetof('X'), 4)
            self.assertEqual(expected, Wrapper.StructTest.__to_uint(data))

    # BUG: ctype.c_wchar size differs between python for windows and linux.on windows it has the
    # size of 2 as expected (same as the 'utf-16le' encoding), where on linux the size is 4 (same
    # as the 'utf-32' encoding), which expands the size of the field and doesn't provide the
    # expected outcome.
    #
    # currently wchar is used only in windows structres, which makes it problematic to emulate
    # windows programs on top of a linux host. until we implement our own wchar which depends on
    # the emualted os rather than the hosting os, the following tests are conidered broken.

    class WCharTest(unittest.TestCase):
        WCHAR_ENC: str

        @unittest.skip('broken wchar implementation')
        def test_wchar(self):
            wchar_enc = self.WCHAR_ENC
            wchar_size = len('\x00'.encode(wchar_enc))

            field_type = ctypes.c_wchar   # TODO: replace ctypes.c_wchar with an alternate implementation
            field_data = 'A'
            self.assertEqual(len(field_data) * wchar_size, ctypes.sizeof(field_type))

            obj = field_type(field_data)
            self.assertEqual(field_data, obj.value)

            obj_bytes = bytes(obj)
            self.assertEqual(field_data.encode(wchar_enc), obj_bytes)

        @unittest.skip('broken wchar implementation')
        def test_wchar_array(self):
            wchar_enc = self.WCHAR_ENC
            wchar_size = len('\x00'.encode(wchar_enc))

            field_elems = 16
            field_type = ctypes.c_wchar * field_elems   # TODO: replace ctypes.c_wchar with an alternate implementation
            field_data = 'unicode sucks'
            self.assertEqual(field_elems * wchar_size, ctypes.sizeof(field_type))

            obj = field_type(*field_data)
            self.assertEqual(field_data, obj.value)

            obj_bytes = bytes(obj)
            self.assertEqual(field_data.ljust(field_elems, '\x00').encode(wchar_enc), obj_bytes)


class StructTestLinux(Wrapper.StructTest, Wrapper.WCharTest):
    OSTYPE = QL_OS.LINUX
    ROOTFS = r'../examples/rootfs/x8664_linux'
    WCHAR_ENC = 'utf-32le'


class StructTestWindows(Wrapper.StructTest, Wrapper.WCharTest):
    OSTYPE = QL_OS.WINDOWS
    ROOTFS = r'../examples/rootfs/x8664_windows'
    WCHAR_ENC = 'utf-16le'


if __name__ == "__main__":
    unittest.main()
