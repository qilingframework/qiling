#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, unittest
from pathlib import PurePath, PurePosixPath, PureWindowsPath

sys.path.append("..")
from qiling import Qiling
from qiling.const import QL_OS, QL_OS_POSIX, QL_VERBOSE
from qiling.os.path import QlPathManager

# define a few aliases
nt_to_posix = QlPathManager.convert_win32_to_posix
posix_to_nt = QlPathManager.convert_posix_to_win32
to_native = QlPathManager.convert_for_native_os

class TestPathUtils(unittest.TestCase):
    def test_convert_win32_to_posix(self):
        rootfs = PurePosixPath(r'../examples/rootfs/x8664_windows')

        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "\\\\.\\PhysicalDrive0\\test")))
        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "\\\\.\\PhysicalDrive0\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "\\\\.\\PhysicalDrive0\\..\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "\\\\.\\PhysicalDrive0\\..\\xxxx\\..\\test")))

        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "\\\\hostname\\share\\test")))
        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "\\\\hostname\\share\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "\\\\hostname\\share\\..\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "\\\\hostname\\share\\..\\xxxx\\..\\test")))

        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "\\\\.\\BootPartition\\test")))
        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "\\\\.\\BootPartition\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "\\\\.\\BootPartition\\..\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "\\\\.\\BootPartition\\..\\xxxx\\..\\test")))

        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "C:\\test")))
        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "C:\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "C:\\..\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "C:\\..\\xxxx\\..\\test")))

        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "\\test")))
        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "\\..\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "\\..\\xxxx\\..\\test")))

        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "test")))
        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "..\\test")))
        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "..\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(nt_to_posix(rootfs, "/", "..\\xxxx\\..\\test")))

        self.assertEqual(str(rootfs / "xxxx" / "test"), str(nt_to_posix(rootfs, "/xxxx", "test")))
        self.assertEqual(str(rootfs / "xxxx" / "test"), str(nt_to_posix(rootfs, "/xxxx/yyyy", "..\\test")))
        self.assertEqual(str(rootfs / "xxxx" / "test"), str(nt_to_posix(rootfs, "/xxxx/yyyy/zzzz", "..\\..\\test")))
        self.assertEqual(str(rootfs / "xxxx" / "test"), str(nt_to_posix(rootfs, "/xxxx/yyyy", "..\\xxxx\\..\\test")))

    def test_convert_posix_to_win32(self):
        rootfs = PureWindowsPath(r'../examples/rootfs/x8664_linux')

        self.assertEqual(str(rootfs / "test"), str(posix_to_nt(rootfs, "/", "/test")))
        self.assertEqual(str(rootfs / "test"), str(posix_to_nt(rootfs, "/", "/../test")))
        self.assertEqual(str(rootfs / "test"), str(posix_to_nt(rootfs, "/", "/../../test")))
        self.assertEqual(str(rootfs / "test"), str(posix_to_nt(rootfs, "/", "/../xxxx/../test")))

        self.assertEqual(str(rootfs / "test"), str(posix_to_nt(rootfs, "/", "test")))
        self.assertEqual(str(rootfs / "test"), str(posix_to_nt(rootfs, "/", "../test")))
        self.assertEqual(str(rootfs / "test"), str(posix_to_nt(rootfs, "/", "../../test")))
        self.assertEqual(str(rootfs / "test"), str(posix_to_nt(rootfs, "/", "../xxxx/../test")))

        self.assertEqual(str(rootfs / "xxxx" / "test"), str(posix_to_nt(rootfs, "/xxxx", "test")))
        self.assertEqual(str(rootfs / "xxxx" / "test"), str(posix_to_nt(rootfs, "/xxxx/yyyy", "../test")))
        self.assertEqual(str(rootfs / "xxxx" / "test"), str(posix_to_nt(rootfs, "/xxxx/yyyy/zzzz", "../../test")))
        self.assertEqual(str(rootfs / "xxxx" / "test"), str(posix_to_nt(rootfs, "/xxxx/yyyy", "../xxxx/../test")))

    def test_convert_for_native_os(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_hello_static"], "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)

        if ql.host.os == QL_OS.WINDOWS:
            rootfs = PurePath(r'../examples/rootfs/x8664_windows')

            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "\\\\.\\PhysicalDrive0\\test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "\\\\.\\PhysicalDrive0\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "\\\\.\\PhysicalDrive0\\..\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "\\\\.\\PhysicalDrive0\\..\\xxxx\\..\\test")))

            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "\\\\hostname\\share\\test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "\\\\hostname\\share\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "\\\\hostname\\share\\..\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "\\\\hostname\\share\\..\\xxxx\\..\\test")))

            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "\\\\.\\BootPartition\\test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "\\\\.\\BootPartition\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "\\\\.\\BootPartition\\..\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "\\\\.\\BootPartition\\..\\xxxx\\..\\test")))

            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "C:\\test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "C:\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "C:\\..\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "C:\\..\\xxxx\\..\\test")))

            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "\\test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "\\..\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "\\..\\xxxx\\..\\test")))

            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "..\\test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "..\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "..\\xxxx\\..\\test")))

            self.assertEqual(str(rootfs / "xxxx" / "test"), str(to_native(rootfs, "/xxxx", "test")))
            self.assertEqual(str(rootfs / "xxxx" / "test"), str(to_native(rootfs, "/xxxx/yyyy", "..\\test")))
            self.assertEqual(str(rootfs / "xxxx" / "test"), str(to_native(rootfs, "/xxxx/yyyy/zzzz", "..\\..\\test")))
            self.assertEqual(str(rootfs / "xxxx" / "test"), str(to_native(rootfs, "/xxxx/yyyy", "..\\xxxx\\..\\test")))

        elif ql.host.os in QL_OS_POSIX:
            rootfs = PurePath(r'../examples/rootfs/x8664_linux')

            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "/test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "/../test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "/../../test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "/../xxxx/../test")))

            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "../test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "../../test")))
            self.assertEqual(str(rootfs / "test"), str(to_native(rootfs, "/", "../xxxx/../test")))

            self.assertEqual(str(rootfs / "xxxx" / "test"), str(to_native(rootfs, "/xxxx", "test")))
            self.assertEqual(str(rootfs / "xxxx" / "test"), str(to_native(rootfs, "/xxxx/yyyy", "../test")))
            self.assertEqual(str(rootfs / "xxxx" / "test"), str(to_native(rootfs, "/xxxx/yyyy/zzzz", "../../test")))
            self.assertEqual(str(rootfs / "xxxx" / "test"), str(to_native(rootfs, "/xxxx/yyyy", "../xxxx/../test")))

        else:
            raise NotImplementedError('unexpected hosting os')

        del ql

if __name__ == "__main__":
    unittest.main()
