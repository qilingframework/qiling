#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import pathlib, sys, unittest

sys.path.append("..")
from qiling import Qiling
from qiling.const import QL_OS, QL_VERBOSE
from qiling.os.path import QlPathManager

class TestPathUtils(unittest.TestCase):
    def test_convert_win32_to_posix(self):
        rootfs = pathlib.Path("../examples/rootfs/x8664_windows").resolve()

        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "\\\\.\\PhysicalDrive0\\test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "\\\\.\\PhysicalDrive0\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "\\\\.\\PhysicalDrive0\\..\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "\\\\.\\PhysicalDrive0\\..\\xxxx\\..\\test")))

        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "\\\\hostname\\share\\test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "\\\\hostname\\share\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "\\\\hostname\\share\\..\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "\\\\hostname\\share\\..\\xxxx\\..\\test")))

        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "\\\\.\\BootPartition\\test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "\\\\.\\BootPartition\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "\\\\.\\BootPartition\\..\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "\\\\.\\BootPartition\\..\\xxxx\\..\\test")))

        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "C:\\test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "C:\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "C:\\..\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "C:\\..\\xxxx\\..\\test")))

        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "\\test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "\\..\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "\\..\\xxxx\\..\\test")))

        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "..\\test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "..\\..\\test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/", "..\\xxxx\\..\\test")))

        self.assertEqual(str(rootfs / "xxxx" / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/xxxx", "test")))
        self.assertEqual(str(rootfs / "xxxx" / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/xxxx/yyyy", "..\\test")))
        self.assertEqual(str(rootfs / "xxxx" / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/xxxx/yyyy/zzzz", "..\\..\\test")))
        self.assertEqual(str(rootfs / "xxxx" / "test"), str(QlPathManager.convert_win32_to_posix(rootfs, "/xxxx/yyyy", "..\\xxxx\\..\\test")))

    def test_convert_posix_to_win32(self):
        rootfs = pathlib.Path("../examples/rootfs/x8664_linux").resolve()

        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_posix_to_win32(rootfs, "/", "/test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_posix_to_win32(rootfs, "/", "/../test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_posix_to_win32(rootfs, "/", "/../../test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_posix_to_win32(rootfs, "/", "/../xxxx/../test")))

        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_posix_to_win32(rootfs, "/", "test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_posix_to_win32(rootfs, "/", "../test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_posix_to_win32(rootfs, "/", "../../test")))
        self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_posix_to_win32(rootfs, "/", "../xxxx/../test")))

        self.assertEqual(str(rootfs / "xxxx" / "test"), str(QlPathManager.convert_posix_to_win32(rootfs, "/xxxx", "test")))
        self.assertEqual(str(rootfs / "xxxx" / "test"), str(QlPathManager.convert_posix_to_win32(rootfs, "/xxxx/yyyy", "../test")))
        self.assertEqual(str(rootfs / "xxxx" / "test"), str(QlPathManager.convert_posix_to_win32(rootfs, "/xxxx/yyyy/zzzz", "../../test")))
        self.assertEqual(str(rootfs / "xxxx" / "test"), str(QlPathManager.convert_posix_to_win32(rootfs, "/xxxx/yyyy", "../xxxx/../test")))

    def test_convert_for_native_os(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_hello_static"], "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)

        if ql.platform == QL_OS.WINDOWS:
            rootfs = pathlib.Path("../examples/rootfs/x8664_windows").resolve()
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "\\\\.\\PhysicalDrive0\\test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "\\\\.\\PhysicalDrive0\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "\\\\.\\PhysicalDrive0\\..\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "\\\\.\\PhysicalDrive0\\..\\xxxx\\..\\test")))

            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "\\\\hostname\\share\\test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "\\\\hostname\\share\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "\\\\hostname\\share\\..\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "\\\\hostname\\share\\..\\xxxx\\..\\test")))

            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "\\\\.\\BootPartition\\test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "\\\\.\\BootPartition\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "\\\\.\\BootPartition\\..\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "\\\\.\\BootPartition\\..\\xxxx\\..\\test")))

            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "C:\\test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "C:\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "C:\\..\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "C:\\..\\xxxx\\..\\test")))

            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "\\test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "\\..\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "\\..\\xxxx\\..\\test")))

            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "..\\test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "..\\..\\test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "..\\xxxx\\..\\test")))

            self.assertEqual(str(rootfs / "xxxx" / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/xxxx", "test")))
            self.assertEqual(str(rootfs / "xxxx" / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/xxxx/yyyy", "..\\test")))
            self.assertEqual(str(rootfs / "xxxx" / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/xxxx/yyyy/zzzz", "..\\..\\test")))
            self.assertEqual(str(rootfs / "xxxx" / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/xxxx/yyyy", "..\\xxxx\\..\\test")))
        else:
            rootfs = pathlib.Path("../examples/rootfs/x8664_linux").resolve()
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "/test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "/../test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "/../../test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "/../xxxx/../test")))

            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "../test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "../../test")))
            self.assertEqual(str(rootfs / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/", "../xxxx/../test")))

            self.assertEqual(str(rootfs / "xxxx" / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/xxxx", "test")))
            self.assertEqual(str(rootfs / "xxxx" / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/xxxx/yyyy", "../test")))
            self.assertEqual(str(rootfs / "xxxx" / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/xxxx/yyyy/zzzz", "../../test")))
            self.assertEqual(str(rootfs / "xxxx" / "test"), str(QlPathManager.convert_for_native_os(rootfs, "/xxxx/yyyy", "../xxxx/../test")))

        del ql

if __name__ == "__main__":
    unittest.main()
