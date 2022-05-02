#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, unittest
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath

sys.path.append('..')
from qiling.const import QL_OS
from qiling.os.path import QlOsPath

is_nt_host = PurePath() == PureWindowsPath()
is_posix_host = PurePath() == PurePosixPath()

def realpath(path: PurePath) -> Path:
    return Path(path).resolve()

def nt_to_native(rootfs: str, cwd: str, path: str) -> str:
    p = QlOsPath(rootfs, cwd, QL_OS.WINDOWS)

    return p.virtual_to_host_path(path)

def posix_to_native(rootfs: str, cwd: str, path: str) -> str:
    p = QlOsPath(rootfs, cwd, QL_OS.LINUX)

    return p.virtual_to_host_path(path)


class TestPathUtils(unittest.TestCase):
    def test_convert_nt_to_posix(self):
        # test only on a POSIX host
        if not is_posix_host:
            self.skipTest('POSIX host only')

        rootfs = PurePosixPath(r'../examples/rootfs/x86_windows')

        expected = str(realpath(rootfs) / 'test')

        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\.\\PhysicalDrive0\\test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\.\\PhysicalDrive0\\..\\test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\.\\PhysicalDrive0\\..\\..\\test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\.\\PhysicalDrive0\\..\\xxxx\\..\\test'))

        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\hostname\\share\\test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\hostname\\share\\..\\test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\hostname\\share\\..\\..\\test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\hostname\\share\\..\\xxxx\\..\\test'))

        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\.\\BootPartition\\test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\.\\BootPartition\\..\\test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\.\\BootPartition\\..\\..\\test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\.\\BootPartition\\..\\xxxx\\..\\test'))

        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', 'C:\\test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', 'C:\\..\\test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', 'C:\\..\\..\\test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', 'C:\\..\\xxxx\\..\\test'))

        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\..\\test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\..\\..\\test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\..\\xxxx\\..\\test'))

        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', 'test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '..\\test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '..\\..\\test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '..\\xxxx\\..\\test'))

        expected = str(realpath(rootfs) / 'Windows' / 'test')

        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\Windows', 'test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\Windows\\System32', '..\\test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\Windows\\System32\\drivers', '..\\..\\test'))
        self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\Windows\\System32', '..\\xxxx\\..\\test'))

    def test_convert_posix_to_nt(self):
        # test only on a Windows host
        if not is_nt_host:
            self.skipTest('NT host only')

        rootfs = PureWindowsPath(r'../examples/rootfs/x86_linux')

        expected = str(realpath(rootfs) / 'test')

        self.assertEqual(expected, posix_to_native(str(rootfs), '/', '/test'))
        self.assertEqual(expected, posix_to_native(str(rootfs), '/', '/../test'))
        self.assertEqual(expected, posix_to_native(str(rootfs), '/', '/../../test'))
        self.assertEqual(expected, posix_to_native(str(rootfs), '/', '/../xxxx/../test'))

        self.assertEqual(expected, posix_to_native(str(rootfs), '/', 'test'))
        self.assertEqual(expected, posix_to_native(str(rootfs), '/', '../test'))
        self.assertEqual(expected, posix_to_native(str(rootfs), '/', '../../test'))
        self.assertEqual(expected, posix_to_native(str(rootfs), '/', '../xxxx/../test'))

        expected = str(realpath(rootfs) / 'proc' / 'test')

        self.assertEqual(expected, posix_to_native(str(rootfs), '/proc', 'test'))
        self.assertEqual(expected, posix_to_native(str(rootfs), '/proc/sys', '../test'))
        self.assertEqual(expected, posix_to_native(str(rootfs), '/proc/sys/net', '../../test'))
        self.assertEqual(expected, posix_to_native(str(rootfs), '/proc/sys', '../xxxx/../test'))

    def test_convert_for_native_os(self):

        if is_nt_host:
            rootfs = PureWindowsPath(r'../examples/rootfs/x86_windows')

            expected = str(realpath(rootfs) / 'test')

            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\.\\PhysicalDrive0\\test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\.\\PhysicalDrive0\\..\\test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\.\\PhysicalDrive0\\..\\..\\test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\.\\PhysicalDrive0\\..\\xxxx\\..\\test'))

            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\hostname\\share\\test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\hostname\\share\\..\\test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\hostname\\share\\..\\..\\test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\hostname\\share\\..\\xxxx\\..\\test'))

            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\.\\BootPartition\\test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\.\\BootPartition\\..\\test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\.\\BootPartition\\..\\..\\test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\\\.\\BootPartition\\..\\xxxx\\..\\test'))

            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', 'C:\\test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', 'C:\\..\\test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', 'C:\\..\\..\\test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', 'C:\\..\\xxxx\\..\\test'))

            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\..\\test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\..\\..\\test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '\\..\\xxxx\\..\\test'))

            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', 'test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '..\\test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '..\\..\\test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\', '..\\xxxx\\..\\test'))

            expected = str(realpath(rootfs) / 'Windows' / 'test')

            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\Windows', 'test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\Windows\\System32', '..\\test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\Windows\\System32\\drivers', '..\\..\\test'))
            self.assertEqual(expected, nt_to_native(str(rootfs), 'C:\\Windows\\System32', '..\\xxxx\\..\\test'))

        elif is_posix_host:
            rootfs = PurePosixPath(r'../examples/rootfs/x86_linux')

            expected = str(realpath(rootfs) / 'test')

            self.assertEqual(expected, posix_to_native(str(rootfs), '/', '/test'))
            self.assertEqual(expected, posix_to_native(str(rootfs), '/', '/../test'))
            self.assertEqual(expected, posix_to_native(str(rootfs), '/', '/../../test'))
            self.assertEqual(expected, posix_to_native(str(rootfs), '/', '/../xxxx/../test'))

            self.assertEqual(expected, posix_to_native(str(rootfs), '/', 'test'))
            self.assertEqual(expected, posix_to_native(str(rootfs), '/', '../test'))
            self.assertEqual(expected, posix_to_native(str(rootfs), '/', '../../test'))
            self.assertEqual(expected, posix_to_native(str(rootfs), '/', '../xxxx/../test'))

            expected = str(realpath(rootfs) / 'proc' / 'test')

            self.assertEqual(expected, posix_to_native(str(rootfs), '/proc', 'test'))
            self.assertEqual(expected, posix_to_native(str(rootfs), '/proc/sys', '../test'))
            self.assertEqual(expected, posix_to_native(str(rootfs), '/proc/sys/net', '../../test'))
            self.assertEqual(expected, posix_to_native(str(rootfs), '/proc/sys', '../xxxx/../test'))

            # test virtual symlink: absolute virtual path
            rootfs = PurePosixPath(r'../examples/rootfs/arm_linux')
            expected = str(realpath(rootfs) / 'tmp' / 'media' / 'nand' / 'symlink_test' / 'libsymlink_test.so')

            self.assertEqual(expected, posix_to_native(str(rootfs), '/', '/lib/libsymlink_test.so'))

            # test virtual symlink: relative virtual path
            rootfs = PurePosixPath(r'../examples/rootfs/arm_qnx')
            expected = str(realpath(rootfs) / 'lib' / 'libm.so.2')

            self.assertEqual(expected, posix_to_native(str(rootfs), '/', '/usr/lib/libm.so.2'))

        else:
            self.fail('unexpected host os')


if __name__ == '__main__':
    unittest.main()
