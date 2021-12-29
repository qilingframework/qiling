#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
from typing import Union
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath

from qiling import Qiling
from qiling.const import QL_OS, QL_OS_POSIX

# OH-MY-WIN32 !!!
# Some codes from cygwin.
#
# Basic guide:
#     We should only handle "normal" paths like "C:\Windows\System32" and "bin/a.exe" for users.
#     For UNC paths like '\\.\PHYSICALDRIVE0" and "\\Server\Share", they should be implemented 
#     by users via fs mapping interface.
class QlPathManager:
    def __init__(self, ql: Qiling, cwd: str):
        self.ql = ql
        self._cwd = cwd

    @property
    def cwd(self) -> str:
        return self._cwd

    @cwd.setter
    def cwd(self, c: str) -> None:
        if not c.startswith('/'):
            self.ql.log.warning(f'Sanity check: path does not start with a forward slash "/"')

        self._cwd = c

    @staticmethod
    def normalize(path: Union[Path, PurePath]) -> Union[Path, PurePath]:
        # expected types: PosixPath, PurePosixPath, WindowsPath, PureWindowsPath
        assert isinstance(path, (Path, PurePath)), f'did not expect {type(path).__name__!r} here'

        normalized_path = type(path)()

        # remove anchor (necessary for Windows UNC paths) and convert to relative path
        if path.is_absolute():
            path = path.relative_to(path.anchor)

        for p in path.parts:
            if p == '.':
                continue

            if p == '..':
                normalized_path = normalized_path.parent
                continue

            normalized_path /= p

        return normalized_path

    @staticmethod
    def convert_win32_to_posix(rootfs: Union[str, Path], cwd: str, path: str) -> Path:
        _rootfs = Path(rootfs)
        _cwd = PurePosixPath(cwd[1:])

        # Things are complicated here.
        # See https://docs.microsoft.com/zh-cn/windows/win32/fileio/naming-a-file?redirectedfrom=MSDN
        if PureWindowsPath(path).is_absolute():
            if (len(path) >= 2 and path.startswith(r'\\')) or \
                (len(path) >= 3 and path[0].isalpha() and path[1:3] == ':\\'): # \\.\PhysicalDrive0 or \\Server\Share\Directory or X:\
                # UNC path should be handled in fs mapping. If not, append it to rootfs directly.
                pw = PureWindowsPath(path)
                result = _rootfs / QlPathManager.normalize(pw)
            else:
                # code should never reach here.
                result = _rootfs / QlPathManager.normalize(path)
        else:
            if len(path) >= 3 and path[:3] == r'\\?' or path[:3] == r'\??': # \??\ or \\?\ or \Device\..
                # Similair to \\.\, it should be handled in fs mapping.
                pw = PureWindowsPath(path)
                result = _rootfs / QlPathManager.normalize(_cwd / pw.relative_to(pw.anchor).as_posix())
            else:
                # a normal relative path
                result = _rootfs / QlPathManager.normalize(_cwd / PureWindowsPath(path).as_posix())

        return result

    @staticmethod
    def convert_posix_to_win32(rootfs: Union[str, Path], cwd: str, path: str) -> Path:
        _rootfs = Path(rootfs)
        _cwd = PurePosixPath(cwd[1:])
        _path = PurePosixPath(path)

        if _path.is_absolute():
            return _rootfs / QlPathManager.normalize(_path)
        else:
            return _rootfs / QlPathManager.normalize(_cwd / _path)

    @staticmethod
    def convert_for_native_os(rootfs: Union[str, Path], cwd: str, path: str) -> Path:
        _rootfs = Path(rootfs)
        _cwd = PurePosixPath(cwd[1:])
        _path = Path(path)

        if _path.is_absolute():
            return _rootfs / QlPathManager.normalize(_path)
        else:
            return _rootfs / QlPathManager.normalize(_cwd / _path.as_posix())

    def convert_path(self, rootfs: Union[str, Path], cwd: str, path: str) -> Path:
        emulated_os = self.ql.ostype
        hosting_os = self.ql.platform_os

        # emulated os and hosting platform are of the same type
        if  (emulated_os == hosting_os) or (emulated_os in QL_OS_POSIX and hosting_os in QL_OS_POSIX):
            return QlPathManager.convert_for_native_os(rootfs, cwd, path)

        elif emulated_os in QL_OS_POSIX and hosting_os == QL_OS.WINDOWS:
            return QlPathManager.convert_posix_to_win32(rootfs, cwd, path)

        elif emulated_os == QL_OS.WINDOWS and hosting_os in QL_OS_POSIX:
            return QlPathManager.convert_win32_to_posix(rootfs, cwd, path)

        else:
            return QlPathManager.convert_for_native_os(rootfs, cwd, path)

    def transform_to_link_path(self, path: str) -> str:
        real_path = self.convert_path(self.ql.rootfs, self.cwd, path)

        return str(real_path.absolute())

    def transform_to_real_path(self, path: str) -> str:
        real_path = self.convert_path(self.ql.rootfs, self.cwd, path)

        if os.path.islink(real_path):
            link_path = Path(os.readlink(real_path))

            if not link_path.is_absolute():
                real_path = Path(os.path.join(os.path.dirname(real_path), link_path))

            # resolve multilevel symbolic link
            if not os.path.exists(real_path):
                path_dirs = link_path.parts

                if link_path.is_absolute():
                    path_dirs = path_dirs[1:]

                for i in range(len(path_dirs) - 1):
                    path_prefix = os.path.sep.join(path_dirs[:i+1])
                    real_path_prefix = self.transform_to_real_path(path_prefix)
                    path_remain = os.path.sep.join(path_dirs[i+1:])
                    real_path = Path(os.path.join(real_path_prefix, path_remain))

                    if os.path.exists(real_path):
                        break

        return str(real_path.absolute())

    # The `relative path` here refers to the path which is relative to the rootfs.
    def transform_to_relative_path(self, path: str) -> str:
        return str(Path(self.cwd) / path)
