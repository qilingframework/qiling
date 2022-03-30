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

        self.convert_path_handler = QlPathManager.__select_convert_path_handler(ql.ostype, ql.host.os)

    @staticmethod
    def __select_convert_path_handler(emu_os: QL_OS, host_os: QL_OS):
        # emulated os and hosting platform are of the same type
        if (emu_os == host_os) or (emu_os in QL_OS_POSIX and host_os in QL_OS_POSIX):
            handler = QlPathManager.convert_for_native_os

        elif emu_os in QL_OS_POSIX and host_os == QL_OS.WINDOWS:
            handler = QlPathManager.convert_posix_to_win32

        elif emu_os == QL_OS.WINDOWS and host_os in QL_OS_POSIX:
            handler = QlPathManager.convert_win32_to_posix

        else:
            handler = QlPathManager.convert_for_native_os

        return handler

    @property
    def cwd(self) -> str:
        return self._cwd

    @cwd.setter
    def cwd(self, c: str) -> None:
        if not c.startswith('/'):
            self.ql.log.warning(f'Sanity check: path does not start with a forward slash "/"')

        self._cwd = c

    @staticmethod
    def normalize(path: PurePath) -> PurePath:
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
    def convert_win32_to_posix(rootfs: Union[str, PurePosixPath], cwd: str, path: str) -> PurePosixPath:
        _rootfs = PurePosixPath(rootfs)
        _cwd = PurePosixPath(cwd[1:])
        _path = PureWindowsPath(path)

        # Things are complicated here.
        # See https://docs.microsoft.com/zh-cn/windows/win32/fileio/naming-a-file?redirectedfrom=MSDN
        if _path.is_absolute():
            if (len(path) >= 2 and path.startswith(r'\\')) or \
                (len(path) >= 3 and path[0].isalpha() and path[1:3] == ':\\'): # \\.\PhysicalDrive0 or \\Server\Share\Directory or X:\
                # UNC path should be handled in fs mapping. If not, append it to rootfs directly.

                result = _rootfs / QlPathManager.normalize(_path)
            else:
                # code should never reach here.
                raise RuntimeError()
        else:
            if len(path) >= 3 and path[:3] == r'\\?' or path[:3] == r'\??': # \??\ or \\?\ or \Device\..
                # Similair to \\.\, it should be handled in fs mapping.

                result = _rootfs / QlPathManager.normalize(_cwd / _path.relative_to(_path.anchor).as_posix())
            else:
                # a normal relative path
                result = _rootfs / QlPathManager.normalize(_cwd / _path.as_posix())

        return result

    @staticmethod
    def convert_posix_to_win32(rootfs: Union[str, PureWindowsPath], cwd: str, path: str) -> PureWindowsPath:
        _rootfs = PureWindowsPath(rootfs)
        _cwd = PurePosixPath(cwd[1:])
        _path = PurePosixPath(path)

        if _path.is_absolute():
            return _rootfs / QlPathManager.normalize(_path)
        else:
            return _rootfs / QlPathManager.normalize(_cwd / _path)

    @staticmethod
    def convert_for_native_os(rootfs: Union[str, PurePath], cwd: str, path: str) -> PurePath:
        _rootfs = PurePath(rootfs)
        _cwd = PurePosixPath(cwd[1:])
        _path = PurePath(path)

        if _path.is_absolute():
            return _rootfs / QlPathManager.normalize(_path)
        else:
            return _rootfs / QlPathManager.normalize(_cwd / _path.as_posix())

    def convert_path(self, rootfs: str, cwd: str, path: str) -> PurePath:
        return self.convert_path_handler(rootfs, cwd, path)

    def transform_to_link_path(self, path: str) -> str:
        real_path = self.convert_path(self.ql.rootfs, self.cwd, path)

        return str(Path(real_path).absolute())

    def transform_to_real_path(self, path: str) -> str:
        # TODO: We really need a virtual file system.
        real_path = self.convert_path(self.ql.rootfs, self.cwd, path)

        if os.path.islink(real_path):
            link_path = os.readlink(real_path)

            real_path = self.convert_path(os.path.dirname(real_path), "/", link_path)

            if os.path.islink(real_path):
                real_path = self.transform_to_real_path(str(real_path))

            # resolve multilevel symbolic link
            if not os.path.exists(real_path):
                link_path = PurePath(link_path)
                path_dirs = link_path.parts

                if link_path.is_absolute():
                    path_dirs = path_dirs[1:]

                for i in range(len(path_dirs) - 1):
                    path_prefix = os.path.sep.join(path_dirs[:i+1])
                    real_path_prefix = self.transform_to_real_path(path_prefix)
                    path_remain = os.path.sep.join(path_dirs[i+1:])
                    real_path = os.path.join(real_path_prefix, path_remain)

                    if os.path.exists(real_path):
                        break

        return str(Path(real_path).absolute())

    # The `relative path` here refers to the path which is relative to the rootfs.
    def transform_to_relative_path(self, path: str) -> str:
        return str(PurePath(self.cwd) / path)
