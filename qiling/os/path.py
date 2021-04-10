#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Any, Mapping
import ctypes, os, uuid

from pathlib import Path, PurePosixPath, PureWindowsPath, PosixPath, WindowsPath
from unicorn import UcError

from qiling import Qiling
from qiling.os.windows.wdk_const import *
from qiling.os.windows.structs import *
from qiling.utils import verify_ret

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
    def cwd(self):
        return self._cwd
    
    @cwd.setter
    def cwd(self, c):
        if c[0] != "/":
            self.ql.log.warning(f"Sanity check: cur_path doesn't start with a /!")
        self._cwd = c

    @staticmethod
    def normalize(path):
        if type(path) is PurePosixPath:
            normalized_path = PurePosixPath()
        elif type(path) is PureWindowsPath:
            normalized_path = PureWindowsPath()
        elif type(path) is PosixPath:
            normalized_path = PosixPath()
        elif type(path) is WindowsPath:
            normalized_path = WindowsPath()

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
    def convert_win32_to_posix(rootfs, cwd, path):
        # rootfs is a concrete path.
        rootfs = Path(rootfs)
        # cwd and path are pure paths
        cwd = PurePosixPath(cwd[1:])

        result = None
        # Things are complicated here.
        # See https://docs.microsoft.com/zh-cn/windows/win32/fileio/naming-a-file?redirectedfrom=MSDN
        if PureWindowsPath(path).is_absolute():
            if (len(path) >= 2 and path[0] == '\\' and path[1] == '\\') or \
                (len(path) >= 3 and path[0].isalpha() and path[2] == '\\'): # \\.\PhysicalDrive0 or \\Server\Share\Directory or X:\
                # UNC path should be handled in fs mapping. If not, append it to rootfs directly.
                pw = PureWindowsPath(path)
                result = rootfs / QlPathManager.normalize(pw)
            else:
                # code should never reach here.
                result = rootfs / QlPathManager.normalize(path)
        else:
            if len(path) >= 3 and path[:3] == r'\\?' or path[:3] == r'\??': # \??\ or \\?\ or \Device\..
                # Similair to \\.\, it should be handled in fs mapping.
                pw = PureWindowsPath(path)
                result = rootfs / QlPathManager.normalize(cwd / pw.relative_to(pw.anchor).as_posix())
            else:
                # a normal relative path
                result = rootfs / QlPathManager.normalize(cwd / PureWindowsPath(path).as_posix())
        return result

    @staticmethod
    def convert_posix_to_win32(rootfs, cwd, path):
        # rootfs is a concrete path.
        rootfs = Path(rootfs)
        # cwd and path are pure paths
        cwd = PurePosixPath(cwd[1:])
        path = PurePosixPath(path)
        if path.is_absolute():
            return rootfs / QlPathManager.normalize(path)
        else:
            return rootfs / QlPathManager.normalize(cwd / path)

    @staticmethod
    def convert_for_native_os(rootfs, cwd, path):
        rootfs = Path(rootfs)
        cwd = PurePosixPath(cwd[1:])
        path = Path(path)
        if path.is_absolute():
            return rootfs / QlPathManager.normalize(path)
        else:
            return rootfs / QlPathManager.normalize(cwd / path.as_posix())

    def convert_path(self, rootfs, cwd, path):
        if  (self.ql.ostype == self.ql.platform ) \
            or (self.ql.ostype in [QL_OS.LINUX, QL_OS.MACOS] and self.ql.platform in [QL_OS.LINUX, QL_OS.MACOS]):
            return QlPathManager.convert_for_native_os(rootfs, cwd, path)
        elif self.ql.ostype in [QL_OS.LINUX, QL_OS.MACOS] and self.ql.platform == QL_OS.WINDOWS:
            return QlPathManager.convert_posix_to_win32(rootfs, cwd, path)
        elif self.ql.ostype == QL_OS.WINDOWS and self.ql.platform in [QL_OS.LINUX, QL_OS.MACOS]:
            return QlPathManager.convert_win32_to_posix(rootfs, cwd, path)
        else:
            # Fallback
            return QlPathManager.convert_for_native_os(rootfs, cwd, path)
    
    def transform_to_link_path(self, path):
        rootfs = self.ql.rootfs
        real_path  = self.convert_path(rootfs, self.cwd, path)

        return str(real_path.absolute())

    def transform_to_real_path(self, path):
        from types import FunctionType

        rootfs = self.ql.rootfs
        real_path = self.convert_path(rootfs, self.cwd, path)
        
        if os.path.islink(real_path):
            link_path = Path(os.readlink(real_path))
            if not link_path.is_absolute():
                real_path = Path(os.path.join(os.path.dirname(real_path), link_path))

            # resolve multilevel symbolic link
            if not os.path.exists(real_path):
                path_dirs = link_path.parts
                if link_path.is_absolute():
                    path_dirs = path_dirs[1:]

                for i in range(0, len(path_dirs)-1):
                    path_prefix = os.path.sep.join(path_dirs[:i+1])
                    real_path_prefix = self.transform_to_real_path(path_prefix)
                    path_remain = os.path.sep.join(path_dirs[i+1:])
                    real_path = Path(os.path.join(real_path_prefix, path_remain))
                    if os.path.exists(real_path):
                        break
            
        return str(real_path.absolute())

    # The `relative path` here refers to the path which is relative to the rootfs.
    def transform_to_relative_path(self, path):
        return str(Path(self.cwd) / path)
