#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import inspect
import os
from typing import Any, MutableMapping, Union

from .path import QlOsPath
from .filestruct import ql_file

# All mapped objects should inherit this class.
# Note this object is compatible with ql_file.
# Q: Why not derive from ql_file directly?
# A: ql_file assumes that it holds a path with a corresponding fd, but
#    a QlFsMappedObject doesn't have to be associated with a path or fd
#    and thus the default implementation may cause unexpected behaviors.
#    Simply let it crash if the method is not implemented.
#
#    A quick way to create a QlFsMappedObject is `ql_file.open` or `open`.
class QlFsMappedObject:
    def __init__(self):
        pass
    
    def read(self, expected_len):
        raise NotImplementedError("QlFsMappedObject method not implemented: read")
    
    def write(self, buffer):
        raise NotImplementedError("QlFsMappedObject method not implemented: write")
    
    def fileno(self):
        raise NotImplementedError("QlFsMappedObject method not implemented: fileno")
    
    def lseek(self, lseek_offset, lseek_origin):
        raise NotImplementedError("QlFsMappedObject method not implemented: lseek")
    
    def close(self):
        raise NotImplementedError("QlFsMappedObject method not implemented: close")
    
    def fstat(self):
        raise NotImplementedError("QlFsMappedObject method not implemented: fstat")
    
    def ioctl(self, ioctl_cmd, ioctl_arg):
        raise NotImplementedError("QlFsMappedObject method not implemented: ioctl")

    def tell(self):
        raise NotImplementedError("QlFsMappedObject method not implemented: tell")
    
    def dup(self):
        raise NotImplementedError("QlFsMappedObject method not implemented: dup")
    
    def readline(self, end = b'\n'):
        raise NotImplementedError("QlFsMappedObject method not implemented: readline")

    @property
    def name(self):
        raise NotImplementedError("QlFsMappedObject property not implemented: name")

class QlFsMapper:

    def __init__(self, path: QlOsPath):
        self._mapping: MutableMapping[str, Any] = {}
        self.path = path

    def _open_mapping_ql_file(self, ql_path: str, openflags: int, openmode: int):
        real_dest = self._mapping[ql_path]

        if isinstance(real_dest, str):
            obj = ql_file.open(real_dest, openflags, openmode)

        elif inspect.isclass(real_dest):
            obj = real_dest()

        else:
            obj = real_dest

        return obj

    def _open_mapping(self, ql_path: str, openmode: str):
        real_dest = self._mapping[ql_path]

        if isinstance(real_dest, str):
            obj = open(real_dest, openmode)

        elif inspect.isclass(real_dest):
            obj = real_dest()

        else:
            obj = real_dest

        return obj

    def has_mapping(self, fm: str) -> bool:
        return fm in self._mapping

    def mapping_count(self) -> int:
        return len(self._mapping)

    def open_ql_file(self, path: str, openflags: int, openmode: int):
        if self.has_mapping(path):
            return self._open_mapping_ql_file(path, openflags, openmode)

        real_path = self.path.transform_to_real_path(path)
        return ql_file.open(real_path, openflags, openmode)

    def open(self, path: str, openmode: str):
        if self.has_mapping(path):
            return self._open_mapping(path, openmode)

        real_path = self.path.transform_to_real_path(path)
        return open(real_path, openmode)

    def _parse_path(self, p: Union[os.PathLike, str]) -> str:
        fspath = getattr(p, '__fspath__', None)

        # p is an `os.PathLike` object
        if fspath is not None:
            p = fspath()

            if isinstance(p, bytes): # os.PathLike.__fspath__ may return bytes.
                p = p.decode("utf-8")

        return p

    def add_fs_mapping(self, ql_path: Union[os.PathLike, str], real_dest: Any) -> None:
        """Map an object to Qiling emulated file system.

        Args:
            ql_path: Emulated path which should be convertable to a string or a hashable object. e.g. pathlib.Path
            real_dest: Mapped object, can be a string, an object or a class.
                string: mapped path in the host machine, e.g. '/dev/urandom' -> '/dev/urandom'
                object: mapped object, will be returned each time the emulated path has been opened
                class:  mapped class, will be used to create a new instance each time the emulated path has been opened
        """

        ql_path = self._parse_path(ql_path)
        real_dest = self._parse_path(real_dest)

        self._mapping[ql_path] = real_dest
