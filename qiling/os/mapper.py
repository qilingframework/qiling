#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from .filestruct import ql_file
from .utils import QlOsUtils
import inspect

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
    
    def __init__(self, ql):
        self._mapping = {}
        self._ql = ql
    
    @property
    def ql(self):
        return self._ql

    def _open_mapping_ql_file(self, ql_path, openflags, openmode):
        real_dest = self._mapping[ql_path]
        if isinstance(real_dest, str):
            qlfile = ql_file.open(real_dest, openflags, openmode)
            return qlfile
        elif inspect.isclass(real_dest):
            new_instance = real_dest()
            return new_instance
        else:
            return real_dest
    
    def _open_mapping(self, ql_path, openmode):
        real_dest = self._mapping[ql_path]
        if isinstance(real_dest, str):
            f = open(real_dest, openmode)
            return f
        elif inspect.isclass(real_dest):
            new_instance = real_dest()
            return new_instance
        else:
            return real_dest

    def has_mapping(self, fm):
        return fm in self._mapping

    def mapping_count(self):
        return len(self._mapping)

    def open_ql_file(self, path, openflags, openmode):
        if self.has_mapping(path):
            self.ql.nprint(f"mapping {path}")
            return self._open_mapping_ql_file(path, openflags, openmode)
        else:
            real_path = self.ql.os.transform_to_real_path(path)
            return ql_file.open(real_path, openflags, openmode)

    def open(self, path, openmode):
        if self.has_mapping(path):
            self.ql.nprint(f"mapping {path}")
            return self._open_mapping(path, openmode)
        else:
            real_path = self.ql.os.transform_to_real_path(path)
            return open(real_path, openmode)

    def _parse_path(self, p):
        if "__fspath__" in dir(p): # p is a os.PathLike object.
            p = p.__fspath__()
            if isinstance(p, bytes): # os.PathLike.__fspath__ may return bytes.
                p = p.decode("utf-8")
        return p

    # ql_path:   Emulated path which should be convertable to a string or a hashable object. e.g. pathlib.Path
    # real_dest: Mapped object, can be a string, an object or a class.
    #            string: mapped path in the host machine, e.g. `/dev/urandom` -> `/dev/urandom`.
    #            object: mapped object, will be returned each time the emulated path has been opened.
    #            class:  mapped class, will be used to create a new instance each time the emulated path has been opened.
    def add_fs_mapping(self, ql_path, real_dest):
        ql_path = self._parse_path(ql_path)
        real_dest = self._parse_path(real_dest)
        self._mapping[ql_path] = real_dest
        