from .filestruct import ql_file
from .utils import QlOsUtils

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
        if not isinstance(real_dest, str): # We have opened this mapping or it is implemented by user.
            return real_dest
        else:
            qlfile = ql_file.open(real_dest, openflags, openmode) # open the path and replace the destination now.
            self._mapping[ql_path] = qlfile
            return qlfile
    
    def _open_mapping(self, ql_path, openmode):
        real_dest = self._mapping[ql_path]
        if not isinstance(real_dest, str):
            return real_dest
        else:
            f = open(real_dest, openmode)
            self._mapping[ql_path] = f
            return f

    def has_mapping(self, fm):
        return fm in self._mapping

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

    def add_fs_mapping(self, ql_path, real_dest):
        # For os.PathLike
        # fm should be always objects which can be converted to a string.
        ql_path = str(ql_path)
        if '__fspath__' in dir(real_dest): # real_dest is a os.PathLike object.
            real_dest = real_dest.__fspath__()
            if isinstance(real_dest, bytes): # os.PathLike.__fspath__ may return bytes.
                real_dest = real_dest.decode("utf-8")
        self._mapping[ql_path] = real_dest
        