#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
from os import PathLike
from typing import Any, Callable, MutableMapping, Union

from .path import QlOsPath
from .filestruct import ql_file

QlPath = Union['PathLike[str]', str, 'PathLike[bytes]', bytes]


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

    def __contains__(self, vpath: str) -> bool:
        # canonicalize the path first
        absvpath = self.path.virtual_abspath(vpath)

        return absvpath in self._mapping

    def has_mapping(self, vpath: str) -> bool:
        """Check whether a specific virtrual path has a binding.

        Args:
            vpath: virtual path name to check

        Returns: `True` if the specified virtual path has been bound, `False` otherwise.
        """

        return vpath in self

    def __len__(self) -> int:
        return len(self._mapping)

    def mapping_count(self) -> int:
        """Count of currently existing bindings.
        """

        return len(self)

    def __open_mapped(self, absvpath: str, opener: Callable, *args) -> Any:
        """Internal method user for opening an existing mapped object.

        Args:
            absvpath: absolute virtual path name
            opener: a method to use to open the target host path
            *args: arguments to the opener method
        """

        mapped = self._mapping[absvpath]

        # mapped to a file name on the host file system
        if isinstance(mapped, str):
            obj = opener(mapped, *args)

        # mapped to a class or a method
        elif callable(mapped):
            obj = mapped()

        # mapped to another kind of object
        else:
            obj = mapped

        return obj

    def __open_new(self, absvpath: str, opener: Callable, *args) -> Any:
        hpath = self.path.virtual_to_host_path(absvpath)

        if not self.path.is_safe_host_path(hpath):
            raise PermissionError(f'unsafe path: {hpath}')

        return opener(hpath, *args)

    def open_ql_file(self, vpath: str, flags: int, mode: int):
        absvpath = self.path.virtual_abspath(vpath)
        opener = self.__open_mapped if self.has_mapping(absvpath) else self.__open_new

        return opener(absvpath, ql_file.open, flags, mode)

    def open(self, vpath: str, mode: str):
        absvpath = self.path.virtual_abspath(vpath)
        opener = self.__open_mapped if self.has_mapping(absvpath) else self.__open_new

        return opener(absvpath, open, mode)

    def file_exists(self, vpath: str) -> bool:
        """Check whether a file exists on the virtual file system.

        Args:
            vpath: virtual path name to check

        Returns: `True` if the specified virtual path has an existing mapping or
        resolves to an existing file on the virtual file system. `False` otherwise.
        """

        if self.has_mapping(vpath):
            return True

        hpath = self.path.virtual_to_host_path(vpath)

        if not self.path.is_safe_host_path(hpath):
            raise PermissionError(f'unsafe path: {hpath}')

        return os.path.isfile(hpath)

    def create_empty_file(self, vpath: str) -> bool:
        if not self.file_exists(vpath):
            try:
                f = self.open(vpath, "w+")
            except OSError:
                # for some reason, we could not create an empty file.
                return False
            else:
                f.close()

        return True

    def __fspath(self, path: QlPath) -> str:
        """Similar to os.fspath, this method takes a path-like object and returns
        its string representation.
        """

        if isinstance(path, PathLike):
            path = path.__fspath__()

        if isinstance(path, str):
            return path

        elif isinstance(path, bytes):
            return path.decode('utf-8')

        raise TypeError(path)

    def add_mapping(self, vpath: QlPath, binding: Union[QlPath, QlFsMappedObject, Callable], *, force: bool = False) -> None:
        """Create a new mapping in the virtual filesystem.

        Args:
            vpath: a virtual path to bind

            binding: a target to use whenever the bound virtual path is referenced. such a target can be
            either a path on the host filesystem, an object instance or a class. the behavior of the mapping
            is determined by the bound object type:
                [*] a string: bind a path on the host filesystem (e.g. "/dev/urandom"). use with caution!
                [*] an object: bind an object instance which will be returned each time the virtual path is opened
                [*] a class: bind a class that will be instantiated each time the virtual path is opened

            force: when set to `True`, re-mapping an existing vpath becomes possible. In such case, the
            old mapping will be discarded

        Raises:
            `KeyError`: in case the specified vpath has already been mapped (default behavior).
        """

        vpath = self.__fspath(vpath)
        absvpath = self.path.virtual_abspath(vpath)

        if self.has_mapping(absvpath) and not force:
            raise KeyError(f'mapping already exists: "{absvpath}"')

        if isinstance(binding, (str, bytes, PathLike)):
            binding = self.__fspath(binding)

        self._mapping[absvpath] = binding

    def remove_mapping(self, vpath: QlPath) -> None:
        """Remove a mapping from the fs mapper.

        Args:
            vpath: bound virtual path to remove

        Raises:
            `KeyError`: in case the specified vpath has no mapping
        """

        vpath = self.__fspath(vpath)
        absvpath = self.path.virtual_abspath(vpath)

        if not self.has_mapping(absvpath):
            raise KeyError(absvpath)

        del self._mapping[absvpath]

    def rename_mapping(self, old_vpath: str, new_vpath: str) -> None:
        old_absvpath = self.path.virtual_abspath(old_vpath)

        # vpath to rename does not exist
        if not self.has_mapping(old_absvpath):
            raise KeyError(old_vpath)

        new_absvpath = self.path.virtual_abspath(new_vpath)

        # new vpath already exists
        if self.has_mapping(new_absvpath):
            raise KeyError(new_vpath)

        # avoid renaming to the same vapth
        if old_absvpath == new_absvpath:
            return

        binding = self._mapping[old_absvpath]

        # remove old mapping and add a new one instead
        self._mapping[new_absvpath] = binding
        del self._mapping[old_absvpath]
