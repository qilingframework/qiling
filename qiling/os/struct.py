from __future__ import annotations

import ctypes
import functools
import sys

from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Type, Optional

from qiling.const import QL_ENDIAN

if TYPE_CHECKING:
    from qiling.os.memory import QlMemoryManager


# the cache decorator is needed here not only for performance purposes, but also to make sure
# the *same* class type is returned every time rather than creating another one with the same
# name and properties.
#
# TODO: work around the missing functools.cache decorator on Python versions earlier than 3.9
cache = functools.cache if sys.version_info >= (3, 9) else functools.lru_cache(maxsize=2)


class BaseStruct(ctypes.Structure):
    """An abstract class for C structures.

    Refrain from subclassing it directly as it does not take the emulated architecture
    properties into account. Subclass `BaseStructEL` or `BaseStructEB` instead.
    """

    def save_to(self, mem: QlMemoryManager, address: int) -> None:
        """Store structure contents to a specified memory address.

        Args:
            mem: memory manager instance
            address: destination address
        """

        data = bytes(self)

        mem.write(address, data)

    @classmethod
    def load_from(cls, mem: QlMemoryManager, address: int):
        """Construct and populate a structure from saved contents.

        Args:
            mem: memory manager instance
            address: source address

        Returns: populated structure instance
        """

        data = mem.read(address, cls.sizeof())

        return cls.from_buffer(data)

    @classmethod
    def volatile_ref(cls, mem: QlMemoryManager, address: int):
        """Refer to a memory location as a volatile structure variable.

        Args:
            mem : memory manager instance
            address : bind address

        Example:
            >>> class Point(BaseStruct):
            ...     _fields_ = [
            ...         ('x', ctypes.c_uint32),
            ...         ('y', ctypes.c_uint32)
            ...     ]

            >>> # bind a volatile Point structure to address `ptr`
            >>> p = Point.volatile_ref(ql.mem, ptr)
            ... if p.x > 10:    # x value is read directly from memory
            ...     p.x = 10    # x value is written directly to memory
            ... # y value in memory remains unchanged
            >>>
        """

        # map all structure field names to their types
        _fields = dict((fname, ftype) for fname, ftype, *_ in cls._fields_)

        class VolatileStructRef(cls):
            """Turn a BaseStruct subclass into a volatile structure.

            Field values are never cached: when retrieving a field's value, its value
            is read from memory and when setting a field's value, its value is flushed
            to memory.

            This is useful to make sure a structure's fields are alway synced with memory.
            """

            def __getattribute__(self, name: str) -> Any:
                # accessing a structure field?
                if name in _fields:
                    field = cls.__dict__[name]
                    ftype = _fields[name]

                    if issubclass(ftype, BaseStruct):
                        fvalue = ftype.volatile_ref(mem, address + field.offset)

                    else:
                        # load field's bytes from memory and tranform them into a value
                        data = mem.read(address + field.offset, field.size)
                        fvalue = ftype.from_buffer(data)

                        if hasattr(fvalue, 'value'):
                            fvalue = fvalue.value

                    # set the value to the structure in order to maintain consistency with ctypes.Structure
                    super().__setattr__(name, fvalue)
                    return fvalue

                # return attribute value
                return super().__getattribute__(name)

            def __setattr__(self, name: str, value: Any) -> None:
                # accessing a structure field?
                if name in _fields:
                    field = cls.__dict__[name]
                    ftype = _fields[name]

                    # transform value into field bytes and write them to memory
                    fvalue = ftype(*value) if hasattr(ftype, '_length_') else ftype(value)
                    data = bytes(fvalue)

                    mem.write(address + field.offset, data)

                    # proceed to set the value to the structure in order to maintain consistency with ctypes.Structure

                # set attribute value
                super().__setattr__(name, value)

        return VolatileStructRef()

    @classmethod
    @contextmanager
    def ref(cls, mem: QlMemoryManager, address: int):
        """A structure context manager to facilitate updating structure contents.

        On context enter, a structure is created and populated from the specified memory
        address. All changes to structure content are written back to memory on context
        exit. If the structure content has not changed, no memory writes occur.

        Args:
            mem : memory manager instance
            address : bind address

        Example:
            >>> class Point(BaseStruct):
            ...     _fields_ = [
            ...         ('x', ctypes.c_uint32),
            ...         ('y', ctypes.c_uint32)
            ...     ]

            >>> # bind a Point structure to address `ptr`
            >>> with Point.ref(ql.mem, ptr) as p:
            ...     p.x = 10
            ...     p.y = 20
            >>> # p data has changed and will be written back to `ptr`

            >>> # bind a Point structure to address `ptr`
            >>> with Point.ref(ql.mem, ptr) as p:
            ...     print(f'saved coordinates: {p.x}, {p.y}')
            >>> # p data has not changed and nothing will be written back
        """

        instance = cls.load_from(mem, address)
        orig_data = hash(bytes(instance))

        try:
            yield instance
        finally:
            curr_data = hash(bytes(instance))

            if curr_data != orig_data:
                instance.save_to(mem, address)

    @classmethod
    def sizeof(cls) -> int:
        """Get structure size in bytes.
        """

        return ctypes.sizeof(cls)

    @classmethod
    def offsetof(cls, fname: str) -> int:
        """Get field offset within the structure.

        Args:
            fname: field name

        Returns: field offset in bytes
        Raises: `AttributeError` if the specified field does not exist
        """

        return getattr(cls, fname).offset

    @classmethod
    def memberat(cls, offset: int) -> Optional[str]:
        """Get the member name at a given offset.

        Args:
            offset: field offset within the structure

        Returns: field name, or None if no field starts at the specified offset
        """

        return next((fname for fname, *_ in cls._fields_ if cls.offsetof(fname) == offset), None)


class BaseStructEL(BaseStruct, ctypes.LittleEndianStructure):
    """Little Endian structure base class.
    """
    pass


class BaseStructEB(BaseStruct, ctypes.BigEndianStructure):
    """Big Endian structure base class.
    """
    pass


@cache
def get_aligned_struct(archbits: int, endian: QL_ENDIAN = QL_ENDIAN.EL) -> Type[BaseStruct]:
    """Provide an aligned version of BaseStruct based on the emulated
    architecture properties.

    Args:
        archbits: required alignment in bits
    """

    Struct = {
        QL_ENDIAN.EL: BaseStructEL,
        QL_ENDIAN.EB: BaseStructEB
    }[endian]

    class AlignedStruct(Struct):
        _pack_ = archbits // 8

    return AlignedStruct


@cache
def get_aligned_union(archbits: int):
    """Provide an aligned union class based on the emulated architecture
    properties. This class does not inherit the special BaseStruct methods.

    FIXME: ctypes.Union endianess cannot be set arbitrarily, rather it depends
    on the hosting system. ctypes.LittleEndianUnion and ctypes.BigEndianUnion
    are available only starting from Python 3.11

    Args:
        archbits: required alignment in bits
    """

    class AlignedUnion(ctypes.Union):
        _pack_ = archbits // 8

    return AlignedUnion


def get_native_type(archbits: int) -> Type[ctypes._SimpleCData]:
    """Select a ctypes integer type whose size matches the emulated
    architecture native size.
    """

    __type = {
        32: ctypes.c_uint32,
        64: ctypes.c_uint64
    }

    return __type[archbits]
