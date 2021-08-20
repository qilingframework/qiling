from typing import (
    Iterator,
)

from ...abc import (
    AtomicDatabaseAPI,
    DatabaseAPI,
)


class BaseDB(DatabaseAPI):
    """
    This is an abstract key/value lookup with all :class:`bytes` values,
    with some convenience methods for databases. As much as possible,
    you can use a DB as if it were a :class:`dict`.

    Notable exceptions are that you cannot iterate through all values or get the length.
    (Unless a subclass explicitly enables it).

    All subclasses must implement these methods:
    __init__, __getitem__, __setitem__, __delitem__

    Subclasses may optionally implement an _exists method
    that is type-checked for key and value.
    """
    def set(self, key: bytes, value: bytes) -> None:
        self[key] = value

    def exists(self, key: bytes) -> bool:
        return self.__contains__(key)

    def __contains__(self, key: bytes) -> bool:     # type: ignore # Breaks LSP
        if hasattr(self, '_exists'):
            # Classes which inherit this class would have `_exists` attr
            return self._exists(key)    # type: ignore
        else:
            return super().__contains__(key)

    def delete(self, key: bytes) -> None:
        try:
            del self[key]
        except KeyError:
            pass

    def __iter__(self) -> Iterator[bytes]:
        raise NotImplementedError("By default, DB classes cannot be iterated.")

    def __len__(self) -> int:
        raise NotImplementedError("By default, DB classes cannot return the total number of keys.")


class BaseAtomicDB(BaseDB, AtomicDatabaseAPI):
    """
    This is an abstract key/value lookup that permits batching of updates, such that the batch of
    changes are atomically saved. They are either all saved, or none are.

    Writes to the database are immediately saved, unless they are explicitly batched
    in a context, like this:

    ::

        atomic_db = AtomicDB()
        with atomic_db.atomic_batch() as db:
            # changes are not immediately saved to the db, inside this context
            db[key] = val

            # changes are still locally visible even though they are not yet committed to the db
            assert db[key] == val

            if some_bad_condition:
                raise Exception("something went wrong, erase all the pending changes")

            db[key2] = val2
            # when exiting the context, the values are saved either key and key2 will both be saved,
            # or neither will
    """
    pass
