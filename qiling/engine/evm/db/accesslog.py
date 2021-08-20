from contextlib import contextmanager
import logging
from typing import (
    Iterator,
    FrozenSet,
    Set,
)

from ..abc import (
    AtomicWriteBatchAPI,
    AtomicDatabaseAPI,
    DatabaseAPI,
)
from ..db.backends.base import (
    BaseDB,
)
from ..db.atomic import (
    BaseAtomicDB,
)


class KeyAccessLoggerDB(BaseDB):
    """
    Wraps around a database, and tracks all the keys that were read since initialization.
    """

    logger = logging.getLogger("eth.db.KeyAccessLoggerDB")

    def __init__(self, wrapped_db: DatabaseAPI, log_missing_keys: bool = True) -> None:
        """
        :param log_missing_keys: True if a key is added to :attr:`keys_read` even if the
            key/value does not exist in the database.
        """
        self.wrapped_db = wrapped_db
        self._keys_read: Set[bytes] = set()
        self._log_missing_keys = log_missing_keys

    @property
    def keys_read(self) -> FrozenSet[bytes]:
        # Make a defensive copy so callers can't modify the list externally
        return frozenset(self._keys_read)

    def __getitem__(self, key: bytes) -> bytes:
        try:
            result = self.wrapped_db.__getitem__(key)
        except KeyError:
            if self._log_missing_keys:
                self._keys_read.add(key)
            raise
        else:
            self._keys_read.add(key)
            return result

    def __setitem__(self, key: bytes, value: bytes) -> None:
        self.wrapped_db[key] = value

    def __delitem__(self, key: bytes) -> None:
        del self.wrapped_db[key]

    def _exists(self, key: bytes) -> bool:
        does_exist = key in self.wrapped_db
        if does_exist or self._log_missing_keys:
            self._keys_read.add(key)
        return does_exist


class KeyAccessLoggerAtomicDB(BaseAtomicDB):
    """
    Wraps around an atomic database, and tracks all the keys that were read since initialization.
    """
    logger = logging.getLogger("eth.db.KeyAccessLoggerAtomicDB")

    def __init__(self, wrapped_db: AtomicDatabaseAPI, log_missing_keys: bool = True) -> None:
        """
        :param log_missing_keys: True if a key is added to :attr:`keys_read` even if the
            key/value does not exist in the database.
        """
        self.wrapped_db = wrapped_db
        self._keys_read: Set[bytes] = set()
        self._log_missing_keys = log_missing_keys

    @property
    def keys_read(self) -> FrozenSet[bytes]:
        # Make a defensive copy so callers can't modify the list externally
        return frozenset(self._keys_read)

    def __getitem__(self, key: bytes) -> bytes:
        try:
            result = self.wrapped_db.__getitem__(key)
        except KeyError:
            if self._log_missing_keys:
                self._keys_read.add(key)
            raise
        else:
            self._keys_read.add(key)
            return result

    def __setitem__(self, key: bytes, value: bytes) -> None:
        self.wrapped_db[key] = value

    def __delitem__(self, key: bytes) -> None:
        del self.wrapped_db[key]

    def _exists(self, key: bytes) -> bool:
        does_exist = key in self.wrapped_db
        if does_exist or self._log_missing_keys:
            self._keys_read.add(key)
        return does_exist

    @contextmanager
    def atomic_batch(self) -> Iterator[AtomicWriteBatchAPI]:
        with self.wrapped_db.atomic_batch() as readable_batch:
            yield readable_batch
