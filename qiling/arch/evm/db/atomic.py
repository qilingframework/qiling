from contextlib import contextmanager
import logging
from typing import (
    Iterator,
)

from eth_utils import (
    ValidationError,
)

from ..abc import (
    AtomicWriteBatchAPI,
    DatabaseAPI,
)

from ..db.diff import (
    DBDiff,
    DBDiffTracker,
    DiffMissingError,
)
from ..db.backends.base import BaseAtomicDB, BaseDB
from ..db.backends.memory import MemoryDB


class AtomicDB(BaseAtomicDB):
    logger = logging.getLogger("eth.db.AtomicDB")

    wrapped_db: DatabaseAPI = None
    _track_diff: DBDiffTracker = None

    def __init__(self, wrapped_db: DatabaseAPI = None) -> None:
        if wrapped_db is None:
            self.wrapped_db = MemoryDB()
        else:
            self.wrapped_db = wrapped_db

    def __getitem__(self, key: bytes) -> bytes:
        return self.wrapped_db[key]

    def __setitem__(self, key: bytes, value: bytes) -> None:
        self.wrapped_db[key] = value

    def __delitem__(self, key: bytes) -> None:
        del self.wrapped_db[key]

    def _exists(self, key: bytes) -> bool:
        return key in self.wrapped_db

    @contextmanager
    def atomic_batch(self) -> Iterator[AtomicWriteBatchAPI]:
        with AtomicDBWriteBatch._commit_unless_raises(self) as readable_batch:
            yield readable_batch


class AtomicDBWriteBatch(BaseDB, AtomicWriteBatchAPI):
    """
    This is returned by a BaseAtomicDB during an atomic_batch, to provide a temporary view
    of the database, before commit.
    """
    logger = logging.getLogger("eth.db.AtomicDBWriteBatch")

    _write_target_db: DatabaseAPI = None
    _track_diff: DBDiffTracker = None

    def __init__(self, write_target_db: DatabaseAPI) -> None:
        self._write_target_db = write_target_db
        self._track_diff = DBDiffTracker()

    def __getitem__(self, key: bytes) -> bytes:
        if self._track_diff is None:
            raise ValidationError("Cannot get data from a write batch, out of context")

        try:
            value = self._track_diff[key]
        except DiffMissingError as missing:
            if missing.is_deleted:
                raise KeyError(key)
            else:
                return self._write_target_db[key]
        else:
            return value

    def __setitem__(self, key: bytes, value: bytes) -> None:
        if self._track_diff is None:
            raise ValidationError("Cannot set data from a write batch, out of context")

        self._track_diff[key] = value

    def __delitem__(self, key: bytes) -> None:
        if self._track_diff is None:
            raise ValidationError("Cannot delete data from a write batch, out of context")

        if key not in self:
            raise KeyError(key)
        del self._track_diff[key]

    def _diff(self) -> DBDiff:
        return self._track_diff.diff()

    def _commit(self) -> None:
        self._diff().apply_to(self._write_target_db, apply_deletes=True)

    def _exists(self, key: bytes) -> bool:
        if self._track_diff is None:
            raise ValidationError("Cannot test data existance from a write batch, out of context")

        try:
            self[key]
        except KeyError:
            return False
        else:
            return True

    @classmethod
    @contextmanager
    def _commit_unless_raises(cls, write_target_db: DatabaseAPI) -> Iterator[AtomicWriteBatchAPI]:
        """
        Commit all writes inside the context, unless an exception was raised.

        Although this is technically an external API, it (and this whole class) is only intended
        to be used by AtomicDB.
        """
        readable_write_batch: AtomicDBWriteBatch = cls(write_target_db)
        try:
            yield readable_write_batch
        except Exception:
            cls.logger.exception(
                "Unexpected error in atomic db write, dropped partial writes: %r",
                readable_write_batch._diff(),
            )
            raise
        else:
            readable_write_batch._commit()
        finally:
            # force a shutdown of this batch, to prevent out-of-context usage
            readable_write_batch._track_diff = None
            readable_write_batch._write_target_db = None
