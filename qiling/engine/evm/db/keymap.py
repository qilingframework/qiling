from abc import (
    abstractmethod,
)

from typing import (
    Any,
)

from ..abc import DatabaseAPI
from ..db.backends.base import BaseDB


class KeyMapDB(BaseDB):
    """
    Modify keys when accessing the database, according to the
    abstract keymap function set in the subclass.
    """
    def __init__(self, db: DatabaseAPI) -> None:
        self._db = db

    @staticmethod
    @abstractmethod
    def keymap(key: bytes) -> bytes:
        raise NotImplementedError

    def __getitem__(self, key: bytes) -> bytes:
        mapped_key = self.keymap(key)
        return self._db[mapped_key]

    def __setitem__(self, key: bytes, val: bytes) -> None:
        mapped_key = self.keymap(key)
        self._db[mapped_key] = val

    def __delitem__(self, key: bytes) -> None:
        mapped_key = self.keymap(key)
        del self._db[mapped_key]

    def __contains__(self, key: bytes) -> bool:     # type: ignore # Breaks LSP
        mapped_key = self.keymap(key)
        return mapped_key in self._db

    def __getattr__(self, attr: Any) -> Any:
        return getattr(self._db, attr)

    def __setattr__(self, attr: Any, val: Any) -> None:
        if attr in ('_db', 'keymap'):
            super().__setattr__(attr, val)
        else:
            setattr(self._db, attr, val)
