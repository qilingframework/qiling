from lru import LRU

from ..abc import DatabaseAPI
from ..db.backends.base import BaseDB


class CacheDB(BaseDB):
    """
    Set and get decoded RLP objects, where the underlying db stores
    encoded objects.
    """
    def __init__(self, db: DatabaseAPI, cache_size: int = 2048) -> None:
        self._db = db
        self._cache_size = cache_size
        self.reset_cache()

    def reset_cache(self) -> None:
        self._cached_values = LRU(self._cache_size)

    def __getitem__(self, key: bytes) -> bytes:
        if key not in self._cached_values:
            self._cached_values[key] = self._db[key]
        return self._cached_values[key]

    def __setitem__(self, key: bytes, value: bytes) -> None:
        self._cached_values[key] = value
        self._db[key] = value

    def __delitem__(self, key: bytes) -> None:
        if key in self._cached_values:
            del self._cached_values[key]
        del self._db[key]
