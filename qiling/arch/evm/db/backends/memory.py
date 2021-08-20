from typing import (
    Dict,
    Iterator,
)

from .base import (
    BaseDB,
)


class MemoryDB(BaseDB):
    kv_store: Dict[bytes, bytes] = None

    def __init__(self, kv_store: Dict[bytes, bytes] = None) -> None:
        if kv_store is None:
            self.kv_store = {}
        else:
            self.kv_store = kv_store

    def __getitem__(self, key: bytes) -> bytes:
        return self.kv_store[key]

    def __setitem__(self, key: bytes, value: bytes) -> None:
        self.kv_store[key] = value

    def _exists(self, key: bytes) -> bool:
        return key in self.kv_store

    def __delitem__(self, key: bytes) -> None:
        del self.kv_store[key]

    def __iter__(self) -> Iterator[bytes]:
        return iter(self.kv_store)

    def __len__(self) -> int:
        return len(self.kv_store)

    def __repr__(self) -> str:
        return f"MemoryDB({self.kv_store!r})"
