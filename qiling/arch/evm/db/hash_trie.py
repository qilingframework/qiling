import contextlib
from typing import (
    cast,
    Iterator,
)

from eth_hash.auto import keccak
from trie import HexaryTrie

from ..db.keymap import (
    KeyMapDB,
)


class HashTrie(KeyMapDB):
    keymap = keccak

    @contextlib.contextmanager
    def squash_changes(self) -> Iterator['HashTrie']:
        with cast(HexaryTrie, self._db).squash_changes() as memory_trie:
            yield type(self)(memory_trie)
