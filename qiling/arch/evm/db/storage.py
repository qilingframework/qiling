from typing import (
    FrozenSet,
    List,
    NamedTuple,
    Set,
)

from eth_hash.auto import keccak
from eth_typing import (
    Address,
    Hash32,
)
from eth_utils import (
    ValidationError,
    encode_hex,
    get_extended_debug_logger,
    int_to_big_endian,
    to_bytes,
    to_int,
)
import rlp
from trie import (
    HexaryTrie,
    exceptions as trie_exceptions,
)

from .._utils.padding import (
    pad32,
)
from ..abc import (
    AccountStorageDatabaseAPI,
    AtomicDatabaseAPI,
    DatabaseAPI,
)
from ..constants import (
    BLANK_ROOT_HASH,
)
from ..db.backends.base import (
    BaseDB,
)
from ..db.backends.memory import (
    MemoryDB,
)
from ..db.batch import (
    BatchDB,
)
from ..db.cache import (
    CacheDB,
)
from ..db.journal import (
    JournalDB,
)
from ..vm.interrupt import (
    MissingStorageTrieNode,
)
from ..typing import (
    JournalDBCheckpoint,
)


class PendingWrites(NamedTuple):
    """
    A set of variables captured just before account storage deletion.
    The variables are used to revive storage if the EVM reverts to a point
    prior to deletion.
    """
    write_trie: HexaryTrie  # The write trie at the time of deletion
    trie_nodes_batch: BatchDB  # A batch of all trie nodes written to the trie
    starting_root_hash: Hash32  # The starting root hash


class StorageLookup(BaseDB):
    """
    This lookup converts lookups of storage slot integers into the appropriate trie lookup.
    Similarly, it persists changes to the appropriate trie at write time.

    StorageLookup also tracks the state roots changed since the last persist.
    """
    logger = get_extended_debug_logger("eth.db.storage.StorageLookup")

    # The trie that is modified in-place, used to calculate storage root on-demand
    _write_trie: HexaryTrie

    # These are the new trie nodes, waiting to be committed to disk
    _trie_nodes_batch: BatchDB

    # When deleting an account, push the pending write info onto this stack.
    # This stack can get as big as the number of transactions per block: one for each delete.
    _historical_write_tries: List[PendingWrites]

    def __init__(self, db: DatabaseAPI, storage_root: Hash32, address: Address) -> None:
        self._db = db

        # Set the starting root hash, to be used for on-disk storage read lookups
        self._initialize_to_root_hash(storage_root)

        self._address = address

    def _get_write_trie(self) -> HexaryTrie:
        if self._trie_nodes_batch is None:
            self._trie_nodes_batch = BatchDB(self._db, read_through_deletes=True)

        if self._write_trie is None:
            batch_db = self._trie_nodes_batch
            self._write_trie = HexaryTrie(batch_db, root_hash=self._starting_root_hash, prune=True)

        return self._write_trie

    def _get_read_trie(self) -> HexaryTrie:
        if self._write_trie is not None:
            return self._write_trie
        else:
            # Creating "HexaryTrie" is a pretty light operation, so not a huge cost
            # to create a new one at every read, but we could
            # cache the read trie, if this becomes a bottleneck.
            return HexaryTrie(self._db, root_hash=self._starting_root_hash)

    def _decode_key(self, key: bytes) -> bytes:
        padded_slot = pad32(key)
        return keccak(padded_slot)

    def __getitem__(self, key: bytes) -> bytes:
        hashed_slot = self._decode_key(key)
        read_trie = self._get_read_trie()
        try:
            return read_trie[hashed_slot]
        except trie_exceptions.MissingTrieNode as exc:
            raise MissingStorageTrieNode(
                exc.missing_node_hash,
                self._starting_root_hash,
                exc.requested_key,
                exc.prefix,
                self._address,
            ) from exc

    def __setitem__(self, key: bytes, value: bytes) -> None:
        hashed_slot = self._decode_key(key)
        write_trie = self._get_write_trie()
        write_trie[hashed_slot] = value

    def _exists(self, key: bytes) -> bool:
        # used by BaseDB for __contains__ checks
        hashed_slot = self._decode_key(key)
        read_trie = self._get_read_trie()
        return hashed_slot in read_trie

    def __delitem__(self, key: bytes) -> None:
        hashed_slot = self._decode_key(key)
        write_trie = self._get_write_trie()
        try:
            del write_trie[hashed_slot]
        except trie_exceptions.MissingTrieNode as exc:
            raise MissingStorageTrieNode(
                exc.missing_node_hash,
                self._starting_root_hash,
                exc.requested_key,
                exc.prefix,
                self._address,
            ) from exc

    @property
    def has_changed_root(self) -> bool:
        return self._write_trie is not None

    def get_changed_root(self) -> Hash32:
        if self._write_trie is not None:
            return self._write_trie.root_hash
        else:
            raise ValidationError("Asked for changed root when no writes have been made")

    def _initialize_to_root_hash(self, root_hash: Hash32) -> None:
        self._starting_root_hash = root_hash
        self._write_trie = None
        self._trie_nodes_batch = None

        # Reset the historical writes, which can't be reverted after committing
        self._historical_write_tries = []

    def commit_to(self, db: DatabaseAPI) -> None:
        """
        Trying to commit changes when nothing has been written will raise a
        ValidationError
        """
        if self._trie_nodes_batch is None:
            raise ValidationError(
                "It is invalid to commit an account's storage if it has no pending changes. "
                "Always check storage_lookup.has_changed_root before attempting to commit. "
                f"Write tries on stack = {len(self._historical_write_tries)}; Root hash = "
                f"{encode_hex(self._starting_root_hash)}"
            )
        self._trie_nodes_batch.commit_to(db, apply_deletes=False)

        # Mark the trie as having been all written out to the database.
        # It removes the 'dirty' flag and clears out any pending writes.
        self._initialize_to_root_hash(self._write_trie.root_hash)

    def new_trie(self) -> int:
        """
        Switch to an empty trie. Save the old trie, and pending writes, in
        case of a revert.

        :return: index for reviving the previous trie
        """
        write_trie = self._get_write_trie()

        # Write the previous trie into a historical stack
        self._historical_write_tries.append(PendingWrites(
            write_trie,
            self._trie_nodes_batch,
            self._starting_root_hash,
        ))

        new_idx = len(self._historical_write_tries)
        self._starting_root_hash = BLANK_ROOT_HASH
        self._write_trie = None
        self._trie_nodes_batch = None

        return new_idx

    def rollback_trie(self, trie_index: int) -> None:
        """
        Revert back to the previous trie, using the index returned by a
        :meth:`~new_trie` call. The index returned by that call returns you
        to the trie in place *before* the call.

        :param trie_index: index for reviving the previous trie
        """

        if trie_index >= len(self._historical_write_tries):
            raise ValidationError(
                f"Trying to roll back a delete to index {trie_index}, but there are only"
                f" {len(self._historical_write_tries)} indices available."
            )

        (
            self._write_trie,
            self._trie_nodes_batch,
            self._starting_root_hash,
        ) = self._historical_write_tries[trie_index]

        # Cannot roll forward after a rollback, so remove created/ignored tries.
        # This also deletes the trie that you just reverted to. It will be re-added
        # to the stack when the next new_trie() is called.
        del self._historical_write_tries[trie_index:]


CLEAR_COUNT_KEY_NAME = b'clear-count'


class AccountStorageDB(AccountStorageDatabaseAPI):
    logger = get_extended_debug_logger("eth.db.storage.AccountStorageDB")

    def __init__(self, db: AtomicDatabaseAPI, storage_root: Hash32, address: Address) -> None:
        """
        Database entries go through several pipes, like so...

        .. code::

            db -> _storage_lookup -> _storage_cache -> _locked_changes -> _journal_storage

        db is the raw database, we can assume it hits disk when written to.
        Keys are stored as node hashes and rlp-encoded node values.

        _storage_lookup is itself a pair of databases: (BatchDB -> HexaryTrie),
        writes to storage lookup *are* immeditaely applied to a trie, generating
        the appropriate trie nodes and and root hash (via the HexaryTrie). The
        writes are *not* persisted to db, until _storage_lookup is explicitly instructed to,
        via :meth:`StorageLookup.commit_to`

        _storage_cache is a cache tied to the state root of the trie. It
        is important that this cache is checked *after* looking for
        the key in _journal_storage, because the cache is only invalidated
        after a state root change. Otherwise, you will see data since the last
        storage root was calculated.

        _locked_changes is a batch database that includes only those values that are
        un-revertable in the EVM. Currently, that means changes that completed in a
        previous transaction.

        Journaling batches writes at the _journal_storage layer, until persist is called.
        It manages all the checkpointing and rollbacks that happen during EVM execution.

        In both _storage_cache and _journal_storage, Keys are set/retrieved as the
        big_endian encoding of the slot integer, and the rlp-encoded value.
        """
        self._address = address
        self._storage_lookup = StorageLookup(db, storage_root, address)
        self._storage_cache = CacheDB(self._storage_lookup)
        self._locked_changes = JournalDB(self._storage_cache)
        self._journal_storage = JournalDB(self._locked_changes)
        self._accessed_slots: Set[int] = set()

        # Track how many times we have cleared the storage. This is journaled
        # in lockstep with other storage changes. That way, we can detect if a revert
        # causes use to revert past the previous storage deletion. The clear count is used
        # as an index to find the base trie from before the revert.
        self._clear_count = JournalDB(MemoryDB({CLEAR_COUNT_KEY_NAME: to_bytes(0)}))

    def get(self, slot: int, from_journal: bool = True) -> int:
        self._accessed_slots.add(slot)
        key = int_to_big_endian(slot)
        lookup_db = self._journal_storage if from_journal else self._locked_changes
        try:
            encoded_value = lookup_db[key]
        except MissingStorageTrieNode:
            raise
        except KeyError:
            return 0

        if encoded_value == b'':
            return 0
        else:
            return rlp.decode(encoded_value, sedes=rlp.sedes.big_endian_int)

    def set(self, slot: int, value: int) -> None:
        key = int_to_big_endian(slot)
        if value:
            self._journal_storage[key] = rlp.encode(value)
        else:
            try:
                current_val = self._journal_storage[key]
            except KeyError:
                # deleting an empty key has no effect
                return
            else:
                if current_val != b'':
                    # only try to delete the value if it's present
                    del self._journal_storage[key]

    def delete(self) -> None:
        self._journal_storage.clear()
        self._storage_cache.reset_cache()

        # Empty out the storage lookup trie (keeping history, in case of a revert)
        new_clear_count = self._storage_lookup.new_trie()

        # Look up the previous count of how many times the account has been deleted.
        # This can happen multiple times in one block, via CREATE2.
        old_clear_count = to_int(self._clear_count[CLEAR_COUNT_KEY_NAME])

        # Gut check that we have incremented correctly
        if new_clear_count != old_clear_count + 1:
            raise ValidationError(
                f"Must increase clear count by one on each delete. Instead, went from"
                f" {old_clear_count} -> {new_clear_count} in account 0x{self._address.hex()}"
            )

        # Save the new count, ie~ the index used for a future revert.
        self._clear_count[CLEAR_COUNT_KEY_NAME] = to_bytes(new_clear_count)

    def record(self, checkpoint: JournalDBCheckpoint) -> None:
        self._journal_storage.record(checkpoint)
        self._clear_count.record(checkpoint)

    def discard(self, checkpoint: JournalDBCheckpoint) -> None:
        latest_clear_count = to_int(self._clear_count[CLEAR_COUNT_KEY_NAME])

        if self._journal_storage.has_checkpoint(checkpoint):
            self._journal_storage.discard(checkpoint)
            self._clear_count.discard(checkpoint)
        else:
            # if the checkpoint comes before this account started tracking,
            #    then simply reset to the beginning
            self._journal_storage.reset()
            self._clear_count.reset()
        self._storage_cache.reset_cache()

        reverted_clear_count = to_int(self._clear_count[CLEAR_COUNT_KEY_NAME])

        if reverted_clear_count == latest_clear_count - 1:
            # This revert rewinds past a trie deletion, so roll back to the trie at
            #   that point. We use the clear count as an index to get back to the
            #   old base trie.
            self._storage_lookup.rollback_trie(reverted_clear_count)
        elif reverted_clear_count == latest_clear_count:
            # No change in the base trie, take no action
            pass
        else:
            # Although CREATE2 permits multiple creates and deletes in a single block,
            #   you can still only revert across a single delete. That's because delete
            #   is only triggered at the end of the transaction.
            raise ValidationError(
                f"This revert has changed the clear count in an invalid way, from"
                f" {latest_clear_count} to {reverted_clear_count}, in 0x{self._address.hex()}"
            )

    def commit(self, checkpoint: JournalDBCheckpoint) -> None:
        if self._journal_storage.has_checkpoint(checkpoint):
            self._journal_storage.commit(checkpoint)
            self._clear_count.commit(checkpoint)
        else:
            # if the checkpoint comes before this account started tracking,
            #    then flatten all changes, without persisting
            self._journal_storage.flatten()
            self._clear_count.flatten()

    def lock_changes(self) -> None:
        if self._journal_storage.has_clear():
            self._locked_changes.clear()
        self._journal_storage.persist()

    def make_storage_root(self) -> None:
        self.lock_changes()
        self._locked_changes.persist()

    def _validate_flushed(self) -> None:
        """
        Will raise an exception if there are some changes made since the last persist.
        """
        journal_diff = self._journal_storage.diff()
        if len(journal_diff) > 0:
            raise ValidationError(
                f"StorageDB had a dirty journal when it needed to be clean: {journal_diff!r}"
            )

    def get_accessed_slots(self) -> FrozenSet[int]:
        return frozenset(self._accessed_slots)

    @property
    def has_changed_root(self) -> bool:
        return self._storage_lookup.has_changed_root

    def get_changed_root(self) -> Hash32:
        return self._storage_lookup.get_changed_root()

    def persist(self, db: DatabaseAPI) -> None:
        self._validate_flushed()
        if self._storage_lookup.has_changed_root:
            self._storage_lookup.commit_to(db)
