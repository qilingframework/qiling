from lru import LRU
from typing import (
    cast,
    Dict,
    Iterable,
    Set,
    Tuple,
)

from eth_hash.auto import keccak
from eth_typing import (
    Address,
    Hash32
)

from eth_utils import (
    encode_hex,
    get_extended_debug_logger,
    to_checksum_address,
    to_dict,
    to_tuple,
    ValidationError,
)
import rlp
from trie import (
    HexaryTrie,
    exceptions as trie_exceptions,
)

from ..abc import (
    AccountDatabaseAPI,
    AccountStorageDatabaseAPI,
    AtomicDatabaseAPI,
    DatabaseAPI,
    MetaWitnessAPI,
)
from ..constants import (
    BLANK_ROOT_HASH,
    EMPTY_SHA3,
)
from ..db.accesslog import (
    KeyAccessLoggerAtomicDB,
    KeyAccessLoggerDB,
)
from ..db.batch import (
    BatchDB,
)
from ..db.cache import (
    CacheDB,
)
from ..db.diff import (
    DBDiff,
)
from ..db.journal import (
    JournalDB,
)
from ..db.storage import (
    AccountStorageDB,
)
from ..db.witness import (
    AccountQueryTracker,
    MetaWitness,
)
from ..typing import (
    JournalDBCheckpoint,
)
from ..vm.interrupt import (
    MissingAccountTrieNode,
    MissingBytecode,
)
from ..rlp.accounts import (
    Account,
)
from ..validation import (
    validate_is_bytes,
    validate_uint256,
    validate_canonical_address,
)

from .hash_trie import HashTrie


class AccountDB(AccountDatabaseAPI):
    logger = get_extended_debug_logger('eth.db.account.AccountDB')

    def __init__(self, db: AtomicDatabaseAPI, state_root: Hash32 = BLANK_ROOT_HASH) -> None:
        r"""
        Internal implementation details (subject to rapid change):
        Database entries go through several pipes, like so...

        .. code::

            db > _batchdb ---------------------------> _journaldb ----------------> code lookups
             \
              -> _batchtrie -> _trie -> _trie_cache -> _journaltrie --------------> account lookups

        Journaling sequesters writes at the _journal* attrs ^, until persist is called.

        _batchtrie enables us to prune all trie changes while building
        state,  without deleting old trie roots.

        _batchdb and _batchtrie together enable us to make the state root,
        without saving everything to the database.

        _journaldb is a journaling of the keys and values used to store
        code and account storage.

        _trie is a hash-trie, used to generate the state root

        _trie_cache is a cache tied to the state root of the trie. It
        is important that this cache is checked *after* looking for
        the key in _journaltrie, because the cache is only invalidated
        after a state root change.

        _journaltrie is a journaling of the accounts (an address->rlp mapping,
        rather than the nodes stored by the trie). This enables
        a squashing of all account changes before pushing them into the trie.

        .. NOTE:: StorageDB works similarly

        AccountDB synchronizes the snapshot/revert/persist of both of the
        journals.
        """
        self._raw_store_db = KeyAccessLoggerAtomicDB(db, log_missing_keys=False)
        self._batchdb = BatchDB(self._raw_store_db)
        self._batchtrie = BatchDB(self._raw_store_db, read_through_deletes=True)
        self._journaldb = JournalDB(self._batchdb)
        self._trie = HashTrie(HexaryTrie(self._batchtrie, state_root, prune=True))
        self._trie_logger = KeyAccessLoggerDB(self._trie, log_missing_keys=False)
        self._trie_cache = CacheDB(self._trie_logger)
        self._journaltrie = JournalDB(self._trie_cache)
        self._account_cache = LRU(2048)
        self._account_stores: Dict[Address, AccountStorageDatabaseAPI] = {}
        self._dirty_accounts: Set[Address] = set()
        self._root_hash_at_last_persist = state_root
        self._accessed_accounts: Set[Address] = set()
        self._accessed_bytecodes: Set[Address] = set()

    @property
    def state_root(self) -> Hash32:
        return self._trie.root_hash

    @state_root.setter
    def state_root(self, value: Hash32) -> None:
        if self._trie.root_hash != value:
            self._trie_cache.reset_cache()
            self._trie.root_hash = value

    def has_root(self, state_root: bytes) -> bool:
        return state_root in self._batchtrie

    #
    # Storage
    #
    def get_storage(self, address: Address, slot: int, from_journal: bool = True) -> int:
        validate_canonical_address(address, title="Storage Address")
        validate_uint256(slot, title="Storage Slot")

        account_store = self._get_address_store(address)
        return account_store.get(slot, from_journal)

    def set_storage(self, address: Address, slot: int, value: int) -> None:
        validate_uint256(value, title="Storage Value")
        validate_uint256(slot, title="Storage Slot")
        validate_canonical_address(address, title="Storage Address")

        account_store = self._get_address_store(address)
        self._dirty_accounts.add(address)
        account_store.set(slot, value)

    def delete_storage(self, address: Address) -> None:
        validate_canonical_address(address, title="Storage Address")

        self._set_storage_root(address, BLANK_ROOT_HASH)
        self._wipe_storage(address)

    def _wipe_storage(self, address: Address) -> None:
        """
        Wipe out the storage, without explicitly handling the storage root update
        """
        account_store = self._get_address_store(address)
        self._dirty_accounts.add(address)
        account_store.delete()

    def _get_address_store(self, address: Address) -> AccountStorageDatabaseAPI:
        if address in self._account_stores:
            store = self._account_stores[address]
        else:
            storage_root = self._get_storage_root(address)
            store = AccountStorageDB(self._raw_store_db, storage_root, address)
            self._account_stores[address] = store
        return store

    def _dirty_account_stores(self) -> Iterable[Tuple[Address, AccountStorageDatabaseAPI]]:
        for address in self._dirty_accounts:
            store = self._account_stores[address]
            yield address, store

    @to_tuple
    def _get_changed_roots(self) -> Iterable[Tuple[Address, Hash32]]:
        # list all the accounts that were changed, and their new storage roots
        for address, store in self._dirty_account_stores():
            if store.has_changed_root:
                yield address, store.get_changed_root()

    def _get_storage_root(self, address: Address) -> Hash32:
        account = self._get_account(address)
        return account.storage_root

    def _set_storage_root(self, address: Address, new_storage_root: Hash32) -> None:
        account = self._get_account(address)
        self._set_account(address, account.copy(storage_root=new_storage_root))

    def _validate_flushed_storage(self, address: Address, store: AccountStorageDatabaseAPI) -> None:
        if store.has_changed_root:
            actual_storage_root = self._get_storage_root(address)
            expected_storage_root = store.get_changed_root()
            if expected_storage_root != actual_storage_root:
                raise ValidationError(
                    "Storage root was not saved to account before trying to persist roots. "
                    f"Account {address!r} had storage {actual_storage_root!r}, "
                    f"but should be {expected_storage_root!r}."
                )

    #
    # Balance
    #
    def get_balance(self, address: Address) -> int:
        validate_canonical_address(address, title="Storage Address")

        account = self._get_account(address)
        return account.balance

    def set_balance(self, address: Address, balance: int) -> None:
        validate_canonical_address(address, title="Storage Address")
        validate_uint256(balance, title="Account Balance")

        account = self._get_account(address)
        self._set_account(address, account.copy(balance=balance))

    #
    # Nonce
    #
    def get_nonce(self, address: Address) -> int:
        validate_canonical_address(address, title="Storage Address")

        account = self._get_account(address)
        return account.nonce

    def set_nonce(self, address: Address, nonce: int) -> None:
        validate_canonical_address(address, title="Storage Address")
        validate_uint256(nonce, title="Nonce")

        account = self._get_account(address)
        self._set_account(address, account.copy(nonce=nonce))

    def increment_nonce(self, address: Address) -> None:
        current_nonce = self.get_nonce(address)
        self.set_nonce(address, current_nonce + 1)

    #
    # Code
    #
    def get_code(self, address: Address) -> bytes:
        validate_canonical_address(address, title="Storage Address")

        code_hash = self.get_code_hash(address)
        if code_hash == EMPTY_SHA3:
            return b''
        else:
            try:
                return self._journaldb[code_hash]
            except KeyError:
                raise MissingBytecode(code_hash) #from KeyError
            finally:
                if code_hash in self._get_accessed_node_hashes():
                    self._accessed_bytecodes.add(address)

    def set_code(self, address: Address, code: bytes) -> None:
        validate_canonical_address(address, title="Storage Address")
        validate_is_bytes(code, title="Code")

        account = self._get_account(address)

        code_hash = keccak(code)
        self._journaldb[code_hash] = code
        self._set_account(address, account.copy(code_hash=code_hash))

    def get_code_hash(self, address: Address) -> Hash32:
        validate_canonical_address(address, title="Storage Address")

        account = self._get_account(address)
        return account.code_hash

    def delete_code(self, address: Address) -> None:
        validate_canonical_address(address, title="Storage Address")

        account = self._get_account(address)
        self._set_account(address, account.copy(code_hash=EMPTY_SHA3))

    #
    # Account Methods
    #
    def account_has_code_or_nonce(self, address: Address) -> bool:
        return self.get_nonce(address) != 0 or self.get_code_hash(address) != EMPTY_SHA3

    def delete_account(self, address: Address) -> None:
        validate_canonical_address(address, title="Storage Address")

        # We must wipe the storage first, because if it's the first time we load it,
        #   then we want to load it with the original storage root hash, not the
        #   empty one. (in case of a later revert, we don't want to poison the storage cache)
        self._wipe_storage(address)

        if address in self._account_cache:
            del self._account_cache[address]
        del self._journaltrie[address]

    def account_exists(self, address: Address) -> bool:
        validate_canonical_address(address, title="Storage Address")
        account_rlp = self._get_encoded_account(address, from_journal=True)
        return account_rlp != b''

    def touch_account(self, address: Address) -> None:
        validate_canonical_address(address, title="Storage Address")

        account = self._get_account(address)
        self._set_account(address, account)

    def account_is_empty(self, address: Address) -> bool:
        return not self.account_has_code_or_nonce(address) and self.get_balance(address) == 0

    #
    # Internal
    #
    def _get_encoded_account(self, address: Address, from_journal: bool = True) -> bytes:
        self._accessed_accounts.add(address)
        lookup_trie = self._journaltrie if from_journal else self._trie_cache

        try:
            return lookup_trie[address]
        except trie_exceptions.MissingTrieNode as exc:
            raise MissingAccountTrieNode(*exc.args) from exc
        except KeyError:
            # In case the account is deleted in the JournalDB
            return b''

    def _get_account(self, address: Address, from_journal: bool = True) -> Account:
        if from_journal and address in self._account_cache.keys():
            return self._account_cache[address]

        rlp_account = self._get_encoded_account(address, from_journal)

        if rlp_account:
            account = rlp.decode(rlp_account, sedes=Account)
        else:
            account = Account()
        if from_journal:
            self._account_cache[address] = account
        return account

    def _set_account(self, address: Address, account: Account) -> None:
        self._account_cache[address] = account
        rlp_account = rlp.encode(account, sedes=Account)
        self._journaltrie[address] = rlp_account

    #
    # Record and discard API
    #
    def record(self) -> JournalDBCheckpoint:
        checkpoint = self._journaldb.record()
        self._journaltrie.record(checkpoint)

        for _, store in self._dirty_account_stores():
            store.record(checkpoint)
        return checkpoint

    def discard(self, checkpoint: JournalDBCheckpoint) -> None:
        self._journaldb.discard(checkpoint)
        self._journaltrie.discard(checkpoint)
        self._account_cache.clear()
        for _, store in self._dirty_account_stores():
            store.discard(checkpoint)

    def commit(self, checkpoint: JournalDBCheckpoint) -> None:
        self._journaldb.commit(checkpoint)
        self._journaltrie.commit(checkpoint)
        for _, store in self._dirty_account_stores():
            store.commit(checkpoint)

    def lock_changes(self) -> None:
        for _, store in self._dirty_account_stores():
            store.lock_changes()

    def make_state_root(self) -> Hash32:
        for _, store in self._dirty_account_stores():
            store.make_storage_root()

        for address, storage_root in self._get_changed_roots():
            if self.account_exists(address) or storage_root != BLANK_ROOT_HASH:
                self._set_storage_root(address, storage_root)

        self._journaldb.persist()

        diff = self._journaltrie.diff()
        if diff.deleted_keys() or diff.pending_items():
            # In addition to squashing (which is redundant here), this context manager causes
            # an atomic commit of the changes, so exceptions will revert the trie
            with self._trie.squash_changes() as memory_trie:
                self._apply_account_diff_without_proof(diff, memory_trie)

        self._journaltrie.reset()
        self._trie_cache.reset_cache()

        return self.state_root

    def persist(self) -> MetaWitnessAPI:
        self.make_state_root()

        # persist storage
        with self._raw_store_db.atomic_batch() as write_batch:
            for address, store in self._dirty_account_stores():
                self._validate_flushed_storage(address, store)
                store.persist(write_batch)

        for address, new_root in self._get_changed_roots():
            if new_root is None:
                raise ValidationError(
                    f"Cannot validate new root of account 0x{address.hex()} "
                    f"which has a new root hash of None"
                )
            elif new_root not in self._raw_store_db and new_root != BLANK_ROOT_HASH:
                raise ValidationError(
                    "After persisting storage trie, a root node was not found. "
                    f"State root for account 0x{address.hex()} "
                    f"is missing for hash 0x{new_root.hex()}."
                )

        # generate witness (copy) before clearing the underlying data
        meta_witness = self._get_meta_witness()

        # reset local storage trackers
        self._account_stores = {}
        self._dirty_accounts = set()
        self._accessed_accounts = set()
        self._accessed_bytecodes = set()
        # We have to clear the account cache here so that future account accesses
        #   will get added to _accessed_accounts correctly. Account accesses that
        #   are cached do not add the address to the list of accessed accounts.
        self._account_cache.clear()

        # persist accounts
        self._validate_generated_root()
        new_root_hash = self.state_root
        with self._raw_store_db.atomic_batch() as write_batch:
            self._batchtrie.commit_to(write_batch, apply_deletes=False)
            self._batchdb.commit_to(write_batch, apply_deletes=False)
        self._root_hash_at_last_persist = new_root_hash

        return meta_witness

    def _get_accessed_node_hashes(self) -> Set[Hash32]:
        return cast(Set[Hash32], self._raw_store_db.keys_read)

    @to_dict
    def _get_access_list(self) -> Iterable[Tuple[Address, AccountQueryTracker]]:
        """
        Get the list of addresses that were accessed, whether the bytecode was accessed, and
        which storage slots were accessed.
        """
        for address in self._accessed_accounts:
            did_access_bytecode = address in self._accessed_bytecodes
            if address in self._account_stores:
                accessed_storage_slots = self._account_stores[address].get_accessed_slots()
            else:
                accessed_storage_slots = frozenset()
            yield address, AccountQueryTracker(did_access_bytecode, accessed_storage_slots)

    def _get_meta_witness(self) -> MetaWitness:
        """
        Get a variety of metadata about the state witness needed to execute the block.

        This creates a copy, so that underlying changes do not affect the returned MetaWitness.
        """
        return MetaWitness(self._get_accessed_node_hashes(), self._get_access_list())

    def _validate_generated_root(self) -> None:
        db_diff = self._journaldb.diff()
        if len(db_diff):
            raise ValidationError(
                f"AccountDB had a dirty db when it needed to be clean: {db_diff!r}"
            )
        trie_diff = self._journaltrie.diff()
        if len(trie_diff):
            raise ValidationError(
                f"AccountDB had a dirty trie when it needed to be clean: {trie_diff!r}"
            )

    def _apply_account_diff_without_proof(self, diff: DBDiff, trie: DatabaseAPI) -> None:
        """
        Apply diff of trie updates, when original nodes might be missing.
        Note that doing this naively will raise exceptions about missing nodes
        from *intermediate* trie roots. This captures exceptions and uses the previous
        trie root hash that will be recognized by other nodes.
        """
        # It's fairly common that when an account is deleted, we need to retrieve nodes
        # for accounts that were not needed during normal execution. We only need these
        # nodes to refactor the trie.
        for delete_key in diff.deleted_keys():
            try:
                del trie[delete_key]
            except trie_exceptions.MissingTrieNode as exc:
                raise MissingAccountTrieNode(
                    exc.missing_node_hash,
                    self._root_hash_at_last_persist,
                    exc.requested_key,
                ) from exc

        # It's fairly unusual, but possible, that setting an account will need unknown
        # nodes during a trie refactor. Here is an example that seems to cause it:
        #
        # Setup:
        #   - Root node is a branch, with 0 pointing to a leaf
        #   - The complete leaf key is (0, 1, 2), so (1, 2) is in the leaf node
        #   - We know the leaf node hash but not the leaf node body
        # Refactor that triggers missing node:
        #   - Add value with key (0, 3, 4)
        #   - We need to replace the current leaf node with a branch that points leaves at 1 and 3
        #   - The leaf for key (0, 1, 2) now contains only the (2) part, so needs to be rebuilt
        #   - We need the full body of the old (1, 2) leaf node, to rebuild

        for key, val in diff.pending_items():
            try:
                trie[key] = val
            except trie_exceptions.MissingTrieNode as exc:
                raise MissingAccountTrieNode(
                    exc.missing_node_hash,
                    self._root_hash_at_last_persist,
                    exc.requested_key,
                ) from exc
