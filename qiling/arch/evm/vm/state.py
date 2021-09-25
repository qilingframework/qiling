#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# from ....core import Qiling
from ..db.atomic import AtomicDB
from typing import Tuple, Type
from eth_typing import Address, BlockNumber, Hash32
from eth_utils import ExtendedDebugLogger, get_extended_debug_logger
from eth_utils.toolz import nth
from ..abc import (
    AccountDatabaseAPI,
    ComputationAPI,
    ExecutionContextAPI,
    MessageAPI,
    StateAPI,
    TransactionContextAPI,
    TransactionExecutorAPI,
    MetaWitnessAPI,
)
from ..constants import BLANK_ROOT_HASH, MAX_PREV_HEADER_DEPTH
from ..typing import JournalDBCheckpoint
from .._utils.datatypes import Configurable


class BaseState(Configurable, StateAPI):
    #
    # Set from __init__
    #
    __slots__ = ['_db', 'execution_context', '_account_db']

    computation_class: Type[ComputationAPI] = None
    transaction_context_class: Type[TransactionContextAPI] = None
    account_db_class: Type[AccountDatabaseAPI] = None
    transaction_executor_class: Type[TransactionExecutorAPI] = None

    def __init__(self,
                 ql,
                 execution_context: ExecutionContextAPI, db=AtomicDB(), state_root=BLANK_ROOT_HASH) -> None:
        self.ql = ql
        self.execution_context = execution_context
        self._account_db = self.get_account_db_class()(db, state_root)

    #
    # Logging
    #
    @property
    def logger(self) -> ExtendedDebugLogger:
        return get_extended_debug_logger(f'eth.vm.state.{self.__class__.__name__}')

    #
    # Block Object Properties (in opcodes)
    #
    @property
    def coinbase(self) -> Address:
        return self.execution_context.coinbase

    @property
    def timestamp(self) -> int:
        return self.execution_context.timestamp

    @property
    def block_number(self) -> BlockNumber:
        return self.execution_context.block_number

    @property
    def difficulty(self) -> int:
        return self.execution_context.difficulty

    @property
    def gas_limit(self) -> int:
        return self.execution_context.gas_limit

    #
    # Access to account db
    #
    @classmethod
    def get_account_db_class(cls) -> Type[AccountDatabaseAPI]:
        if cls.account_db_class is None:
            raise AttributeError(f"No account_db_class set for {cls.__name__}")
        return cls.account_db_class

    @property
    def state_root(self) -> Hash32:
        return self._account_db.state_root

    def make_state_root(self) -> Hash32:
        return self._account_db.make_state_root()

    def get_storage(self, address: Address, slot: int, from_journal: bool = True) -> int:
        return self._account_db.get_storage(address, slot, from_journal)

    def set_storage(self, address: Address, slot: int, value: int) -> None:
        return self._account_db.set_storage(address, slot, value)

    def delete_storage(self, address: Address) -> None:
        self._account_db.delete_storage(address)

    def delete_account(self, address: Address) -> None:
        self._account_db.delete_account(address)

    def get_balance(self, address: Address) -> int:
        return self._account_db.get_balance(address)

    def set_balance(self, address: Address, balance: int) -> None:
        self._account_db.set_balance(address, balance)

    def delta_balance(self, address: Address, delta: int) -> None:
        self.set_balance(address, self.get_balance(address) + delta)

    def get_nonce(self, address: Address) -> int:
        return self._account_db.get_nonce(address)

    def set_nonce(self, address: Address, nonce: int) -> None:
        self._account_db.set_nonce(address, nonce)

    def increment_nonce(self, address: Address) -> None:
        self._account_db.increment_nonce(address)

    def get_code(self, address: Address) -> bytes:
        return self._account_db.get_code(address)

    def set_code(self, address: Address, code: bytes) -> None:
        self._account_db.set_code(address, code)

    def get_code_hash(self, address: Address) -> Hash32:
        return self._account_db.get_code_hash(address)

    def delete_code(self, address: Address) -> None:
        self._account_db.delete_code(address)

    def has_code_or_nonce(self, address: Address) -> bool:
        return self._account_db.account_has_code_or_nonce(address)

    def account_exists(self, address: Address) -> bool:
        return self._account_db.account_exists(address)

    def touch_account(self, address: Address) -> None:
        self._account_db.touch_account(address)

    def account_is_empty(self, address: Address) -> bool:
        return self._account_db.account_is_empty(address)

    #
    # Access self._chaindb
    #
    def snapshot(self) -> Tuple[Hash32, JournalDBCheckpoint]:
        return self.state_root, self._account_db.record()

    def revert(self, snapshot: Tuple[Hash32, JournalDBCheckpoint]) -> None:
        state_root, account_snapshot = snapshot

        # first revert the database state root.
        self._account_db.state_root = state_root
        # now roll the underlying database back
        self._account_db.discard(account_snapshot)

    def commit(self, snapshot: Tuple[Hash32, JournalDBCheckpoint]) -> None:
        _, account_snapshot = snapshot
        self._account_db.commit(account_snapshot)

    def lock_changes(self) -> None:
        self._account_db.lock_changes()

    def persist(self) -> MetaWitnessAPI:
        return self._account_db.persist()

    #
    # Access self.prev_hashes (Read-only)
    #
    def get_ancestor_hash(self, block_number: int) -> Hash32:
        ancestor_depth = self.block_number - block_number - 1
        is_ancestor_depth_out_of_range = (
            ancestor_depth >= MAX_PREV_HEADER_DEPTH
            or ancestor_depth < 0
            or block_number < 0
        )
        if is_ancestor_depth_out_of_range:
            return Hash32(b'')

        try:
            return nth(ancestor_depth, self.execution_context.prev_hashes)
        except StopIteration:
            # Ancestor with specified depth not present
            return Hash32(b'')

    #
    # Computation
    #
    def get_computation(self,
                        ql,
                        message: MessageAPI,
                        transaction_context: TransactionContextAPI) -> ComputationAPI:
        if self.computation_class is None:
            raise AttributeError("No `computation_class` has been set for this State")
        else:
            computation = self.computation_class(self, ql, message, transaction_context)
        return computation

    #
    # Transaction context
    #
    @classmethod
    def get_transaction_context_class(cls) -> Type[TransactionContextAPI]:
        if cls.transaction_context_class is None:
            raise AttributeError("No `transaction_context_class` has been set for this State")
        return cls.transaction_context_class

    #
    # Execution
    #
    def get_transaction_executor(self) -> TransactionExecutorAPI:
        return self.transaction_executor_class(self.ql, self)

    @classmethod
    def get_transaction_context(cls,
                                message: MessageAPI) -> TransactionContextAPI:
        return cls.get_transaction_context_class()(
            gas_price=message.gas_price,
            origin=message.sender,
        )


class BaseTransactionExecutor(TransactionExecutorAPI):
    def __init__(self, ql, vm_state: StateAPI) -> None:
        self.ql = ql
        self.vm_state = vm_state

    def __call__(self, message: MessageAPI) -> ComputationAPI:
        computation = self.build_computation(message)
        finalized_computation = self.finalize_computation(message, computation)
        return finalized_computation
