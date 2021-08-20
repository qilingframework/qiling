from abc import (
    ABC,
    abstractmethod
)
from typing import (
    Any,
    Callable,
    ContextManager,
    Dict,
    FrozenSet,
    Iterable,
    Iterator,
    MutableMapping,
    Tuple,
    Type,
    TypeVar,
    Union,
)

from eth_typing import (
    Address,
    BlockNumber,
    Hash32,
)

from eth_utils import ExtendedDebugLogger

from .constants import BLANK_ROOT_HASH

from .exceptions import VMError
from .typing import (
    BytesOrView,
    JournalDBCheckpoint,
)


T = TypeVar('T')


class MetaWitnessAPI(ABC):
    @property
    @abstractmethod
    def hashes(self) -> FrozenSet[Hash32]:
        ...

    @property
    @abstractmethod
    def accounts_queried(self) -> FrozenSet[Address]:
        ...

    @property
    @abstractmethod
    def account_bytecodes_queried(self) -> FrozenSet[Address]:
        ...

    @abstractmethod
    def get_slots_queried(self, address: Address) -> FrozenSet[int]:
        ...

    @property
    @abstractmethod
    def total_slots_queried(self) -> int:
        """
        Summed across all accounts, how many storage slots were queried?
        """
        ...


class DatabaseAPI(MutableMapping[bytes, bytes], ABC):
    """
    A class representing a database.
    """
    @abstractmethod
    def set(self, key: bytes, value: bytes) -> None:
        """
        Assign the ``value`` to the ``key``.
        """
        ...

    @abstractmethod
    def exists(self, key: bytes) -> bool:
        """
        Return ``True`` if the ``key`` exists in the database, otherwise ``False``.
        """
        ...

    @abstractmethod
    def delete(self, key: bytes) -> None:
        """
        Delete the given ``key`` from the database.
        """
        ...


class AtomicWriteBatchAPI(DatabaseAPI):
    """
    The readable/writeable object returned by an atomic database when we start building
    a batch of writes to commit.

    Reads to this database will observe writes written during batching,
    but the writes will not actually persist until this object is committed.
    """
    pass


class AtomicDatabaseAPI(DatabaseAPI):
    """
    Like ``BatchDB``, but immediately write out changes if they are
    not in an ``atomic_batch()`` context.
    """
    @abstractmethod
    def atomic_batch(self) -> ContextManager[AtomicWriteBatchAPI]:
        """
        Return a :class:`~typing.ContextManager` to write an atomic batch to the database.
        """
        ...


class GasMeterAPI(ABC):
    """
    A class to define a gas meter.
    """
    gas_refunded: int
    gas_remaining: int

    #
    # Write API
    #
    @abstractmethod
    def consume_gas(self, amount: int, reason: str) -> None:
        """
        Consume ``amount`` of gas for a defined ``reason``.
        """
        ...

    @abstractmethod
    def return_gas(self, amount: int) -> None:
        """
        Return ``amount`` of gas.
        """
        ...

    @abstractmethod
    def refund_gas(self, amount: int) -> None:
        """
        Refund ``amount`` of gas.
        """
        ...


class MessageAPI(ABC):
    """
    A message for VM computation.
    """
    code: bytes
    _code_address: Address
    create_address: Address
    data: BytesOrView
    depth: int
    gas: int
    is_static: bool
    sender: Address
    should_transfer_value: bool
    _storage_address: Address
    to: Address
    value: int
    gas_price: int

    __slots__ = [
        'code',
        '_code_address',
        'create_address',
        'data',
        'depth',
        'gas',
        'is_static',
        'sender',
        'should_transfer_value',
        '_storage_address'
        'to',
        'value',
    ]

    @property
    @abstractmethod
    def code_address(self) -> Address:
        ...

    @property
    @abstractmethod
    def storage_address(self) -> Address:
        ...

    @property
    @abstractmethod
    def is_create(self) -> bool:
        ...

    @property
    @abstractmethod
    def data_as_bytes(self) -> bytes:
        ...


class OpcodeAPI(ABC):
    """
    A class representing an opcode.
    """
    mnemonic: str

    @abstractmethod
    def __call__(self, computation: 'ComputationAPI') -> None:
        """
        Execute the logic of the opcode.
        """
        ...

    @classmethod
    @abstractmethod
    def as_opcode(cls: Type[T],
                  logic_fn: Callable[['ComputationAPI'], None],
                  mnemonic: str,
                  gas_cost: int) -> T:
        """
        Class factory method for turning vanilla functions into Opcodes.
        """
        ...

    @abstractmethod
    def __copy__(self) -> 'OpcodeAPI':
        """
        Return a copy of the opcode.
        """
        ...

    @abstractmethod
    def __deepcopy__(self, memo: Any) -> 'OpcodeAPI':
        """
        Return a deep copy of the opcode.
        """
        ...


class TransactionContextAPI(ABC):
    """
    Immutable transaction context information that remains constant over the VM execution.
    """
    @abstractmethod
    def __init__(self, gas_price: int, origin: Address) -> None:
        """
        Initialize the transaction context from the given ``gas_price`` and ``origin`` address.
        """
        ...

    @abstractmethod
    def get_next_log_counter(self) -> int:
        """
        Increment and return the log counter.
        """
        ...

    @property
    @abstractmethod
    def gas_price(self) -> int:
        """
        Return the gas price of the transaction context.
        """
        ...

    @property
    @abstractmethod
    def origin(self) -> Address:
        """
        Return the origin of the transaction context.
        """
        ...


class MemoryAPI(ABC):
    """
    A class representing the memory of the :class:`~eth.abc.VirtualMachineAPI`.
    """
    @abstractmethod
    def extend(self, start_position: int, size: int) -> None:
        """
        Extend the memory from the given ``start_position`` to the provided ``size``.
        """
        ...

    @abstractmethod
    def __len__(self) -> int:
        """
        Return the length of the memory.
        """
        ...

    @abstractmethod
    def write(self, start_position: int, size: int, value: bytes) -> None:
        """
        Write `value` into memory.
        """
        ...

    @abstractmethod
    def read(self, start_position: int, size: int) -> memoryview:
        """
        Return a view into the memory
        """
        ...

    @abstractmethod
    def read_bytes(self, start_position: int, size: int) -> bytes:
        """
        Read a value from memory and return a fresh bytes instance
        """
        ...


class StackAPI(ABC):
    """
    A class representing the stack of the :class:`~eth.abc.VirtualMachineAPI`.
    """
    @abstractmethod
    def push_int(self, value: int) -> None:
        """
        Push an integer item onto the stack.
        """
        ...

    @abstractmethod
    def push_bytes(self, value: bytes) -> None:
        """
        Push a bytes item onto the stack.
        """
        ...

    @abstractmethod
    def pop1_bytes(self) -> bytes:
        """
        Pop and return a bytes element from the stack.

        Raise `eth.exceptions.InsufficientStack` if the stack was empty.
        """
        ...

    @abstractmethod
    def pop1_int(self) -> int:
        """
        Pop and return an integer from the stack.

        Raise `eth.exceptions.InsufficientStack` if the stack was empty.
        """
        ...

    @abstractmethod
    def pop1_any(self) -> Union[int, bytes]:
        """
        Pop and return an element from the stack.
        The type of each element will be int or bytes, depending on whether it was
        pushed with push_bytes or push_int.

        Raise `eth.exceptions.InsufficientStack` if the stack was empty.
        """
        ...

    @abstractmethod
    def pop_any(self, num_items: int) -> Tuple[Union[int, bytes], ...]:
        """
        Pop and return a tuple of items of length ``num_items`` from the stack.
        The type of each element will be int or bytes, depending on whether it was
        pushed with stack_push_bytes or stack_push_int.

        Raise `eth.exceptions.InsufficientStack` if there are not enough items on
        the stack.

        Items are ordered with the top of the stack as the first item in the tuple.
        """
        ...

    @abstractmethod
    def pop_ints(self, num_items: int) -> Tuple[int, ...]:
        """
        Pop and return a tuple of integers of length ``num_items`` from the stack.

        Raise `eth.exceptions.InsufficientStack` if there are not enough items on
        the stack.

        Items are ordered with the top of the stack as the first item in the tuple.
        """
        ...

    @abstractmethod
    def pop_bytes(self, num_items: int) -> Tuple[bytes, ...]:
        """
        Pop and return a tuple of bytes of length ``num_items`` from the stack.

        Raise `eth.exceptions.InsufficientStack` if there are not enough items on
        the stack.

        Items are ordered with the top of the stack as the first item in the tuple.
        """
        ...

    @abstractmethod
    def swap(self, position: int) -> None:
        """
        Perform a SWAP operation on the stack.
        """
        ...

    @abstractmethod
    def dup(self, position: int) -> None:
        """
        Perform a DUP operation on the stack.
        """
        ...


class CodeStreamAPI(ABC):
    """
    A class representing a stream of EVM code.
    """
    program_counter: int

    @abstractmethod
    def read(self, size: int) -> bytes:
        """
        Read and return the code from the current position of the cursor up to ``size``.
        """
        ...

    @abstractmethod
    def pc(self) -> int:
        ...

    @abstractmethod
    def __len__(self) -> int:
        """
        Return the length of the code stream.
        """
        ...

    @abstractmethod
    def __getitem__(self, index: int) -> int:
        """
        Return the ordinal value of the byte at the given ``index``.
        """
        ...

    @abstractmethod
    def __iter__(self) -> Iterator[int]:
        """
        Iterate over all ordinal values of the bytes of the code stream.
        """
        ...

    @abstractmethod
    def peek(self) -> int:
        """
        Return the ordinal value of the byte at the current program counter.
        """
        ...

    @abstractmethod
    def seek(self, program_counter: int) -> ContextManager['CodeStreamAPI']:
        """
        Return a :class:`~typing.ContextManager` with the program counter
        set to ``program_counter``.
        """
        ...

    @abstractmethod
    def is_valid_opcode(self, position: int) -> bool:
        """
        Return ``True`` if a valid opcode exists at ``position``.
        """
        ...


class StackManipulationAPI(ABC):
    @abstractmethod
    def stack_pop_ints(self, num_items: int) -> Tuple[int, ...]:
        """
        Pop the last ``num_items`` from the stack, returning a tuple of their ordinal values.
        """
        ...

    @abstractmethod
    def stack_pop_bytes(self, num_items: int) -> Tuple[bytes, ...]:
        """
        Pop the last ``num_items`` from the stack, returning a tuple of bytes.
        """
        ...

    @abstractmethod
    def stack_pop_any(self, num_items: int) -> Tuple[Union[int, bytes], ...]:
        """
        Pop the last ``num_items`` from the stack, returning a tuple with potentially mixed values
        of bytes or ordinal values of bytes.
        """
        ...

    @abstractmethod
    def stack_pop1_int(self) -> int:
        """
        Pop one item from the stack and return the ordinal value of the represented bytes.
        """
        ...

    @abstractmethod
    def stack_pop1_bytes(self) -> bytes:
        """
        Pop one item from the stack and return the value as ``bytes``.
        """
        ...

    @abstractmethod
    def stack_pop1_any(self) -> Union[int, bytes]:
        """
        Pop one item from the stack and return the value either as byte or the ordinal value of
        a byte.
        """
        ...

    @abstractmethod
    def stack_push_int(self, value: int) -> None:
        """
        Push ``value`` on the stack which must be a 256 bit integer.
        """
        ...

    @abstractmethod
    def stack_push_bytes(self, value: bytes) -> None:
        """
        Push ``value`` on the stack which must be a 32 byte string.
        """
        ...


class ExecutionContextAPI(ABC):
    """
    A class representing context information that remains constant over the execution of a block.
    """
    @property
    @abstractmethod
    def coinbase(self) -> Address:
        """
        Return the coinbase address of the block.
        """
        ...

    @property
    @abstractmethod
    def timestamp(self) -> int:
        """
        Return the timestamp of the block.
        """
        ...

    @property
    @abstractmethod
    def block_number(self) -> BlockNumber:
        """
        Return the number of the block.
        """
        ...

    @property
    @abstractmethod
    def difficulty(self) -> int:
        """
        Return the difficulty of the block.
        """
        ...

    @property
    @abstractmethod
    def gas_limit(self) -> int:
        """
        Return the gas limit of the block.
        """
        ...

    @property
    @abstractmethod
    def prev_hashes(self) -> Iterable[Hash32]:
        """
        Return an iterable of block hashes that precede the block.
        """
        ...

    @property
    @abstractmethod
    def chain_id(self) -> int:
        """
        Return the id of the chain.
        """
        ...


class ComputationAPI(ContextManager['ComputationAPI'], StackManipulationAPI):
    """
    The base class for all execution computations.
    """
    msg: MessageAPI
    logger: ExtendedDebugLogger
    code: CodeStreamAPI
    opcodes: Dict[int, OpcodeAPI] = None
    state: 'StateAPI'
    return_data: bytes

    @abstractmethod
    def __init__(self,
                 state: 'StateAPI',
                 message: MessageAPI,
                 transaction_context: TransactionContextAPI) -> None:
        """
        Instantiate the computation.
        """
        ...

    #
    # Convenience
    #
    @property
    @abstractmethod
    def is_origin_computation(self) -> bool:
        """
        Return ``True`` if this computation is the outermost computation at ``depth == 0``.
        """
        ...

    #
    # Error handling
    #
    @property
    @abstractmethod
    def is_success(self) -> bool:
        """
        Return ``True`` if the computation did not result in an error.
        """
        ...

    @property
    @abstractmethod
    def is_error(self) -> bool:
        """
        Return ``True`` if the computation resulted in an error.
        """
        ...

    @property
    @abstractmethod
    def error(self) -> VMError:
        """
        Return the :class:`~eth.exceptions.VMError` of the computation.
        Raise ``AttributeError`` if no error exists.
        """
        ...

    @error.setter
    def error(self, value: VMError) -> None:
        """
        Set an :class:`~eth.exceptions.VMError` for the computation.
        """
        # See: https://github.com/python/mypy/issues/4165
        # Since we can't also decorate this with abstract method we want to be
        # sure that the setter doesn't actually get used as a noop.
        raise NotImplementedError

    @abstractmethod
    def raise_if_error(self) -> None:
        """
        If there was an error during computation, raise it as an exception immediately.

        :raise VMError:
        """
        ...

    @property
    @abstractmethod
    def should_burn_gas(self) -> bool:
        """
        Return ``True`` if the remaining gas should be burned.
        """
        ...

    @property
    @abstractmethod
    def should_return_gas(self) -> bool:
        """
        Return ``True`` if the remaining gas should be returned.
        """
        ...

    @property
    @abstractmethod
    def should_erase_return_data(self) -> bool:
        """
        Return ``True`` if the return data should be zerod out due to an error.
        """
        ...

    #
    # Memory Management
    #
    @abstractmethod
    def extend_memory(self, start_position: int, size: int) -> None:
        """
        Extend the size of the memory to be at minimum ``start_position + size``
        bytes in length.  Raise `eth.exceptions.OutOfGas` if there is not enough
        gas to pay for extending the memory.
        """
        ...

    @abstractmethod
    def memory_write(self, start_position: int, size: int, value: bytes) -> None:
        """
        Write ``value`` to memory at ``start_position``. Require that ``len(value) == size``.
        """
        ...

    @abstractmethod
    def memory_read(self, start_position: int, size: int) -> memoryview:
        """
        Read and return a view of ``size`` bytes from memory starting at ``start_position``.
        """
        ...

    @abstractmethod
    def memory_read_bytes(self, start_position: int, size: int) -> bytes:
        """
        Read and return ``size`` bytes from memory starting at ``start_position``.
        """
        ...

    #
    # Gas Consumption
    #
    @abstractmethod
    def get_gas_meter(self) -> GasMeterAPI:
        """
        Return the :class:`~eth.abc.GasMeterAPI` of the computation.
        """
        ...

    @abstractmethod
    def consume_gas(self, amount: int, reason: str) -> None:
        """
        Consume ``amount`` of gas from the remaining gas.
        Raise `eth.exceptions.OutOfGas` if there is not enough gas remaining.
        """
        ...

    @abstractmethod
    def return_gas(self, amount: int) -> None:
        """
        Return ``amount`` of gas to the available gas pool.
        """
        ...

    @abstractmethod
    def refund_gas(self, amount: int) -> None:
        """
        Add ``amount`` of gas to the pool of gas marked to be refunded.
        """
        ...

    @abstractmethod
    def get_gas_refund(self) -> int:
        """
        Return the number of refunded gas.
        """
        ...

    @abstractmethod
    def get_gas_used(self) -> int:
        """
        Return the number of used gas.
        """
        ...

    @abstractmethod
    def get_gas_remaining(self) -> int:
        """
        Return the number of remaining gas.
        """
        ...

    #
    # Stack management
    #
    @abstractmethod
    def stack_swap(self, position: int) -> None:
        """
        Swap the item on the top of the stack with the item at ``position``.
        """
        ...

    @abstractmethod
    def stack_dup(self, position: int) -> None:
        """
        Duplicate the stack item at ``position`` and pushes it onto the stack.
        """
        ...

    #
    # Computation result
    #
    @property
    @abstractmethod
    def output(self) -> bytes:
        """
        Get the return value of the computation.
        """
        ...

    @output.setter
    def output(self, value: bytes) -> None:
        """
        Set the return value of the computation.
        """
        # See: https://github.com/python/mypy/issues/4165
        # Since we can't also decorate this with abstract method we want to be
        # sure that the setter doesn't actually get used as a noop.
        raise NotImplementedError

    #
    # Runtime operations
    #
    @abstractmethod
    def prepare_child_message(self,
                              gas: int,
                              to: Address,
                              value: int,
                              data: BytesOrView,
                              code: bytes,
                              **kwargs: Any) -> MessageAPI:
        """
        Helper method for creating a child computation.
        """
        ...

    @abstractmethod
    def apply_child_computation(self, child_msg: MessageAPI) -> 'ComputationAPI':
        """
        Apply the vm message ``child_msg`` as a child computation.
        """
        ...

    @abstractmethod
    def generate_child_computation(self, child_msg: MessageAPI) -> 'ComputationAPI':
        """
        Generate a child computation from the given ``child_msg``.
        """
        ...

    @abstractmethod
    def add_child_computation(self, child_computation: 'ComputationAPI') -> None:
        """
        Add the given ``child_computation``.
        """
        ...

    #
    # Account management
    #
    @abstractmethod
    def register_account_for_deletion(self, beneficiary: Address) -> None:
        """
        Register the address of ``beneficiary`` for deletion.
        """
        ...

    @abstractmethod
    def get_accounts_for_deletion(self) -> Tuple[Tuple[Address, Address], ...]:
        """
        Return a tuple of addresses that are registered for deletion.
        """
        ...

    #
    # EVM logging
    #
    @abstractmethod
    def add_log_entry(self, account: Address, topics: Tuple[int, ...], data: bytes) -> None:
        """
        Add a log entry.
        """
        ...

    @abstractmethod
    def get_raw_log_entries(self) -> Tuple[Tuple[int, bytes, Tuple[int, ...], bytes], ...]:
        """
        Return a tuple of raw log entries.
        """
        ...

    @abstractmethod
    def get_log_entries(self) -> Tuple[Tuple[bytes, Tuple[int, ...], bytes], ...]:
        """
        Return the log entries for this computation and its children.

        They are sorted in the same order they were emitted during the transaction processing, and
        include the sequential counter as the first element of the tuple representing every entry.
        """
        ...

    #
    # State Transition
    #
    @classmethod
    @abstractmethod
    def apply_message(
            cls,
            state: 'StateAPI',
            message: MessageAPI,
            transaction_context: TransactionContextAPI) -> 'ComputationAPI':
        """
        Execute a VM message. This is where the VM-specific call logic exists.
        """
        ...

    @classmethod
    @abstractmethod
    def apply_create_message(
            cls,
            state: 'StateAPI',
            message: MessageAPI,
            transaction_context: TransactionContextAPI) -> 'ComputationAPI':
        """
        Execute a VM message to create a new contract. This is where the VM-specific
        create logic exists.
        """
        ...

    # @classmethod
    # @abstractmethod
    # def apply_computation(cls,
    #                       state: 'StateAPI',
    #                       message: MessageAPI,
    #                       transaction_context: TransactionContextAPI) -> 'ComputationAPI':
    #     """
    #     Execute the logic within the message: Either run the precompile, or
    #     step through each opcode.  Generally, the only VM-specific logic is for
    #     each opcode as it executes.

    #     This should rarely be called directly, because it will skip over other important
    #     VM-specific logic that happens before or after the execution.

    #     Instead, prefer :meth:`~apply_message` or :meth:`~apply_create_message`.
    #     """
    #     ...

    #
    # Opcode API
    #
    @property
    @abstractmethod
    def precompiles(self) -> Dict[Address, Callable[['ComputationAPI'], None]]:
        """
        Return a dictionary where the keys are the addresses of precompiles and the values are
        the precompile functions.
        """
        ...

    @abstractmethod
    def get_opcode_fn(self, opcode: int) -> OpcodeAPI:
        """
        Return the function for the given ``opcode``.
        """
        ...


class AccountStorageDatabaseAPI(ABC):
    """
    Storage cache and write batch for a single account. Changes are not
    merklized until :meth:`make_storage_root` is called.
    """
    @abstractmethod
    def get(self, slot: int, from_journal: bool = True) -> int:
        """
        Return the value at ``slot``. Lookups take the journal into consideration unless
        ``from_journal`` is explicitly set to ``False``.
        """
        ...

    @abstractmethod
    def set(self, slot: int, value: int) -> None:
        """
        Write ``value`` into ``slot``.
        """
        ...

    @abstractmethod
    def delete(self) -> None:
        """
        Delete the entire storage at the account.
        """
        ...

    @abstractmethod
    def record(self, checkpoint: JournalDBCheckpoint) -> None:
        """
        Record changes into the given ``checkpoint``.
        """
        ...

    @abstractmethod
    def discard(self, checkpoint: JournalDBCheckpoint) -> None:
        """
        Discard the given ``checkpoint``.
        """
        ...

    @abstractmethod
    def commit(self, checkpoint: JournalDBCheckpoint) -> None:
        """
        Collapse changes into the given ``checkpoint``.
        """
        ...

    @abstractmethod
    def lock_changes(self) -> None:
        """
        Locks in changes to storage, typically just as a transaction starts.

        This is used, for example, to look up the storage value from the start
        of the transaction, when calculating gas costs in EIP-2200: net gas metering.
        """
        ...

    @abstractmethod
    def make_storage_root(self) -> None:
        """
        Force calculation of the storage root for this account
        """
        ...

    @property
    @abstractmethod
    def has_changed_root(self) -> bool:
        """
        Return ``True`` if the storage root has changed.
        """
        ...

    @abstractmethod
    def get_changed_root(self) -> Hash32:
        """
        Return the changed root hash.
        Raise ``ValidationError`` if the root has not changed.
        """
        ...

    @abstractmethod
    def persist(self, db: DatabaseAPI) -> None:
        """
        Persist all changes to the database.
        """
        ...

    @abstractmethod
    def get_accessed_slots(self) -> FrozenSet[int]:
        """
        List all the slots that had been accessed since object creation.
        """
        ...


class AccountAPI(ABC):
    """
    A class representing an Ethereum account.
    """
    nonce: int
    balance: int
    storage_root: Hash32
    code_hash: Hash32


class AccountDatabaseAPI(ABC):
    """
    A class representing a database for accounts.
    """
    @abstractmethod
    def __init__(self, db: AtomicDatabaseAPI, state_root: Hash32 = BLANK_ROOT_HASH) -> None:
        """
        Initialize the account database.
        """
        ...

    @property
    @abstractmethod
    def state_root(self) -> Hash32:
        """
        Return the state root hash.
        """
        ...

    @state_root.setter
    def state_root(self, value: Hash32) -> None:
        """
        Force-set the state root hash.
        """
        # See: https://github.com/python/mypy/issues/4165
        # Since we can't also decorate this with abstract method we want to be
        # sure that the setter doesn't actually get used as a noop.
        raise NotImplementedError

    @abstractmethod
    def has_root(self, state_root: bytes) -> bool:
        """
        Return ``True`` if the `state_root` exists, otherwise ``False``.
        """
        ...

    #
    # Storage
    #
    @abstractmethod
    def get_storage(self, address: Address, slot: int, from_journal: bool = True) -> int:
        """
        Return the value stored at ``slot`` for the given ``address``. Take the journal
        into consideration unless ``from_journal`` is set to ``False``.
        """
        ...

    @abstractmethod
    def set_storage(self, address: Address, slot: int, value: int) -> None:
        """
        Write ``value`` into ``slot`` for the given ``address``.
        """
        ...

    @abstractmethod
    def delete_storage(self, address: Address) -> None:
        """
        Delete the storage at ``address``.
        """
        ...

    #
    # Balance
    #
    @abstractmethod
    def get_balance(self, address: Address) -> int:
        """
        Return the balance at ``address``.
        """
        ...

    @abstractmethod
    def set_balance(self, address: Address, balance: int) -> None:
        """
        Set ``balance`` as the new balance for ``address``.
        """
        ...

    #
    # Nonce
    #
    @abstractmethod
    def get_nonce(self, address: Address) -> int:
        """
        Return the nonce for ``address``.
        """
        ...

    @abstractmethod
    def set_nonce(self, address: Address, nonce: int) -> None:
        """
        Set ``nonce`` as the new nonce for ``address``.
        """
        ...

    @abstractmethod
    def increment_nonce(self, address: Address) -> None:
        """
        Increment the nonce for ``address``.
        """
        ...

    #
    # Code
    #
    @abstractmethod
    def set_code(self, address: Address, code: bytes) -> None:
        """
        Set ``code`` as the new code at ``address``.
        """
        ...

    @abstractmethod
    def get_code(self, address: Address) -> bytes:
        """
        Return the code at the given ``address``.
        """
        ...

    @abstractmethod
    def get_code_hash(self, address: Address) -> Hash32:
        """
        Return the hash of the code at ``address``.
        """
        ...

    @abstractmethod
    def delete_code(self, address: Address) -> None:
        """
        Delete the code at ``address``.
        """
        ...

    #
    # Account Methods
    #
    @abstractmethod
    def account_has_code_or_nonce(self, address: Address) -> bool:
        """
        Return ``True`` if either code or a nonce exists at ``address``.
        """
        ...

    @abstractmethod
    def delete_account(self, address: Address) -> None:
        """
        Delete the account at ``address``.
        """
        ...

    @abstractmethod
    def account_exists(self, address: Address) -> bool:
        """
        Return ``True`` if an account exists at ``address``, otherwise ``False``.
        """
        ...

    @abstractmethod
    def touch_account(self, address: Address) -> None:
        """
        Touch the account at ``address``.
        """
        ...

    @abstractmethod
    def account_is_empty(self, address: Address) -> bool:
        """
        Return ``True`` if an account exists at ``address``.
        """
        ...

    #
    # Record and discard API
    #
    @abstractmethod
    def record(self) -> JournalDBCheckpoint:
        """
        Create and return a new checkpoint.
        """
        ...

    @abstractmethod
    def discard(self, checkpoint: JournalDBCheckpoint) -> None:
        """
        Discard the given ``checkpoint``.
        """
        ...

    @abstractmethod
    def commit(self, checkpoint: JournalDBCheckpoint) -> None:
        """
        Collapse changes into ``checkpoint``.
        """
        ...

    @abstractmethod
    def lock_changes(self) -> None:
        """
        Locks in changes across all accounts' storage databases.

        This is typically used at the end of a transaction, to make sure that
        a revert doesn't roll back through the previous transaction, and to
        be able to look up the "original" value of any account storage, where
        "original" is the beginning of a transaction (instead of the beginning
        of a block).

        See :meth:`eth.abc.AccountStorageDatabaseAPI.lock_changes` for
        what is called on each account's storage database.
        """
        ...

    @abstractmethod
    def make_state_root(self) -> Hash32:
        """
        Generate the state root with all the current changes in AccountDB

        Current changes include every pending change to storage, as well as all account changes.
        After generating all the required tries, the final account state root is returned.

        This is an expensive operation, so should be called as little as possible. For example,
        pre-Byzantium, this is called after every transaction, because we need the state root
        in each receipt. Byzantium+, we only need state roots at the end of the block,
        so we *only* call it right before persistance.

        :return: the new state root
        """
        ...

    @abstractmethod
    def persist(self) -> MetaWitnessAPI:
        """
        Send changes to underlying database, including the trie state
        so that it will forever be possible to read the trie from this checkpoint.

        :meth:`make_state_root` must be explicitly called before this method.
        Otherwise persist will raise a ValidationError.
        """
        ...


class TransactionExecutorAPI(ABC):
    """
    A class providing APIs to execute transactions on VM state.
    """
    @abstractmethod
    def __init__(self, vm_state: 'StateAPI') -> None:
        """
        Initialize the executor from the given ``vm_state``.
        """
        ...

    @abstractmethod
    def __call__(self, message: MessageAPI) -> 'ComputationAPI':
        """
        Execute the ``transaction`` and return a :class:`eth.abc.ComputationAPI`.
        """
        ...

    # @abstractmethod
    # def validate_transaction(self, transaction: SignedTransactionAPI) -> None:
    #     """
    #     Validate the given ``transaction``.
    #     Raise a ``ValidationError`` if the transaction is invalid.
    #     """
    #     ...

    @abstractmethod
    def build_evm_message(self,
                        origin: Address,
                        gas_price: int,
                        gas: int,
                        to: Address,
                        sender: Address,
                        value: int,
                        data: bytes,
                        code: bytes,
                        code_address: Address = None,
                        contract_address: Address = None) -> MessageAPI:
        """
        Build and return a :class:`~eth.abc.MessageAPI` from the given ``transaction``.
        """
        ...

    @abstractmethod
    def build_computation(self,
                          message: MessageAPI) -> 'ComputationAPI':
        """
        Apply the ``message`` to the VM and use the given ``transaction`` to
        retrieve the context from.
        """

        ...

    @abstractmethod
    def finalize_computation(self,
                             message: MessageAPI,
                             computation: 'ComputationAPI') -> 'ComputationAPI':
        """
        Finalize the ``transaction``.
        """
        ...


class ConfigurableAPI(ABC):
    """
    A class providing inline subclassing.
    """
    @classmethod
    @abstractmethod
    def configure(cls: Type[T],
                  __name__: str = None,
                  **overrides: Any) -> Type[T]:
        ...


class StateAPI(ConfigurableAPI):
    """
    The base class that encapsulates all of the various moving parts related to
    the state of the VM during execution.
    Each :class:`~eth.abc.VirtualMachineAPI` must be configured with a subclass of the
    :class:`~eth.abc.StateAPI`.

      .. note::

        Each :class:`~eth.abc.StateAPI` class must be configured with:

        - ``computation_class``: The :class:`~eth.abc.ComputationAPI` class for
          vm execution.
        - ``transaction_context_class``: The :class:`~eth.abc.TransactionContextAPI`
          class for vm execution.
    """
    #
    # Set from __init__
    #
    execution_context: ExecutionContextAPI

    computation_class: Type[ComputationAPI]
    transaction_context_class: Type[TransactionContextAPI]
    account_db_class: Type[AccountDatabaseAPI]
    transaction_executor_class: Type[TransactionExecutorAPI] = None

    @abstractmethod
    def __init__(
            self,
            db: AtomicDatabaseAPI,
            execution_context: ExecutionContextAPI,
            state_root: bytes) -> None:
        """
        Initialize the state.
        """
        ...

    @property
    @abstractmethod
    def logger(self) -> ExtendedDebugLogger:
        """
        Return the logger.
        """
        ...

    #
    # Block Object Properties (in opcodes)
    #
    @property
    @abstractmethod
    def coinbase(self) -> Address:
        """
        Return the current ``coinbase`` from the current :attr:`~execution_context`
        """
        ...

    @property
    @abstractmethod
    def timestamp(self) -> int:
        """
        Return the current ``timestamp`` from the current :attr:`~execution_context`
        """
        ...

    @property
    @abstractmethod
    def block_number(self) -> BlockNumber:
        """
        Return the current ``block_number`` from the current :attr:`~execution_context`
        """
        ...

    @property
    @abstractmethod
    def difficulty(self) -> int:
        """
        Return the current ``difficulty`` from the current :attr:`~execution_context`
        """
        ...

    @property
    @abstractmethod
    def gas_limit(self) -> int:
        """
        Return the current ``gas_limit`` from the current :attr:`~transaction_context`
        """
        ...

    #
    # Access to account db
    #
    @classmethod
    @abstractmethod
    def get_account_db_class(cls) -> Type[AccountDatabaseAPI]:
        """
        Return the :class:`~eth.abc.AccountDatabaseAPI` class that the
        state class uses.
        """
        ...

    @property
    @abstractmethod
    def state_root(self) -> Hash32:
        """
        Return the current ``state_root`` from the underlying database
        """
        ...

    @abstractmethod
    def make_state_root(self) -> Hash32:
        """
        Create and return the state root.
        """
        ...

    @abstractmethod
    def get_storage(self, address: Address, slot: int, from_journal: bool = True) -> int:
        """
        Return the storage at ``slot`` for ``address``.
        """
        ...

    @abstractmethod
    def set_storage(self, address: Address, slot: int, value: int) -> None:
        """
        Write ``value`` to the given ``slot`` at ``address``.
        """
        ...

    @abstractmethod
    def delete_storage(self, address: Address) -> None:
        """
        Delete the storage at ``address``
        """
        ...

    @abstractmethod
    def delete_account(self, address: Address) -> None:
        """
        Delete the account at the given ``address``.
        """
        ...

    @abstractmethod
    def get_balance(self, address: Address) -> int:
        """
        Return the balance for the account at ``address``.
        """
        ...

    @abstractmethod
    def set_balance(self, address: Address, balance: int) -> None:
        """
        Set ``balance`` to the balance at ``address``.
        """
        ...

    @abstractmethod
    def delta_balance(self, address: Address, delta: int) -> None:
        """
        Apply ``delta`` to the balance at ``address``.
        """
        ...

    @abstractmethod
    def get_nonce(self, address: Address) -> int:
        """
        Return the nonce at ``address``.
        """
        ...

    @abstractmethod
    def set_nonce(self, address: Address, nonce: int) -> None:
        """
        Set ``nonce`` as the new nonce at ``address``.
        """
        ...

    @abstractmethod
    def increment_nonce(self, address: Address) -> None:
        """
        Increment the nonce at ``address``.
        """
        ...

    @abstractmethod
    def get_code(self, address: Address) -> bytes:
        """
        Return the code at ``address``.
        """
        ...

    @abstractmethod
    def set_code(self, address: Address, code: bytes) -> None:
        """
        Set ``code`` as the new code at ``address``.
        """
        ...

    @abstractmethod
    def get_code_hash(self, address: Address) -> Hash32:
        """
        Return the hash of the code at ``address``.
        """
        ...

    @abstractmethod
    def delete_code(self, address: Address) -> None:
        """
        Delete the code at ``address``.
        """
        ...

    @abstractmethod
    def has_code_or_nonce(self, address: Address) -> bool:
        """
        Return ``True`` if either a nonce or code exists at the given ``address``.
        """
        ...

    @abstractmethod
    def account_exists(self, address: Address) -> bool:
        """
        Return ``True`` if an account exists at ``address``.
        """
        ...

    @abstractmethod
    def touch_account(self, address: Address) -> None:
        """
        Touch the account at the given ``address``.
        """
        ...

    @abstractmethod
    def account_is_empty(self, address: Address) -> bool:
        """
        Return ``True`` if the account at ``address`` is empty, otherwise ``False``.
        """
        ...

    #
    # Access self._chaindb
    #
    @abstractmethod
    def snapshot(self) -> Tuple[Hash32, JournalDBCheckpoint]:
        """
        Perform a full snapshot of the current state.

        Snapshots are a combination of the :attr:`~state_root` at the time of the
        snapshot and the checkpoint from the journaled DB.
        """
        ...

    @abstractmethod
    def revert(self, snapshot: Tuple[Hash32, JournalDBCheckpoint]) -> None:
        """
        Revert the VM to the state at the snapshot
        """
        ...

    @abstractmethod
    def commit(self, snapshot: Tuple[Hash32, JournalDBCheckpoint]) -> None:
        """
        Commit the journal to the point where the snapshot was taken.  This
        merges in any changes that were recorded since the snapshot.
        """
        ...

    @abstractmethod
    def lock_changes(self) -> None:
        """
        Locks in all changes to state, typically just as a transaction starts.

        This is used, for example, to look up the storage value from the start
        of the transaction, when calculating gas costs in EIP-2200: net gas metering.
        """
        ...

    @abstractmethod
    def persist(self) -> MetaWitnessAPI:
        """
        Persist the current state to the database.
        """
        ...

    #
    # Access self.prev_hashes (Read-only)
    #
    @abstractmethod
    def get_ancestor_hash(self, block_number: BlockNumber) -> Hash32:
        """
        Return the hash for the ancestor block with number ``block_number``.
        Return the empty bytestring ``b''`` if the block number is outside of the
        range of available block numbers (typically the last 255 blocks).
        """
        ...

    #
    # Computation
    #
    @abstractmethod
    def get_computation(self,
                        message: MessageAPI,
                        transaction_context: TransactionContextAPI) -> ComputationAPI:
        """
        Return a computation instance for the given `message` and `transaction_context`
        """
        ...

    #
    # Transaction context
    #
    @classmethod
    @abstractmethod
    def get_transaction_context_class(cls) -> Type[TransactionContextAPI]:
        """
        Return the :class:`~eth.vm.transaction_context.BaseTransactionContext` class that the
        state class uses.
        """
        ...

    #
    # Execution
    #
    @abstractmethod
    def get_transaction_executor(self) -> TransactionExecutorAPI:
        """
        Return the transaction executor.
        """
        ...

    @classmethod
    @abstractmethod
    def get_transaction_context(cls,
                                message: MessageAPI) -> TransactionContextAPI:
        """
        Return the :class:`~eth.abc.TransactionContextAPI` for the given ``transaction``
        """
        ...
