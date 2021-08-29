#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import itertools
# from qiling.core import Qiling
from types import TracebackType
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
    Type,
    Union,
)

from sys import version_info
if version_info.minor >= 8:
    from functools import cached_property
else:
    from cached_property import cached_property
    
from eth_typing import Address

from ..abc import (
    MemoryAPI,
    StackAPI,
    GasMeterAPI,
    MessageAPI,
    OpcodeAPI,
    CodeStreamAPI,
    ComputationAPI,
    StateAPI,
    TransactionContextAPI,
)
from ..constants import (
    GAS_MEMORY,
    GAS_MEMORY_QUADRATIC_DENOMINATOR,
)
from ..exceptions import (
    Halt,
    VMError,
)
from ..typing import BytesOrView
from .._utils.datatypes import Configurable
from .._utils.numeric import ceil32
from ..validation import (
    validate_canonical_address,
    validate_is_bytes,
    validate_uint256,
)
from .code_stream import CodeStream
from .gas_meter import GasMeter
from .logic.invalid import InvalidOpcode
from .memory import Memory
from .message import Message
from .stack import Stack
from .disassembler import EVMDisasm
from ..hooks import evm_hooks_info
from .utils import analysis_bytecode, bytecode_to_bytes, runtime_code_detector


# def NO_RESULT(computation: ComputationAPI) -> None:
#     """
#     This is a special method intended for usage as the "no precompile found" result.
#     The type signature is designed to match the other precompiles.
#     """
#     raise Exception("This method is never intended to be executed")


def memory_gas_cost(size_in_bytes: int) -> int:
    size_in_words = ceil32(size_in_bytes) // 32
    linear_cost = size_in_words * GAS_MEMORY
    quadratic_cost = size_in_words ** 2 // GAS_MEMORY_QUADRATIC_DENOMINATOR

    total_cost = linear_cost + quadratic_cost
    return total_cost


class BaseComputation(Configurable, ComputationAPI):
    """
    The base class for all execution computations.

      .. note::

        Each :class:`~eth.vm.computation.BaseComputation` class must be configured with:

        ``opcodes``: A mapping from the opcode integer value to the logic function for the opcode.

        ``_precompiles``: A mapping of contract address to the precompile function for execution
        of precompiled contracts.
    """
    state: StateAPI = None
    msg: MessageAPI = None
    transaction_context: TransactionContextAPI = None

    _memory: MemoryAPI = None
    _stack: StackAPI = None
    _gas_meter: GasMeterAPI = None

    code: CodeStreamAPI = None

    children: List[ComputationAPI] = None

    _output: bytes = b''
    return_data: bytes = b''
    _error: VMError = None

    # TODO: use a NamedTuple for log entries
    _log_entries: List[Tuple[int, Address, Tuple[int, ...], bytes]] = None
    accounts_to_delete: Dict[Address, Address] = None

    # VM configuration
    opcodes: Dict[int, OpcodeAPI] = None
    _precompiles: Dict[Address, Callable[[ComputationAPI], ComputationAPI]] = None

    def __init__(self,
                 state: StateAPI,
                 message: MessageAPI,
                 transaction_context: TransactionContextAPI) -> None:
        self.ql = state.ql
        self.state = state
        self.msg = message
        self.transaction_context = transaction_context

        self._memory = Memory()
        self._stack = Stack()
        self._gas_meter = self.get_gas_meter()

        self.children = []
        self.accounts_to_delete = {}
        self._log_entries = []

        code = message.code
        self.code = CodeStream(code)

    #
    # Convenience
    #
    @property
    def is_origin_computation(self) -> bool:
        return self.msg.sender == self.transaction_context.origin

    #
    # Error handling
    #
    @property
    def is_success(self) -> bool:
        return self._error is None

    @property
    def is_error(self) -> bool:
        return not self.is_success

    @property
    def error(self) -> VMError:
        if self._error is not None:
            return self._error
        raise AttributeError("Computation does not have an error")

    @error.setter
    def error(self, value: VMError) -> None:
        if self._error is not None:
            raise AttributeError(f"Computation already has an error set: {self._error}")
        self._error = value

    def raise_if_error(self) -> None:
        if self._error is not None:
            raise self._error

    @property
    def should_burn_gas(self) -> bool:
        return self.is_error and self._error.burns_gas

    @property
    def should_return_gas(self) -> bool:
        return not self.should_burn_gas

    @property
    def should_erase_return_data(self) -> bool:
        return self.is_error and self._error.erases_return_data

    #
    # Memory Management
    #
    def extend_memory(self, start_position: int, size: int) -> None:
        validate_uint256(start_position, title="Memory start position")
        validate_uint256(size, title="Memory size")

        before_size = ceil32(len(self._memory))
        after_size = ceil32(start_position + size)

        before_cost = memory_gas_cost(before_size)
        after_cost = memory_gas_cost(after_size)

        if size:
            if before_cost < after_cost:
                gas_fee = after_cost - before_cost
                self._gas_meter.consume_gas(
                    gas_fee,
                    reason=" ".join((
                        "Expanding memory",
                        str(before_size),
                        "->",
                        str(after_size),
                    ))
                )

            self._memory.extend(start_position, size)

    def memory_write(self, start_position: int, size: int, value: bytes) -> None:
        return self._memory.write(start_position, size, value)

    def memory_read(self, start_position: int, size: int) -> memoryview:
        return self._memory.read(start_position, size)

    def memory_read_bytes(self, start_position: int, size: int) -> bytes:
        return self._memory.read_bytes(start_position, size)

    #
    # Gas Consumption
    #
    def get_gas_meter(self) -> GasMeterAPI:
        return GasMeter(self.msg.gas)

    def consume_gas(self, amount: int, reason: str) -> None:
        return self._gas_meter.consume_gas(amount, reason)

    def return_gas(self, amount: int) -> None:
        return self._gas_meter.return_gas(amount)

    def refund_gas(self, amount: int) -> None:
        return self._gas_meter.refund_gas(amount)

    def get_gas_refund(self) -> int:
        if self.is_error:
            return 0
        else:
            return self._gas_meter.gas_refunded + sum(c.get_gas_refund() for c in self.children)

    def get_gas_used(self) -> int:
        if self.should_burn_gas:
            return self.msg.gas
        else:
            return max(
                0,
                self.msg.gas - self._gas_meter.gas_remaining,
            )

    def get_gas_remaining(self) -> int:
        if self.should_burn_gas:
            return 0
        else:
            return self._gas_meter.gas_remaining

    #
    # Stack management
    #
    def stack_swap(self, position: int) -> None:
        return self._stack.swap(position)

    def stack_dup(self, position: int) -> None:
        return self._stack.dup(position)

    # Stack manipulation is performance-sensitive code.
    # Avoid method call overhead by proxying stack method directly to stack object

    @cached_property
    def stack_pop_ints(self) -> Callable[[int], Tuple[int, ...]]:
        return self._stack.pop_ints

    @cached_property
    def stack_pop_bytes(self) -> Callable[[int], Tuple[bytes, ...]]:
        return self._stack.pop_bytes

    @cached_property
    def stack_pop_any(self) -> Callable[[int], Tuple[Union[int, bytes], ...]]:
        return self._stack.pop_any

    @cached_property
    def stack_pop1_int(self) -> Callable[[], int]:
        return self._stack.pop1_int

    @cached_property
    def stack_pop1_bytes(self) -> Callable[[], bytes]:
        return self._stack.pop1_bytes

    @cached_property
    def stack_pop1_any(self) -> Callable[[], Union[int, bytes]]:
        return self._stack.pop1_any

    @cached_property
    def stack_push_int(self) -> Callable[[int], None]:
        return self._stack.push_int

    @cached_property
    def stack_push_bytes(self) -> Callable[[bytes], None]:
        return self._stack.push_bytes

    #
    # Computation result
    #
    @property
    def output(self) -> bytes:
        if self.should_erase_return_data:
            return b''
        else:
            return self._output

    @output.setter
    def output(self, value: bytes) -> None:
        validate_is_bytes(value)
        self._output = value

    #
    # Runtime operations
    #
    def prepare_child_message(self,
                              gas: int,
                              to: Address,
                              value: int,
                              data: BytesOrView,
                              code: bytes,
                              **kwargs: Any) -> MessageAPI:
        kwargs.setdefault('sender', self.msg.storage_address)

        child_message = Message(
            gas=gas,
            to=to,
            value=value,
            data=data,
            code=code,
            depth=self.msg.depth + 1,
            **kwargs
        )
        return child_message

    def apply_child_computation(self, child_msg: MessageAPI) -> ComputationAPI:
        child_computation = self.generate_child_computation(child_msg)
        self.add_child_computation(child_computation)
        return child_computation

    def generate_child_computation(self, child_msg: MessageAPI) -> ComputationAPI:
        if child_msg.is_create:
            child_computation = self.apply_create_message(
                self.state,
                child_msg,
                self.transaction_context,
            )
        else:
            child_computation = self.apply_message(
                self.state,
                child_msg,
                self.transaction_context,
            )
        return child_computation

    def add_child_computation(self, child_computation: ComputationAPI) -> None:
        if child_computation.is_error:
            if child_computation.msg.is_create:
                self.return_data = child_computation.output
            elif child_computation.should_burn_gas:
                self.return_data = b''
            else:
                self.return_data = child_computation.output
        else:
            if child_computation.msg.is_create:
                self.return_data = b''
            else:
                self.return_data = child_computation.output
        self.children.append(child_computation)

    #
    # Account management
    #
    def register_account_for_deletion(self, beneficiary: Address) -> None:
        validate_canonical_address(beneficiary, title="Self destruct beneficiary address")

        if self.msg.storage_address in self.accounts_to_delete:
            raise ValueError(
                "Invariant.  Should be impossible for an account to be "
                "registered for deletion multiple times"
            )
        self.accounts_to_delete[self.msg.storage_address] = beneficiary

    def get_accounts_for_deletion(self) -> Tuple[Tuple[Address, Address], ...]:
        if self.is_error:
            return tuple()
        else:
            return tuple(dict(itertools.chain(
                self.accounts_to_delete.items(),
                *(child.get_accounts_for_deletion() for child in self.children)
            )).items())

    #
    # EVM logging
    #
    def add_log_entry(self, account: Address, topics: Tuple[int, ...], data: bytes) -> None:
        validate_canonical_address(account, title="Log entry address")
        for topic in topics:
            validate_uint256(topic, title="Log entry topic")
        validate_is_bytes(data, title="Log entry data")
        self._log_entries.append(
            (self.transaction_context.get_next_log_counter(), account, topics, data))

    def get_raw_log_entries(self) -> Tuple[Tuple[int, bytes, Tuple[int, ...], bytes], ...]:
        if self.is_error:
            return ()
        else:
            return tuple(sorted(itertools.chain(
                self._log_entries,
                *(child.get_raw_log_entries() for child in self.children)
            )))

    def get_log_entries(self) -> Tuple[Tuple[bytes, Tuple[int, ...], bytes], ...]:
        return tuple(log[1:] for log in self.get_raw_log_entries())

    #
    # Context Manager API
    #
    def __enter__(self) -> ComputationAPI:
        return self

    def __exit__(self,
                 exc_type: Optional[Type[BaseException]],
                 exc_value: Optional[BaseException],
                 traceback: Optional[TracebackType]) -> Union[None, bool]:
        if exc_value and isinstance(exc_value, VMError):
            self._error = exc_value
            if self.should_burn_gas:
                self.consume_gas(
                    self._gas_meter.gas_remaining,
                    reason=" ".join((
                        "Zeroing gas due to VM Exception:",
                        str(exc_value),
                    )),
                )

            # suppress VM exceptions
            return True
        return None

    #
    # disassembly
    #
    @property
    def disasm(self):
        if self.msg.is_create:
            load_bytecode, runtime_code, _, _ = analysis_bytecode(self.msg.code)
            code = CodeStream(bytecode_to_bytes(load_bytecode + runtime_code))
        else:
            if self.msg.depth > 0:
                runtime_code, _, _ = runtime_code_detector(self.msg.code)
                code = bytecode_to_bytes(runtime_code)
                code = CodeStream(code)
            else:
                code = CodeStream(self.msg.code)

        return EVMDisasm().disasm(code, evm_hooks_info)

    #
    # Opcode API
    #
    @property
    def precompiles(self) -> Dict[Address, Callable[[ComputationAPI], Any]]:
        if self._precompiles is None:
            return dict()
        else:
            return self._precompiles

    def get_opcode_fn(self, opcode: int) -> OpcodeAPI:
        try:
            return self.opcodes[opcode]
        except KeyError:
            return InvalidOpcode(opcode)
