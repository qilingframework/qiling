#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from eth_typing import (
    Address,
)

from ... import constants

from ...exceptions import (
    OutOfBoundsRead,
)

from ..._utils.address import (
    force_bytes_to_address,
)
from ..._utils.numeric import (
    ceil32,
)

from ...vm.computation import BaseComputation


def balance(computation: BaseComputation) -> None:
    addr = force_bytes_to_address(computation.stack_pop1_bytes())
    _push_balance_of_address(addr, computation)


def selfbalance(computation: BaseComputation) -> None:
    _push_balance_of_address(computation.msg.storage_address, computation)


def _push_balance_of_address(address: Address, computation: BaseComputation) -> None:
    balance = computation.state.get_balance(address)
    computation.stack_push_int(balance)


def origin(computation: BaseComputation) -> None:
    computation.stack_push_bytes(computation.transaction_context.origin)


def address(computation: BaseComputation) -> None:
    computation.stack_push_bytes(computation.msg.storage_address)


def caller(computation: BaseComputation) -> None:
    computation.stack_push_bytes(computation.msg.sender)


def callvalue(computation: BaseComputation) -> None:
    computation.stack_push_int(computation.msg.value)


def calldataload(computation: BaseComputation) -> None:
    """
    Load call data into memory.
    """
    start_position = computation.stack_pop1_int()

    value = computation.msg.data_as_bytes[start_position:start_position + 32]
    padded_value = value.ljust(32, b'\x00')
    normalized_value = padded_value.lstrip(b'\x00')

    computation.stack_push_bytes(normalized_value)


def calldatasize(computation: BaseComputation) -> None:
    size = len(computation.msg.data)
    computation.stack_push_int(size)


def calldatacopy(computation: BaseComputation) -> None:
    (
        mem_start_position,
        calldata_start_position,
        size,
    ) = computation.stack_pop_ints(3)

    computation.extend_memory(mem_start_position, size)

    word_count = ceil32(size) // 32
    copy_gas_cost = word_count * constants.GAS_COPY

    computation.consume_gas(copy_gas_cost, reason="CALLDATACOPY fee")

    value = computation.msg.data_as_bytes[
        calldata_start_position: calldata_start_position + size
    ]
    padded_value = value.ljust(size, b'\x00')

    computation.memory_write(mem_start_position, size, padded_value)


def chain_id(computation: BaseComputation) -> None:
    computation.stack_push_int(computation.state.execution_context.chain_id)


def codesize(computation: BaseComputation) -> None:
    size = len(computation.code)
    computation.stack_push_int(size)


def codecopy(computation: BaseComputation) -> None:
    (
        mem_start_position,
        code_start_position,
        size,
    ) = computation.stack_pop_ints(3)

    computation.extend_memory(mem_start_position, size)

    word_count = ceil32(size) // 32
    copy_gas_cost = constants.GAS_COPY * word_count

    computation.consume_gas(
        copy_gas_cost,
        reason="CODECOPY: word gas cost",
    )

    with computation.code.seek(code_start_position):
        code_bytes = computation.code.read(size)

    padded_code_bytes = code_bytes.ljust(size, b'\x00')

    computation.memory_write(mem_start_position, size, padded_code_bytes)


def gasprice(computation: BaseComputation) -> None:
    computation.stack_push_int(computation.transaction_context.gas_price)


def extcodesize(computation: BaseComputation) -> None:
    account = force_bytes_to_address(computation.stack_pop1_bytes())
    code_size = len(computation.state.get_code(account))

    computation.stack_push_int(code_size)


def extcodecopy(computation: BaseComputation) -> None:
    account = force_bytes_to_address(computation.stack_pop1_bytes())
    (
        mem_start_position,
        code_start_position,
        size,
    ) = computation.stack_pop_ints(3)

    computation.extend_memory(mem_start_position, size)

    word_count = ceil32(size) // 32
    copy_gas_cost = constants.GAS_COPY * word_count

    computation.consume_gas(
        copy_gas_cost,
        reason='EXTCODECOPY: word gas cost',
    )

    code = computation.state.get_code(account)

    code_bytes = code[code_start_position:code_start_position + size]
    padded_code_bytes = code_bytes.ljust(size, b'\x00')

    computation.memory_write(mem_start_position, size, padded_code_bytes)


def extcodehash(computation: BaseComputation) -> None:
    """
    Return the code hash for a given address.
    EIP: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1052.md
    """
    account = force_bytes_to_address(computation.stack_pop1_bytes())
    state = computation.state

    if state.account_is_empty(account):
        computation.stack_push_bytes(constants.NULL_BYTE)
    else:
        computation.stack_push_bytes(state.get_code_hash(account))


def returndatasize(computation: BaseComputation) -> None:
    size = len(computation.return_data)
    computation.stack_push_int(size)


def returndatacopy(computation: BaseComputation) -> None:
    (
        mem_start_position,
        returndata_start_position,
        size,
    ) = computation.stack_pop_ints(3)

    if returndata_start_position + size > len(computation.return_data):
        raise OutOfBoundsRead(
            "Return data length is not sufficient to satisfy request.  Asked "
            f"for data from index {returndata_start_position} "
            f"to {returndata_start_position + size}.  "
            f"Return data is {len(computation.return_data)} bytes in length."
        )

    computation.extend_memory(mem_start_position, size)

    word_count = ceil32(size) // 32
    copy_gas_cost = word_count * constants.GAS_COPY

    computation.consume_gas(copy_gas_cost, reason="RETURNDATACOPY fee")

    value = computation.return_data[returndata_start_position: returndata_start_position + size]

    computation.memory_write(mem_start_position, size, value)
