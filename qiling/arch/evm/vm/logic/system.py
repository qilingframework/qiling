#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from eth_typing import (
    Address,
)
from eth_utils import (
    encode_hex,
)
from ... import constants
from ...exceptions import (
    Halt,
    Revert,
    WriteProtection,
)

from ..._utils.address import (
    force_bytes_to_address,
    generate_contract_address,
    generate_safe_contract_address,
)
from ..._utils.numeric import (
    ceil32,
)
from ...abc import (
    ComputationAPI,
    MessageAPI,
)
from ...vm import mnemonics
from ...vm.opcode import Opcode

from .call import max_child_gas_eip150


def return_op(computation: ComputationAPI) -> None:
    start_position, size = computation.stack_pop_ints(2)

    computation.extend_memory(start_position, size)

    computation.output = computation.memory_read_bytes(start_position, size)
    raise Halt('RETURN')


def revert(computation: ComputationAPI) -> None:
    start_position, size = computation.stack_pop_ints(2)

    computation.extend_memory(start_position, size)

    computation.output = computation.memory_read_bytes(start_position, size)
    raise Revert(computation.output)


def selfdestruct(computation: ComputationAPI) -> None:
    beneficiary = force_bytes_to_address(computation.stack_pop1_bytes())
    _selfdestruct(computation, beneficiary)


def selfdestruct_eip150(computation: ComputationAPI) -> None:
    beneficiary = force_bytes_to_address(computation.stack_pop1_bytes())
    if not computation.state.account_exists(beneficiary):
        computation.consume_gas(
            constants.GAS_SELFDESTRUCT_NEWACCOUNT,
            reason=mnemonics.SELFDESTRUCT,
        )
    _selfdestruct(computation, beneficiary)


def selfdestruct_eip161(computation: ComputationAPI) -> None:
    beneficiary = force_bytes_to_address(computation.stack_pop1_bytes())
    is_dead = (
        not computation.state.account_exists(beneficiary)
        or computation.state.account_is_empty(beneficiary)
    )
    if is_dead and computation.state.get_balance(computation.msg.storage_address):
        computation.consume_gas(
            constants.GAS_SELFDESTRUCT_NEWACCOUNT,
            reason=mnemonics.SELFDESTRUCT,
        )
    _selfdestruct(computation, beneficiary)


def _selfdestruct(computation: ComputationAPI, beneficiary: Address) -> None:
    local_balance = computation.state.get_balance(computation.msg.storage_address)
    beneficiary_balance = computation.state.get_balance(beneficiary)

    # 1st: Transfer to beneficiary
    computation.state.set_balance(beneficiary, local_balance + beneficiary_balance)
    # 2nd: Zero the balance of the address being deleted (must come after
    # sending to beneficiary in case the contract named itself as the
    # beneficiary.
    computation.state.set_balance(computation.msg.storage_address, 0)

    # 3rd: Register the account to be deleted
    computation.register_account_for_deletion(beneficiary)
    raise Halt('SELFDESTRUCT')


class CreateOpcodeStackData:

    def __init__(self,
                 endowment: int,
                 memory_start: int,
                 memory_length: int,
                 salt: int = None) -> None:

        self.endowment = endowment
        self.memory_start = memory_start
        self.memory_length = memory_length
        self.salt = salt


class Create(Opcode):

    def max_child_gas_modifier(self, gas: int) -> int:
        return gas

    def get_gas_cost(self, data: CreateOpcodeStackData) -> int:
        return self.gas_cost

    def generate_contract_address(self,
                                  stack_data: CreateOpcodeStackData,
                                  call_data: bytes,
                                  computation: ComputationAPI) -> Address:

        creation_nonce = computation.state.get_nonce(computation.msg.storage_address)
        computation.state.increment_nonce(computation.msg.storage_address)

        contract_address = generate_contract_address(
            computation.msg.storage_address,
            creation_nonce,
        )

        return contract_address

    def get_stack_data(self, computation: ComputationAPI) -> CreateOpcodeStackData:
        endowment, memory_start, memory_length = computation.stack_pop_ints(3)

        return CreateOpcodeStackData(endowment, memory_start, memory_length)

    def __call__(self, computation: ComputationAPI) -> None:

        stack_data = self.get_stack_data(computation)

        gas_cost = self.get_gas_cost(stack_data)
        computation.consume_gas(gas_cost, reason=self.mnemonic)

        computation.extend_memory(stack_data.memory_start, stack_data.memory_length)

        insufficient_funds = computation.state.get_balance(
            computation.msg.storage_address
        ) < stack_data.endowment
        stack_too_deep = computation.msg.depth + 1 > constants.STACK_DEPTH_LIMIT

        if insufficient_funds or stack_too_deep:
            computation.stack_push_int(0)
            return

        call_data = computation.memory_read_bytes(
            stack_data.memory_start, stack_data.memory_length
        )

        create_msg_gas = self.max_child_gas_modifier(
            computation.get_gas_remaining()
        )
        computation.consume_gas(create_msg_gas, reason=self.mnemonic)

        contract_address = self.generate_contract_address(stack_data, call_data, computation)

        is_collision = computation.state.has_code_or_nonce(contract_address)

        if is_collision:
            computation.stack_push_int(0)
            return

        child_msg = computation.prepare_child_message(
            gas=create_msg_gas,
            to=constants.CREATE_CONTRACT_ADDRESS,
            value=stack_data.endowment,
            data=b'',
            code=call_data,
            create_address=contract_address,
        )
        self.apply_create_message(computation, child_msg)

    def apply_create_message(self, computation: ComputationAPI, child_msg: MessageAPI) -> None:
        child_computation = computation.apply_child_computation(child_msg)

        if child_computation.is_error:
            computation.stack_push_int(0)
        else:
            computation.stack_push_bytes(child_msg.storage_address)

        computation.return_gas(child_computation.get_gas_remaining())


class CreateEIP150(Create):
    def max_child_gas_modifier(self, gas: int) -> int:
        return max_child_gas_eip150(gas)


class CreateByzantium(CreateEIP150):
    def __call__(self, computation: ComputationAPI) -> None:
        if computation.msg.is_static:
            raise WriteProtection("Cannot modify state while inside of a STATICCALL context")
        return super().__call__(computation)


class Create2(CreateByzantium):

    def get_stack_data(self, computation: ComputationAPI) -> CreateOpcodeStackData:
        endowment, memory_start, memory_length, salt = computation.stack_pop_ints(4)

        return CreateOpcodeStackData(endowment, memory_start, memory_length, salt)

    def get_gas_cost(self, data: CreateOpcodeStackData) -> int:
        return constants.GAS_CREATE + constants.GAS_SHA3WORD * ceil32(data.memory_length) // 32

    def generate_contract_address(self,
                                  stack_data: CreateOpcodeStackData,
                                  call_data: bytes,
                                  computation: ComputationAPI) -> Address:

        computation.state.increment_nonce(computation.msg.storage_address)
        return generate_safe_contract_address(
            computation.msg.storage_address,
            stack_data.salt,
            call_data
        )

    def apply_create_message(self, computation: ComputationAPI, child_msg: MessageAPI) -> None:
        # We need to ensure that creation operates on empty storage **and**
        # that if the initialization code fails that we revert the account back
        # to its original state root.
        snapshot = computation.state.snapshot()

        computation.state.delete_storage(child_msg.storage_address)

        child_computation = computation.apply_child_computation(child_msg)

        if child_computation.is_error:
            computation.state.revert(snapshot)
            computation.stack_push_int(0)
        else:
            computation.state.commit(snapshot)
            computation.stack_push_bytes(child_msg.storage_address)

        computation.return_gas(child_computation.get_gas_remaining())
