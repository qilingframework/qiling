from ...utils import bytecode_to_bytes, runtime_code_detector
from ...._utils.transactions import calculate_intrinsic_gas
from typing import Type

from eth_typing.evm import Address
from eth_utils import encode_hex
from ....abc import (
    AccountDatabaseAPI,
    ComputationAPI,
    MessageAPI,
    TransactionContextAPI,
    TransactionExecutorAPI,
)
from ....constants import CREATE_CONTRACT_ADDRESS
from ....db.account import AccountDB
from ....exceptions import ContractCreationCollision
from ...._utils.address import generate_contract_address
from ....vm.message import Message
from ....vm.state import BaseState, BaseTransactionExecutor
from .computation import FrontierComputation
from .constants import FRONTIER_TX_GAS_SCHEDULE, REFUND_SELFDESTRUCT
from .transaction_context import FrontierTransactionContext


class FrontierTransactionExecutor(BaseTransactionExecutor):
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

        if origin is None:
            origin = sender
        
        gas_fee = gas_price * gas
        self.vm_state.delta_balance(sender, -1 * gas_fee)
        self.vm_state.increment_nonce(sender)


        message_gas = gas - calculate_intrinsic_gas(data, to, FRONTIER_TX_GAS_SCHEDULE)

        if to == CREATE_CONTRACT_ADDRESS and contract_address is None:
            contract_address = generate_contract_address(
                sender,
                self.vm_state.get_nonce(sender),
            )
        # elif to != CREATE_CONTRACT_ADDRESS and self.vm_state.get_code(to) != b'':
        #     contract_address = to
        #     auxcode = self.vm_state.get_code(to)
        #     rtcode, _, _ = runtime_code_detector(bytecode_to_bytes(auxcode))
        #     code = bytecode_to_bytes(rtcode)

        message = Message(
            gas=message_gas,
            to=to,
            sender=sender,
            value=value,
            data=data,
            code=code,
            code_address=code_address,
            create_address=contract_address,
            gas_price=gas_price
        )

        return message

    def build_computation(self,
                          message: MessageAPI) -> ComputationAPI:
        transaction_context = self.vm_state.get_transaction_context(message)
        if message.is_create:
            is_collision = self.vm_state.has_code_or_nonce(
                message.storage_address
            )

            if is_collision:
                # The address of the newly created contract has *somehow* collided
                # with an existing contract address.
                computation = self.vm_state.get_computation(message, transaction_context)
                computation.error = ContractCreationCollision(
                    f"Address collision while creating contract: "
                    f"{encode_hex(message.storage_address)}"
                )
            else:
                computation = self.vm_state.computation_class.apply_create_message(
                    self.vm_state,
                    message,
                    transaction_context,
                )
        else:
            computation = self.vm_state.computation_class.apply_message(
                self.vm_state,
                message,
                transaction_context,
            )

        return computation

    def finalize_computation(self,
                             message: MessageAPI,
                             computation: ComputationAPI) -> ComputationAPI:
        # Self Destruct Refunds
        num_deletions = len(computation.get_accounts_for_deletion())
        if num_deletions:
            computation.refund_gas(REFUND_SELFDESTRUCT * num_deletions)
        
        # Gas Refunds
        gas_remaining = computation.get_gas_remaining()
        gas_refunded = computation.get_gas_refund()
        gas_used = message.gas - gas_remaining
        gas_refund = min(gas_refunded, gas_used // 2)
        gas_refund_amount = (gas_refund + gas_remaining) * message.gas_price

        if gas_refund_amount:
            self.vm_state.delta_balance(computation.msg.sender, gas_refund_amount)

        # Miner Fees
        transaction_fee = \
            (message.gas - gas_remaining - gas_refund) * message.gas_price
        self.vm_state.delta_balance(self.vm_state.coinbase, transaction_fee)

        # Process Self Destructs
        for account, _ in computation.get_accounts_for_deletion():
            # TODO: need to figure out how we prevent multiple selfdestructs from
            # the same account and if this is the right place to put this.

            # TODO: this balance setting is likely superflous and can be
            # removed since `delete_account` does this.
            self.vm_state.set_balance(account, 0)
            self.vm_state.delete_account(account)

        return computation


class FrontierState(BaseState):
    computation_class: Type[ComputationAPI] = FrontierComputation
    transaction_context_class: Type[TransactionContextAPI] = FrontierTransactionContext
    account_db_class: Type[AccountDatabaseAPI] = AccountDB
    transaction_executor_class: Type[TransactionExecutorAPI] = FrontierTransactionExecutor
