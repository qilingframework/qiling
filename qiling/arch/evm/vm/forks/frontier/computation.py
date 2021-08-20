from ...exec import EVMExecutor
from ...debug import run_debugger
from .... import precompiles
from ....constants import (
    GAS_CODEDEPOSIT,
    STACK_DEPTH_LIMIT,
)

from ...._utils.address import force_bytes_to_address
from ....abc import (
    ComputationAPI,
    MessageAPI,
    StateAPI,
    TransactionContextAPI,
)
from ....exceptions import (
    OutOfGas,
    InsufficientFunds,
    StackDepthLimit,
)
from ....vm.computation import BaseComputation
from .opcodes import FRONTIER_OPCODES


FRONTIER_PRECOMPILES = {
    force_bytes_to_address(b'\x01'): precompiles.ecrecover,
    force_bytes_to_address(b'\x02'): precompiles.sha256,
    force_bytes_to_address(b'\x03'): precompiles.ripemd160,
    force_bytes_to_address(b'\x04'): precompiles.identity,
}


class FrontierComputation(BaseComputation):
    """
    A class for all execution computations in the ``Frontier`` fork.
    Inherits from :class:`~eth.vm.computation.BaseComputation`
    """
    # Override
    opcodes = FRONTIER_OPCODES
    _precompiles = FRONTIER_PRECOMPILES     # type: ignore # https://github.com/python/mypy/issues/708 # noqa: E501

    @classmethod
    def apply_message(
            cls,
            state: StateAPI,
            message: MessageAPI,
            transaction_context: TransactionContextAPI) -> ComputationAPI:

        snapshot = state.snapshot()

        if message.depth > STACK_DEPTH_LIMIT:
            raise StackDepthLimit("Stack depth limit reached")

        if message.should_transfer_value and message.value:
            sender_balance = state.get_balance(message.sender)

            if sender_balance < message.value:
                raise InsufficientFunds(
                    f"Insufficient funds: {sender_balance} < {message.value}"
                )

            state.delta_balance(message.sender, -1 * message.value)
            state.delta_balance(message.storage_address, message.value)

        state.touch_account(message.storage_address)

        # computation = cls.apply_computation(
        #     state,
        #     message,
        #     transaction_context,
        # )
        computation = cls(state, message, transaction_context)
        executor = EVMExecutor(computation)
        computation = run_debugger(executor) if state.ql.debugger == True else executor.execute()

        if computation.is_error:
            state.revert(snapshot)
        else:
            state.commit(snapshot)

        return computation

    @classmethod
    def apply_create_message(
            cls,
            state: StateAPI,
            message: MessageAPI,
            transaction_context: TransactionContextAPI) -> ComputationAPI:

        computation = cls.apply_message(state, message, transaction_context)

        if computation.is_error:
            return computation
        else:
            contract_code = computation.output

            if contract_code:
                contract_code_gas_fee = len(contract_code) * GAS_CODEDEPOSIT
                try:
                    computation.consume_gas(
                        contract_code_gas_fee,
                        reason="Write contract code for CREATE",
                    )
                except OutOfGas:
                    computation.output = b''
                else:
                    state.set_code(message.storage_address, contract_code)
            return computation
