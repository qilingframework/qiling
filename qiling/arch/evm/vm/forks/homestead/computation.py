from eth_hash.auto import keccak

from .... import constants
from ....exceptions import (
    OutOfGas,
)
from eth_utils import (
    encode_hex,
)

from ....abc import (
    ComputationAPI,
    MessageAPI,
    StateAPI,
    TransactionContextAPI,
)
from ....vm.forks.frontier.computation import (
    FrontierComputation,
)

from .opcodes import HOMESTEAD_OPCODES


class HomesteadComputation(FrontierComputation):
    """
    A class for all execution computations in the ``Frontier`` fork.
    Inherits from :class:`~eth.vm.forks.frontier.computation.FrontierComputation`
    """
    # Override
    opcodes = HOMESTEAD_OPCODES

    @classmethod
    def apply_create_message(
            cls,
            state: StateAPI,
            message: MessageAPI,
            transaction_context: TransactionContextAPI) -> ComputationAPI:
        snapshot = state.snapshot()

        computation = cls.apply_message(state, message, transaction_context)

        if computation.is_error:
            state.revert(snapshot)
            return computation
        else:
            contract_code = computation.output

            if contract_code:
                contract_code_gas_cost = len(contract_code) * constants.GAS_CODEDEPOSIT
                try:
                    computation.consume_gas(
                        contract_code_gas_cost,
                        reason="Write contract code for CREATE",
                    )
                except OutOfGas as err:
                    # Different from Frontier: reverts state on gas failure while
                    # writing contract code.
                    computation.error = err
                    state.revert(snapshot)
                else:
                    state.set_code(message.storage_address, contract_code)
                    state.commit(snapshot)
            else:
                state.commit(snapshot)
            return computation
