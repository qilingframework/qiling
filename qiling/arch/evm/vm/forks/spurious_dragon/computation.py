from eth_hash.auto import keccak
from eth_utils import (
    encode_hex,
)

from .... import constants
from ....abc import (
    ComputationAPI,
    MessageAPI,
    StateAPI,
    TransactionContextAPI,
)
from ....exceptions import (
    OutOfGas,
)
from ....vm.forks.homestead.computation import (
    HomesteadComputation,
)

from .constants import EIP170_CODE_SIZE_LIMIT
from .opcodes import SPURIOUS_DRAGON_OPCODES


class SpuriousDragonComputation(HomesteadComputation):
    """
    A class for all execution computations in the ``SpuriousDragon`` fork.
    Inherits from :class:`~eth.vm.forks.homestead.computation.HomesteadComputation`
    """
    # Override
    opcodes = SPURIOUS_DRAGON_OPCODES

    @classmethod
    def apply_create_message(
            cls,
            state: StateAPI,
            message: MessageAPI,
            transaction_context: TransactionContextAPI) -> ComputationAPI:

        snapshot = state.snapshot()

        # EIP161 nonce incrementation
        state.increment_nonce(message.storage_address)

        computation = cls.apply_message(state, message, transaction_context)

        if computation.is_error:
            state.revert(snapshot)
            return computation
        else:
            contract_code = computation.output

            if contract_code and len(contract_code) >= EIP170_CODE_SIZE_LIMIT:
                computation.error = OutOfGas(
                    f"Contract code size exceeds EIP170 limit of {EIP170_CODE_SIZE_LIMIT}."
                    f"  Got code of size: {len(contract_code)}"
                )
                state.revert(snapshot)
            elif contract_code:
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
