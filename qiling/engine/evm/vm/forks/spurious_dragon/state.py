from typing import Type

from eth_utils import (
    encode_hex,
)

from ....abc import (
    ComputationAPI, MessageAPI,
    TransactionExecutorAPI,
)
from ....vm.forks.homestead.state import (
    HomesteadState,
    HomesteadTransactionExecutor,
)

from .computation import SpuriousDragonComputation
from ._utils import collect_touched_accounts


class SpuriousDragonTransactionExecutor(HomesteadTransactionExecutor):
    def finalize_computation(self,
                             message: MessageAPI,
                             computation: ComputationAPI) -> ComputationAPI:
        computation = super().finalize_computation(message, computation)

        #
        # EIP161 state clearing
        #
        touched_accounts = collect_touched_accounts(computation)

        for account in touched_accounts:
            should_delete = (
                self.vm_state.account_exists(account)
                and self.vm_state.account_is_empty(account)
            )
            if should_delete:
                self.vm_state.delete_account(account)

        return computation


class SpuriousDragonState(HomesteadState):
    computation_class: Type[ComputationAPI] = SpuriousDragonComputation
    transaction_executor_class: Type[TransactionExecutorAPI] = SpuriousDragonTransactionExecutor
