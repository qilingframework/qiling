from typing import Type

from ....abc import (
    ComputationAPI,
)
from ....vm.forks.frontier.state import (
    FrontierState,
    FrontierTransactionExecutor,
)

from .computation import HomesteadComputation
# from .validation import validate_homestead_transaction


class HomesteadState(FrontierState):
    computation_class: Type[ComputationAPI] = HomesteadComputation

    # def validate_transaction(self, transaction: SignedTransactionAPI) -> None:
    #     validate_homestead_transaction(self, transaction)


class HomesteadTransactionExecutor(FrontierTransactionExecutor):
    pass
