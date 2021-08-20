from ....vm.forks.byzantium.state import (
    ByzantiumState
)

from .computation import ConstantinopleComputation


class ConstantinopleState(ByzantiumState):
    computation_class = ConstantinopleComputation
