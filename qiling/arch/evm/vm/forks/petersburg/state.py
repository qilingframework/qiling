from ....vm.forks.byzantium.state import (
    ByzantiumState
)

from .computation import PetersburgComputation


class PetersburgState(ByzantiumState):
    computation_class = PetersburgComputation
