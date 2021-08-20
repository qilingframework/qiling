from ....vm.forks.istanbul.state import (
    IstanbulState
)

from .computation import MuirGlacierComputation


class MuirGlacierState(IstanbulState):
    computation_class = MuirGlacierComputation
