from ....vm.forks.petersburg.state import (
    PetersburgState
)

from .computation import IstanbulComputation


class IstanbulState(PetersburgState):
    computation_class = IstanbulComputation
