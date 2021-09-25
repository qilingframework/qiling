from ....vm.forks.muir_glacier.state import (
    MuirGlacierState
)

from .computation import BerlinComputation


class BerlinState(MuirGlacierState):
    computation_class = BerlinComputation
