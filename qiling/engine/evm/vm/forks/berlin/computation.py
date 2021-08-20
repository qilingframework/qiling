from ....vm.forks.muir_glacier.computation import (
    MUIR_GLACIER_PRECOMPILES
)
from ....vm.forks.muir_glacier.computation import (
    MuirGlacierComputation,
)

from .opcodes import BERLIN_OPCODES

BERLIN_PRECOMPILES = MUIR_GLACIER_PRECOMPILES


class BerlinComputation(MuirGlacierComputation):
    """
    A class for all execution computations in the ``Berlin`` fork.
    Inherits from :class:`~eth.vm.forks.muir_glacier.MuirGlacierComputation`
    """
    # Override
    opcodes = BERLIN_OPCODES
    _precompiles = BERLIN_PRECOMPILES
