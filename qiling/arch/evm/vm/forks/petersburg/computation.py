from ....vm.forks.byzantium.computation import (
    BYZANTIUM_PRECOMPILES
)
from ....vm.forks.byzantium.computation import (
    ByzantiumComputation
)

from .opcodes import PETERSBURG_OPCODES

PETERSBURG_PRECOMPILES = BYZANTIUM_PRECOMPILES


class PetersburgComputation(ByzantiumComputation):
    """
    A class for all execution computations in the ``Petersburg`` fork.
    Inherits from :class:`~eth.vm.forks.byzantium.computation.ByzantiumComputation`
    """
    # Override
    opcodes = PETERSBURG_OPCODES
    _precompiles = PETERSBURG_PRECOMPILES
