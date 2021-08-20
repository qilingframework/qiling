from ..istanbul import IstanbulVM
from .state import MuirGlacierState


class MuirGlacierVM(IstanbulVM):
    # fork name
    fork = 'muir-glacier'

    # classes
    _state_class = MuirGlacierState
