from ..muir_glacier import MuirGlacierVM
from .state import BerlinState


class BerlinVM(MuirGlacierVM):
    # fork name
    fork = 'berlin'

    # classes
    _state_class = BerlinState
