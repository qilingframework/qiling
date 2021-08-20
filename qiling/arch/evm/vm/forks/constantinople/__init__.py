from ..byzantium import ByzantiumVM
from .state import ConstantinopleState


class ConstantinopleVM(ByzantiumVM):
    # fork name
    fork = 'constantinople'

    # classes
    _state_class = ConstantinopleState
