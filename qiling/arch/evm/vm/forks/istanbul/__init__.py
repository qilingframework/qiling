from ..constantinople import ConstantinopleVM
from .state import IstanbulState


class IstanbulVM(ConstantinopleVM):
    # fork name
    fork = 'istanbul'

    # classes
    _state_class = IstanbulState
