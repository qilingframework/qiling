from ...vm import BaseVM
from .state import FrontierState

class FrontierVM(BaseVM):
    # fork name
    fork: str = 'frontier'  # noqa: E701  # flake8 bug that's fixed in 3.6.0+

    # classes
    _state_class = FrontierState

