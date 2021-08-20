from ..frontier import FrontierVM
from .state import HomesteadState

class HomesteadVM(FrontierVM):
    # fork name
    fork: str = 'homestead'  # noqa: E701  # flake8 bug that's fixed in 3.6.0+

    # classes
    _state_class = HomesteadState
