# from typing import Type

# from ....abc import StateAPI
from ..homestead import HomesteadVM

from .state import TangerineWhistleState


class TangerineWhistleVM(HomesteadVM):
    # fork name
    fork: str = 'tangerine-whistle'  # noqa

    # classes
    _state_class= TangerineWhistleState

#     # Don't bother with any DAO logic in Tangerine VM or later
#     # This is how we skip DAO logic on Ropsten, for example
#     support_dao_fork = False
