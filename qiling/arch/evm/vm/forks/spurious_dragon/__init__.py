# from typing import Type

# from ....abc import (
#     BlockAPI,
#     StateAPI,
# )

from ..tangerine_whistle import TangerineWhistleVM

# from .blocks import SpuriousDragonBlock
from .state import SpuriousDragonState


class SpuriousDragonVM(TangerineWhistleVM):
    # fork name
    fork: str = 'spurious-dragon'  # noqa: E701  # flake8 bug that's fixed in 3.6.0+

    # classes
    # block_class: Type[BlockAPI] = SpuriousDragonBlock
    _state_class = SpuriousDragonState
