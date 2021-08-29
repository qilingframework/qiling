# from typing import (
#     Type,
# )

# from ....abc import (
#     StateAPI,
#     BlockAPI,
# )
from ..byzantium import ByzantiumVM
#     get_uncle_reward,
# )

# from .blocks import PetersburgBlock
# from .constants import EIP1234_BLOCK_REWARD
# from .headers import (
#     compute_petersburg_difficulty,
#     configure_petersburg_header,
#     create_petersburg_header_from_parent,
# )
from .state import PetersburgState


class PetersburgVM(ByzantiumVM):
    # fork name
    fork = 'petersburg'

    # classes
    # block_class: Type[BlockAPI] = PetersburgBlock
    _state_class = PetersburgState

#     # Methods
#     create_header_from_parent = staticmethod(create_petersburg_header_from_parent)  # type: ignore
#     compute_difficulty = staticmethod(compute_petersburg_difficulty)    # type: ignore
#     configure_header = configure_petersburg_header
#     get_uncle_reward = staticmethod(get_uncle_reward(EIP1234_BLOCK_REWARD))

#     @staticmethod
#     def get_block_reward() -> int:
#         return EIP1234_BLOCK_REWARD
