import copy
from typing import Dict

from eth_utils.toolz import merge

from ....vm.forks.muir_glacier.opcodes import (
    MUIR_GLACIER_OPCODES,
)
from ....vm.opcode import Opcode


UPDATED_OPCODES: Dict[int, Opcode] = {
    # New opcodes
}

BERLIN_OPCODES = merge(
    copy.deepcopy(MUIR_GLACIER_OPCODES),
    UPDATED_OPCODES,
)
