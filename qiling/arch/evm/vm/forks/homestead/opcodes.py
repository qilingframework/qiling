import copy
from typing import Dict

from eth_utils.toolz import merge

from .... import constants
from ....abc import OpcodeAPI
from ....vm import mnemonics
from ....vm import opcode_values
from ....vm.logic import (
    call,
)

from ....vm.forks.frontier.opcodes import FRONTIER_OPCODES


NEW_OPCODES = {
    opcode_values.DELEGATECALL: call.DelegateCall.configure(
        __name__='opcode:DELEGATECALL',
        mnemonic=mnemonics.DELEGATECALL,
        gas_cost=constants.GAS_CALL,
    )(),
}


HOMESTEAD_OPCODES: Dict[int, OpcodeAPI] = merge(
    copy.deepcopy(FRONTIER_OPCODES),
    NEW_OPCODES
)
