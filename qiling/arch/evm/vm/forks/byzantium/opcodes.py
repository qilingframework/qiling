import copy
import functools
from typing import Dict

from eth_utils.toolz import merge

from typing import (
    Any,
    Callable,
)

from .... import constants

from ....abc import OpcodeAPI
from ....exceptions import (
    WriteProtection,
)
from ....vm import mnemonics
from ....vm import opcode_values
from ....vm.computation import BaseComputation
from ....vm.forks.tangerine_whistle.constants import (
    GAS_CALL_EIP150,
    GAS_SELFDESTRUCT_EIP150
)
from ....vm.logic import (
    call,
    context,
    logging,
    storage,
    system,
)
from ....vm.opcode import as_opcode

from ....vm.forks.spurious_dragon.opcodes import SPURIOUS_DRAGON_OPCODES


def ensure_no_static(opcode_fn: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(opcode_fn)
    def inner(computation: BaseComputation) -> Callable[..., Any]:
        if computation.msg.is_static:
            raise WriteProtection("Cannot modify state while inside of a STATICCALL context")
        return opcode_fn(computation)
    return inner


UPDATED_OPCODES = {
    opcode_values.REVERT: as_opcode(
        logic_fn=system.revert,
        mnemonic=mnemonics.REVERT,
        gas_cost=constants.GAS_ZERO,
    ),
    #
    # Context
    #
    opcode_values.RETURNDATASIZE: as_opcode(
        logic_fn=context.returndatasize,
        mnemonic=mnemonics.RETURNDATASIZE,
        gas_cost=constants.GAS_BASE,
    ),
    opcode_values.RETURNDATACOPY: as_opcode(
        logic_fn=context.returndatacopy,
        mnemonic=mnemonics.RETURNDATACOPY,
        gas_cost=constants.GAS_VERYLOW,
    ),
    #
    # Call
    #
    opcode_values.STATICCALL: call.StaticCall.configure(
        __name__='opcode:STATICCALL',
        mnemonic=mnemonics.STATICCALL,
        gas_cost=GAS_CALL_EIP150,
    )(),
    opcode_values.CALL: call.CallByzantium.configure(
        __name__='opcode:CALL',
        mnemonic=mnemonics.CALL,
        gas_cost=GAS_CALL_EIP150,
    )(),
    #
    # Logging
    #
    opcode_values.LOG0: as_opcode(
        logic_fn=ensure_no_static(logging.log0),
        mnemonic=mnemonics.LOG0,
        gas_cost=constants.GAS_LOG,
    ),
    opcode_values.LOG1: as_opcode(
        logic_fn=ensure_no_static(logging.log1),
        mnemonic=mnemonics.LOG1,
        gas_cost=constants.GAS_LOG,
    ),
    opcode_values.LOG2: as_opcode(
        logic_fn=ensure_no_static(logging.log2),
        mnemonic=mnemonics.LOG2,
        gas_cost=constants.GAS_LOG,
    ),
    opcode_values.LOG3: as_opcode(
        logic_fn=ensure_no_static(logging.log3),
        mnemonic=mnemonics.LOG3,
        gas_cost=constants.GAS_LOG,
    ),
    opcode_values.LOG4: as_opcode(
        logic_fn=ensure_no_static(logging.log4),
        mnemonic=mnemonics.LOG4,
        gas_cost=constants.GAS_LOG,
    ),
    #
    # Create
    #
    opcode_values.CREATE: system.CreateByzantium.configure(
        __name__='opcode:CREATE',
        mnemonic=mnemonics.CREATE,
        gas_cost=constants.GAS_CREATE,
    )(),
    #
    # Storage
    #
    opcode_values.SSTORE: as_opcode(
        logic_fn=ensure_no_static(storage.sstore),
        mnemonic=mnemonics.SSTORE,
        gas_cost=constants.GAS_NULL,
    ),
    #
    # Self Destruct
    #
    opcode_values.SELFDESTRUCT: as_opcode(
        logic_fn=ensure_no_static(system.selfdestruct_eip161),
        mnemonic=mnemonics.SELFDESTRUCT,
        gas_cost=GAS_SELFDESTRUCT_EIP150,
    ),
}


BYZANTIUM_OPCODES: Dict[int, OpcodeAPI] = merge(
    copy.deepcopy(SPURIOUS_DRAGON_OPCODES),
    UPDATED_OPCODES,
)
