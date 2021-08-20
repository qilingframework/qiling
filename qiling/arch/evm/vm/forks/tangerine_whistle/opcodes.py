import copy

from eth_utils.toolz import merge

from ....vm.forks.tangerine_whistle import constants
from ....constants import GAS_CREATE
from ....vm import opcode_values
from ....vm import mnemonics
from ....vm.forks.homestead.opcodes import HOMESTEAD_OPCODES
from ....vm.logic import (
    call,
    context,
    storage,
    system,
)
from ....vm.opcode import as_opcode


UPDATED_OPCODES = {
    opcode_values.EXTCODESIZE: as_opcode(
        logic_fn=context.extcodesize,
        mnemonic=mnemonics.EXTCODESIZE,
        gas_cost=constants.GAS_EXTCODE_EIP150,
    ),
    opcode_values.EXTCODECOPY: as_opcode(
        logic_fn=context.extcodecopy,
        mnemonic=mnemonics.EXTCODECOPY,
        gas_cost=constants.GAS_EXTCODE_EIP150,
    ),
    opcode_values.BALANCE: as_opcode(
        logic_fn=context.balance,
        mnemonic=mnemonics.BALANCE,
        gas_cost=constants.GAS_BALANCE_EIP150,
    ),
    opcode_values.SLOAD: as_opcode(
        logic_fn=storage.sload,
        mnemonic=mnemonics.SLOAD,
        gas_cost=constants.GAS_SLOAD_EIP150,
    ),
    opcode_values.SELFDESTRUCT: as_opcode(
        logic_fn=system.selfdestruct_eip150,
        mnemonic=mnemonics.SELFDESTRUCT,
        gas_cost=constants.GAS_SELFDESTRUCT_EIP150,
    ),
    opcode_values.CREATE: system.CreateEIP150.configure(
        __name__='opcode:CREATE',
        mnemonic=mnemonics.CREATE,
        gas_cost=GAS_CREATE,
    )(),
    opcode_values.CALL: call.CallEIP150.configure(
        __name__='opcode:CALL',
        mnemonic=mnemonics.CALL,
        gas_cost=constants.GAS_CALL_EIP150,
    )(),
    opcode_values.CALLCODE: call.CallCodeEIP150.configure(
        __name__='opcode:CALLCODE',
        mnemonic=mnemonics.CALLCODE,
        gas_cost=constants.GAS_CALL_EIP150,
    )(),
    opcode_values.DELEGATECALL: call.DelegateCallEIP150.configure(
        __name__='opcode:DELEGATECALL',
        mnemonic=mnemonics.DELEGATECALL,
        gas_cost=constants.GAS_CALL_EIP150,
    )(),
}


TANGERINE_WHISTLE_OPCODES = merge(
    copy.deepcopy(HOMESTEAD_OPCODES),
    UPDATED_OPCODES,
)
