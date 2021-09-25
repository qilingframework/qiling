import copy

from eth_utils.toolz import merge

from .... import constants
from ....vm import (
    mnemonics,
    opcode_values,
)
from ....vm.forks.byzantium.opcodes import (
    ensure_no_static
)
from ....vm.forks.petersburg.opcodes import (
    PETERSBURG_OPCODES,
)
from ....vm.forks.istanbul.constants import (
    GAS_BALANCE_EIP1884,
    GAS_SLOAD_EIP1884,
    GAS_EXTCODEHASH_EIP1884,
)
from ....vm.logic import (
    context,
    storage,
)
from ....vm.opcode import as_opcode
from .storage import (
    sstore_eip2200,
)


UPDATED_OPCODES = {
    # New opcodes
    opcode_values.CHAINID: as_opcode(
        logic_fn=context.chain_id,
        mnemonic=mnemonics.CHAINID,
        gas_cost=constants.GAS_BASE,
    ),
    opcode_values.SELFBALANCE: as_opcode(
        logic_fn=context.selfbalance,
        mnemonic=mnemonics.SELFBALANCE,
        gas_cost=constants.GAS_LOW,
    ),

    # Repriced opcodes
    opcode_values.SSTORE: as_opcode(
        logic_fn=ensure_no_static(sstore_eip2200),
        mnemonic=mnemonics.SSTORE,
        gas_cost=constants.GAS_NULL,
    ),
    opcode_values.BALANCE: as_opcode(
        logic_fn=context.balance,
        mnemonic=mnemonics.BALANCE,
        gas_cost=GAS_BALANCE_EIP1884,
    ),
    opcode_values.SLOAD: as_opcode(
        logic_fn=storage.sload,
        mnemonic=mnemonics.SLOAD,
        gas_cost=GAS_SLOAD_EIP1884,
    ),
    opcode_values.EXTCODEHASH: as_opcode(
        logic_fn=context.extcodehash,
        mnemonic=mnemonics.EXTCODEHASH,
        gas_cost=GAS_EXTCODEHASH_EIP1884,
    ),
}

ISTANBUL_OPCODES = merge(
    copy.deepcopy(PETERSBURG_OPCODES),
    UPDATED_OPCODES,
)
