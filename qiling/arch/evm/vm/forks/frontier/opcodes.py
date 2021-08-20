from typing import Dict

from .... import constants

from ....abc import OpcodeAPI
from ....vm import mnemonics
from ....vm import opcode_values
from ....vm.logic import (
    arithmetic,
    block,
    call,
    comparison,
    context,
    duplication,
    flow,
    logging,
    memory,
    sha3,
    stack,
    storage,
    swap,
    system,
)
from ....vm.opcode import (
    as_opcode,
)


FRONTIER_OPCODES: Dict[int, OpcodeAPI] = {
    #
    # Arithmetic
    #
    opcode_values.STOP: as_opcode(
        logic_fn=flow.stop,
        mnemonic=mnemonics.STOP,
        gas_cost=constants.GAS_ZERO,
    ),
    opcode_values.ADD: as_opcode(
        logic_fn=arithmetic.add,
        mnemonic=mnemonics.ADD,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.MUL: as_opcode(
        logic_fn=arithmetic.mul,
        mnemonic=mnemonics.MUL,
        gas_cost=constants.GAS_LOW,
    ),
    opcode_values.SUB: as_opcode(
        logic_fn=arithmetic.sub,
        mnemonic=mnemonics.SUB,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.DIV: as_opcode(
        logic_fn=arithmetic.div,
        mnemonic=mnemonics.DIV,
        gas_cost=constants.GAS_LOW,
    ),
    opcode_values.SDIV: as_opcode(
        logic_fn=arithmetic.sdiv,
        mnemonic=mnemonics.SDIV,
        gas_cost=constants.GAS_LOW,
    ),
    opcode_values.MOD: as_opcode(
        logic_fn=arithmetic.mod,
        mnemonic=mnemonics.MOD,
        gas_cost=constants.GAS_LOW,
    ),
    opcode_values.SMOD: as_opcode(
        logic_fn=arithmetic.smod,
        mnemonic=mnemonics.SMOD,
        gas_cost=constants.GAS_LOW,
    ),
    opcode_values.ADDMOD: as_opcode(
        logic_fn=arithmetic.addmod,
        mnemonic=mnemonics.ADDMOD,
        gas_cost=constants.GAS_MID,
    ),
    opcode_values.MULMOD: as_opcode(
        logic_fn=arithmetic.mulmod,
        mnemonic=mnemonics.MULMOD,
        gas_cost=constants.GAS_MID,
    ),
    opcode_values.EXP: as_opcode(
        logic_fn=arithmetic.exp(gas_per_byte=constants.GAS_EXPBYTE),
        mnemonic=mnemonics.EXP,
        gas_cost=constants.GAS_EXP,
    ),
    opcode_values.SIGNEXTEND: as_opcode(
        logic_fn=arithmetic.signextend,
        mnemonic=mnemonics.SIGNEXTEND,
        gas_cost=constants.GAS_LOW,
    ),
    #
    # Comparisons
    #
    opcode_values.LT: as_opcode(
        logic_fn=comparison.lt,
        mnemonic=mnemonics.LT,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.GT: as_opcode(
        logic_fn=comparison.gt,
        mnemonic=mnemonics.GT,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SLT: as_opcode(
        logic_fn=comparison.slt,
        mnemonic=mnemonics.SLT,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SGT: as_opcode(
        logic_fn=comparison.sgt,
        mnemonic=mnemonics.SGT,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.EQ: as_opcode(
        logic_fn=comparison.eq,
        mnemonic=mnemonics.EQ,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.ISZERO: as_opcode(
        logic_fn=comparison.iszero,
        mnemonic=mnemonics.ISZERO,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.AND: as_opcode(
        logic_fn=comparison.and_op,
        mnemonic=mnemonics.AND,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.OR: as_opcode(
        logic_fn=comparison.or_op,
        mnemonic=mnemonics.OR,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.XOR: as_opcode(
        logic_fn=comparison.xor,
        mnemonic=mnemonics.XOR,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.NOT: as_opcode(
        logic_fn=comparison.not_op,
        mnemonic=mnemonics.NOT,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.BYTE: as_opcode(
        logic_fn=comparison.byte_op,
        mnemonic=mnemonics.BYTE,
        gas_cost=constants.GAS_VERYLOW,
    ),
    #
    # Sha3
    #
    opcode_values.SHA3: as_opcode(
        logic_fn=sha3.sha3,
        mnemonic=mnemonics.SHA3,
        gas_cost=constants.GAS_SHA3,
    ),
    #
    # Environment Information
    #
    opcode_values.ADDRESS: as_opcode(
        logic_fn=context.address,
        mnemonic=mnemonics.ADDRESS,
        gas_cost=constants.GAS_BASE,
    ),
    opcode_values.BALANCE: as_opcode(
        logic_fn=context.balance,
        mnemonic=mnemonics.BALANCE,
        gas_cost=constants.GAS_BALANCE,
    ),
    opcode_values.ORIGIN: as_opcode(
        logic_fn=context.origin,
        mnemonic=mnemonics.ORIGIN,
        gas_cost=constants.GAS_BASE,
    ),
    opcode_values.CALLER: as_opcode(
        logic_fn=context.caller,
        mnemonic=mnemonics.CALLER,
        gas_cost=constants.GAS_BASE,
    ),
    opcode_values.CALLVALUE: as_opcode(
        logic_fn=context.callvalue,
        mnemonic=mnemonics.CALLVALUE,
        gas_cost=constants.GAS_BASE,
    ),
    opcode_values.CALLDATALOAD: as_opcode(
        logic_fn=context.calldataload,
        mnemonic=mnemonics.CALLDATALOAD,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.CALLDATASIZE: as_opcode(
        logic_fn=context.calldatasize,
        mnemonic=mnemonics.CALLDATASIZE,
        gas_cost=constants.GAS_BASE,
    ),
    opcode_values.CALLDATACOPY: as_opcode(
        logic_fn=context.calldatacopy,
        mnemonic=mnemonics.CALLDATACOPY,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.CODESIZE: as_opcode(
        logic_fn=context.codesize,
        mnemonic=mnemonics.CODESIZE,
        gas_cost=constants.GAS_BASE,
    ),
    opcode_values.CODECOPY: as_opcode(
        logic_fn=context.codecopy,
        mnemonic=mnemonics.CODECOPY,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.GASPRICE: as_opcode(
        logic_fn=context.gasprice,
        mnemonic=mnemonics.GASPRICE,
        gas_cost=constants.GAS_BASE,
    ),
    opcode_values.EXTCODESIZE: as_opcode(
        logic_fn=context.extcodesize,
        mnemonic=mnemonics.EXTCODESIZE,
        gas_cost=constants.GAS_EXTCODE,
    ),
    opcode_values.EXTCODECOPY: as_opcode(
        logic_fn=context.extcodecopy,
        mnemonic=mnemonics.EXTCODECOPY,
        gas_cost=constants.GAS_EXTCODE,
    ),
    #
    # Block Information
    #
    opcode_values.BLOCKHASH: as_opcode(
        logic_fn=block.blockhash,
        mnemonic=mnemonics.BLOCKHASH,
        gas_cost=constants.GAS_BLOCKHASH,
    ),
    opcode_values.COINBASE: as_opcode(
        logic_fn=block.coinbase,
        mnemonic=mnemonics.COINBASE,
        gas_cost=constants.GAS_BASE,
    ),
    opcode_values.TIMESTAMP: as_opcode(
        logic_fn=block.timestamp,
        mnemonic=mnemonics.TIMESTAMP,
        gas_cost=constants.GAS_BASE,
    ),
    opcode_values.NUMBER: as_opcode(
        logic_fn=block.number,
        mnemonic=mnemonics.NUMBER,
        gas_cost=constants.GAS_BASE,
    ),
    opcode_values.DIFFICULTY: as_opcode(
        logic_fn=block.difficulty,
        mnemonic=mnemonics.DIFFICULTY,
        gas_cost=constants.GAS_BASE,
    ),
    opcode_values.GASLIMIT: as_opcode(
        logic_fn=block.gaslimit,
        mnemonic=mnemonics.GASLIMIT,
        gas_cost=constants.GAS_BASE,
    ),
    #
    # Stack, Memory, Storage and Flow Operations
    #
    opcode_values.POP: as_opcode(
        logic_fn=stack.pop,
        mnemonic=mnemonics.POP,
        gas_cost=constants.GAS_BASE,
    ),
    opcode_values.MLOAD: as_opcode(
        logic_fn=memory.mload,
        mnemonic=mnemonics.MLOAD,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.MSTORE: as_opcode(
        logic_fn=memory.mstore,
        mnemonic=mnemonics.MSTORE,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.MSTORE8: as_opcode(
        logic_fn=memory.mstore8,
        mnemonic=mnemonics.MSTORE8,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SLOAD: as_opcode(
        logic_fn=storage.sload,
        mnemonic=mnemonics.SLOAD,
        gas_cost=constants.GAS_SLOAD,
    ),
    opcode_values.SSTORE: as_opcode(
        logic_fn=storage.sstore,
        mnemonic=mnemonics.SSTORE,
        gas_cost=constants.GAS_NULL,
    ),
    opcode_values.JUMP: as_opcode(
        logic_fn=flow.jump,
        mnemonic=mnemonics.JUMP,
        gas_cost=constants.GAS_MID,
    ),
    opcode_values.JUMPI: as_opcode(
        logic_fn=flow.jumpi,
        mnemonic=mnemonics.JUMPI,
        gas_cost=constants.GAS_HIGH,
    ),
    opcode_values.PC: as_opcode(
        logic_fn=flow.program_counter,
        mnemonic=mnemonics.PC,
        gas_cost=constants.GAS_BASE,
    ),
    opcode_values.MSIZE: as_opcode(
        logic_fn=memory.msize,
        mnemonic=mnemonics.MSIZE,
        gas_cost=constants.GAS_BASE,
    ),
    opcode_values.GAS: as_opcode(
        logic_fn=flow.gas,
        mnemonic=mnemonics.GAS,
        gas_cost=constants.GAS_BASE,
    ),
    opcode_values.JUMPDEST: as_opcode(
        logic_fn=flow.jumpdest,
        mnemonic=mnemonics.JUMPDEST,
        gas_cost=constants.GAS_JUMPDEST,
    ),
    #
    # Push Operations
    #
    opcode_values.PUSH1: as_opcode(
        logic_fn=stack.push1,
        mnemonic=mnemonics.PUSH1,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH2: as_opcode(
        logic_fn=stack.push2,
        mnemonic=mnemonics.PUSH2,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH3: as_opcode(
        logic_fn=stack.push3,
        mnemonic=mnemonics.PUSH3,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH4: as_opcode(
        logic_fn=stack.push4,
        mnemonic=mnemonics.PUSH4,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH5: as_opcode(
        logic_fn=stack.push5,
        mnemonic=mnemonics.PUSH5,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH6: as_opcode(
        logic_fn=stack.push6,
        mnemonic=mnemonics.PUSH6,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH7: as_opcode(
        logic_fn=stack.push7,
        mnemonic=mnemonics.PUSH7,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH8: as_opcode(
        logic_fn=stack.push8,
        mnemonic=mnemonics.PUSH8,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH9: as_opcode(
        logic_fn=stack.push9,
        mnemonic=mnemonics.PUSH9,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH10: as_opcode(
        logic_fn=stack.push10,
        mnemonic=mnemonics.PUSH10,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH11: as_opcode(
        logic_fn=stack.push11,
        mnemonic=mnemonics.PUSH11,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH12: as_opcode(
        logic_fn=stack.push12,
        mnemonic=mnemonics.PUSH12,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH13: as_opcode(
        logic_fn=stack.push13,
        mnemonic=mnemonics.PUSH13,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH14: as_opcode(
        logic_fn=stack.push14,
        mnemonic=mnemonics.PUSH14,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH15: as_opcode(
        logic_fn=stack.push15,
        mnemonic=mnemonics.PUSH15,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH16: as_opcode(
        logic_fn=stack.push16,
        mnemonic=mnemonics.PUSH16,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH17: as_opcode(
        logic_fn=stack.push17,
        mnemonic=mnemonics.PUSH17,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH18: as_opcode(
        logic_fn=stack.push18,
        mnemonic=mnemonics.PUSH18,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH19: as_opcode(
        logic_fn=stack.push19,
        mnemonic=mnemonics.PUSH19,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH20: as_opcode(
        logic_fn=stack.push20,
        mnemonic=mnemonics.PUSH20,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH21: as_opcode(
        logic_fn=stack.push21,
        mnemonic=mnemonics.PUSH21,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH22: as_opcode(
        logic_fn=stack.push22,
        mnemonic=mnemonics.PUSH22,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH23: as_opcode(
        logic_fn=stack.push23,
        mnemonic=mnemonics.PUSH23,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH24: as_opcode(
        logic_fn=stack.push24,
        mnemonic=mnemonics.PUSH24,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH25: as_opcode(
        logic_fn=stack.push25,
        mnemonic=mnemonics.PUSH25,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH26: as_opcode(
        logic_fn=stack.push26,
        mnemonic=mnemonics.PUSH26,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH27: as_opcode(
        logic_fn=stack.push27,
        mnemonic=mnemonics.PUSH27,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH28: as_opcode(
        logic_fn=stack.push28,
        mnemonic=mnemonics.PUSH28,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH29: as_opcode(
        logic_fn=stack.push29,
        mnemonic=mnemonics.PUSH29,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH30: as_opcode(
        logic_fn=stack.push30,
        mnemonic=mnemonics.PUSH30,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH31: as_opcode(
        logic_fn=stack.push31,
        mnemonic=mnemonics.PUSH31,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.PUSH32: as_opcode(
        logic_fn=stack.push32,
        mnemonic=mnemonics.PUSH32,
        gas_cost=constants.GAS_VERYLOW,
    ),
    #
    # Duplicate Operations
    #
    opcode_values.DUP1: as_opcode(
        logic_fn=duplication.dup1,
        mnemonic=mnemonics.DUP1,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.DUP2: as_opcode(
        logic_fn=duplication.dup2,
        mnemonic=mnemonics.DUP2,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.DUP3: as_opcode(
        logic_fn=duplication.dup3,
        mnemonic=mnemonics.DUP3,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.DUP4: as_opcode(
        logic_fn=duplication.dup4,
        mnemonic=mnemonics.DUP4,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.DUP5: as_opcode(
        logic_fn=duplication.dup5,
        mnemonic=mnemonics.DUP5,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.DUP6: as_opcode(
        logic_fn=duplication.dup6,
        mnemonic=mnemonics.DUP6,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.DUP7: as_opcode(
        logic_fn=duplication.dup7,
        mnemonic=mnemonics.DUP7,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.DUP8: as_opcode(
        logic_fn=duplication.dup8,
        mnemonic=mnemonics.DUP8,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.DUP9: as_opcode(
        logic_fn=duplication.dup9,
        mnemonic=mnemonics.DUP9,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.DUP10: as_opcode(
        logic_fn=duplication.dup10,
        mnemonic=mnemonics.DUP10,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.DUP11: as_opcode(
        logic_fn=duplication.dup11,
        mnemonic=mnemonics.DUP11,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.DUP12: as_opcode(
        logic_fn=duplication.dup12,
        mnemonic=mnemonics.DUP12,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.DUP13: as_opcode(
        logic_fn=duplication.dup13,
        mnemonic=mnemonics.DUP13,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.DUP14: as_opcode(
        logic_fn=duplication.dup14,
        mnemonic=mnemonics.DUP14,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.DUP15: as_opcode(
        logic_fn=duplication.dup15,
        mnemonic=mnemonics.DUP15,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.DUP16: as_opcode(
        logic_fn=duplication.dup16,
        mnemonic=mnemonics.DUP16,
        gas_cost=constants.GAS_VERYLOW,
    ),
    #
    # Exchange Operations
    #
    opcode_values.SWAP1: as_opcode(
        logic_fn=swap.swap1,
        mnemonic=mnemonics.SWAP1,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SWAP2: as_opcode(
        logic_fn=swap.swap2,
        mnemonic=mnemonics.SWAP2,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SWAP3: as_opcode(
        logic_fn=swap.swap3,
        mnemonic=mnemonics.SWAP3,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SWAP4: as_opcode(
        logic_fn=swap.swap4,
        mnemonic=mnemonics.SWAP4,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SWAP5: as_opcode(
        logic_fn=swap.swap5,
        mnemonic=mnemonics.SWAP5,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SWAP6: as_opcode(
        logic_fn=swap.swap6,
        mnemonic=mnemonics.SWAP6,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SWAP7: as_opcode(
        logic_fn=swap.swap7,
        mnemonic=mnemonics.SWAP7,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SWAP8: as_opcode(
        logic_fn=swap.swap8,
        mnemonic=mnemonics.SWAP8,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SWAP9: as_opcode(
        logic_fn=swap.swap9,
        mnemonic=mnemonics.SWAP9,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SWAP10: as_opcode(
        logic_fn=swap.swap10,
        mnemonic=mnemonics.SWAP10,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SWAP11: as_opcode(
        logic_fn=swap.swap11,
        mnemonic=mnemonics.SWAP11,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SWAP12: as_opcode(
        logic_fn=swap.swap12,
        mnemonic=mnemonics.SWAP12,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SWAP13: as_opcode(
        logic_fn=swap.swap13,
        mnemonic=mnemonics.SWAP13,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SWAP14: as_opcode(
        logic_fn=swap.swap14,
        mnemonic=mnemonics.SWAP14,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SWAP15: as_opcode(
        logic_fn=swap.swap15,
        mnemonic=mnemonics.SWAP15,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SWAP16: as_opcode(
        logic_fn=swap.swap16,
        mnemonic=mnemonics.SWAP16,
        gas_cost=constants.GAS_VERYLOW,
    ),
    #
    # Logging
    #
    opcode_values.LOG0: as_opcode(
        logic_fn=logging.log0,
        mnemonic=mnemonics.LOG0,
        gas_cost=constants.GAS_LOG,
    ),
    opcode_values.LOG1: as_opcode(
        logic_fn=logging.log1,
        mnemonic=mnemonics.LOG1,
        gas_cost=constants.GAS_LOG,
    ),
    opcode_values.LOG2: as_opcode(
        logic_fn=logging.log2,
        mnemonic=mnemonics.LOG2,
        gas_cost=constants.GAS_LOG,
    ),
    opcode_values.LOG3: as_opcode(
        logic_fn=logging.log3,
        mnemonic=mnemonics.LOG3,
        gas_cost=constants.GAS_LOG,
    ),
    opcode_values.LOG4: as_opcode(
        logic_fn=logging.log4,
        mnemonic=mnemonics.LOG4,
        gas_cost=constants.GAS_LOG,
    ),
    #
    # System
    #
    opcode_values.CREATE: system.Create.configure(
        __name__='opcode:CREATE',
        mnemonic=mnemonics.CREATE,
        gas_cost=constants.GAS_CREATE,
    )(),
    opcode_values.CALL: call.Call.configure(
        __name__='opcode:CALL',
        mnemonic=mnemonics.CALL,
        gas_cost=constants.GAS_CALL,
    )(),
    opcode_values.CALLCODE: call.CallCode.configure(
        __name__='opcode:CALLCODE',
        mnemonic=mnemonics.CALLCODE,
        gas_cost=constants.GAS_CALL,
    )(),
    opcode_values.RETURN: as_opcode(
        logic_fn=system.return_op,
        mnemonic=mnemonics.RETURN,
        gas_cost=constants.GAS_ZERO,
    ),
    opcode_values.SELFDESTRUCT: as_opcode(
        logic_fn=system.selfdestruct,
        mnemonic=mnemonics.SELFDESTRUCT,
        gas_cost=constants.GAS_SELFDESTRUCT,
    ),
}
