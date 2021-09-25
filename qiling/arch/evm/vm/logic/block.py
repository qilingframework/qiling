#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from ...vm.computation import BaseComputation


def blockhash(computation: BaseComputation) -> None:
    block_number = computation.stack_pop1_int()

    block_hash = computation.state.get_ancestor_hash(block_number)

    computation.stack_push_bytes(block_hash)


def coinbase(computation: BaseComputation) -> None:
    computation.stack_push_bytes(computation.state.coinbase)


def timestamp(computation: BaseComputation) -> None:
    computation.stack_push_int(computation.state.timestamp)


def number(computation: BaseComputation) -> None:
    computation.stack_push_int(computation.state.block_number)


def difficulty(computation: BaseComputation) -> None:
    computation.stack_push_int(computation.state.difficulty)


def gaslimit(computation: BaseComputation) -> None:
    computation.stack_push_int(computation.state.gas_limit)
