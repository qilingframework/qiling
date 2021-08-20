from eth_typing import (
    Address
)
from ....constants import (
    GAS_TX,
    GAS_TXDATAZERO,
    GAS_TXDATANONZERO,
)
from ...._utils.transactions import IntrinsicGasSchedule


CREATE_CONTRACT_ADDRESS = Address(b'')


#
# Difficulty
#
FRONTIER_DIFFICULTY_ADJUSTMENT_CUTOFF = 13


#
# Stack Limit
#
STACK_DEPTH_LIMIT = 1024


#
# Gas Costs and Refunds
#
REFUND_SELFDESTRUCT = 24000
GAS_CODEDEPOSIT = 200



FRONTIER_TX_GAS_SCHEDULE = IntrinsicGasSchedule(
    gas_tx=GAS_TX,
    gas_txcreate=0,
    gas_txdatazero=GAS_TXDATAZERO,
    gas_txdatanonzero=GAS_TXDATANONZERO,
)