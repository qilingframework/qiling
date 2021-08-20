from ....vm.forks.frontier.constants import FRONTIER_TX_GAS_SCHEDULE
from ....constants import GAS_TXCREATE

#
# Difficulty
#
HOMESTEAD_DIFFICULTY_ADJUSTMENT_CUTOFF = 10


#
# Gas Costs and Refunds
#
GAS_CODEDEPOSIT = 200


HOMESTEAD_TX_GAS_SCHEDULE = FRONTIER_TX_GAS_SCHEDULE._replace(
    gas_txcreate=GAS_TXCREATE,
)