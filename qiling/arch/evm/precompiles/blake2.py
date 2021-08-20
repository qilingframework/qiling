import blake2b
from eth_utils import (
    ValidationError,
)

from .._utils.blake2.coders import extract_blake2b_parameters
from ..exceptions import (
    VMError,
)
from ..vm.computation import (
    BaseComputation,
)

GAS_COST_PER_ROUND = 1


def blake2b_fcompress(computation: BaseComputation) -> BaseComputation:
    try:
        parameters = extract_blake2b_parameters(computation.msg.data_as_bytes)
    except ValidationError as exc:
        raise VMError(f"Blake2b input parameter validation failure: {exc}") from exc

    num_rounds = parameters[0]
    gas_cost = GAS_COST_PER_ROUND * num_rounds

    computation.consume_gas(gas_cost, reason=f"Blake2b Compress Precompile w/ {num_rounds} rounds")

    computation.output = blake2b.compress(*parameters)
    return computation
