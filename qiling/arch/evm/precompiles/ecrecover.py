from eth_keys import keys
from eth_keys.exceptions import (
    BadSignature,
)

from eth_utils import (
    big_endian_to_int,
    ValidationError,
)

from .. import constants

from .._utils.padding import (
    pad32,
    pad32r,
)

from ..validation import (
    validate_lt_secpk1n,
    validate_gte,
    validate_lte,
)
from ..vm.computation import (
    BaseComputation,
)


def ecrecover(computation: BaseComputation) -> BaseComputation:
    computation.consume_gas(constants.GAS_ECRECOVER, reason="ECRecover Precompile")
    data = computation.msg.data_as_bytes
    raw_message_hash = data[:32]
    message_hash = pad32r(raw_message_hash)

    v_bytes = pad32r(data[32:64])
    v = big_endian_to_int(v_bytes)

    r_bytes = pad32r(data[64:96])
    r = big_endian_to_int(r_bytes)

    s_bytes = pad32r(data[96:128])
    s = big_endian_to_int(s_bytes)

    try:
        validate_lt_secpk1n(r, title="ECRecover: R")
        validate_lt_secpk1n(s, title="ECRecover: S")
        validate_lte(v, 28, title="ECRecover: V")
        validate_gte(v, 27, title="ECRecover: V")
    except ValidationError:
        return computation

    canonical_v = v - 27

    try:
        signature = keys.Signature(vrs=(canonical_v, r, s))
        public_key = signature.recover_public_key_from_msg_hash(message_hash)
    except BadSignature:
        return computation

    address = public_key.to_canonical_address()
    padded_address = pad32(address)

    computation.output = padded_address
    return computation
