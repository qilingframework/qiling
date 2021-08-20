import rlp
from rlp.sedes import (
    BigEndianInt,
    Binary,
)


address = Binary.fixed_length(20, allow_empty=True)
hash32 = Binary.fixed_length(32)
uint32 = BigEndianInt(32)
uint256 = BigEndianInt(256)
trie_root = Binary.fixed_length(32, allow_empty=True)
chain_gaps = rlp.sedes.List((
    rlp.sedes.CountableList(rlp.sedes.List((uint32, uint32))),
    uint32,
))
