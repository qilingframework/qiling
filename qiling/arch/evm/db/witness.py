from typing import (
    Dict,
    FrozenSet,
    NamedTuple,
    Set,
)

from eth_typing import (
    Address,
    Hash32,
)

from ..abc import (
    MetaWitnessAPI,
)


class AccountQueryTracker(NamedTuple):
    did_query_bytecode: bool
    slots_queried: FrozenSet[int]


class MetaWitness(MetaWitnessAPI):
    def __init__(
            self,
            witness_hashes: Set[Hash32],
            accounts_metadata_queried: Dict[Address, AccountQueryTracker]) -> None:

        self._trie_node_hashes = frozenset(witness_hashes)
        self._accounts_metadata_queried = accounts_metadata_queried

    @property
    def hashes(self) -> FrozenSet[Hash32]:
        return self._trie_node_hashes

    @property
    def accounts_queried(self) -> FrozenSet[Address]:
        return frozenset(self._accounts_metadata_queried.keys())

    @property
    def account_bytecodes_queried(self) -> FrozenSet[Address]:
        return frozenset(
            address
            for address, query_tracker in self._accounts_metadata_queried.items()
            if query_tracker.did_query_bytecode
        )

    def get_slots_queried(self, address: Address) -> FrozenSet[int]:
        try:
            query_tracker = self._accounts_metadata_queried[address]
        except KeyError:
            return frozenset()
        else:
            return query_tracker.slots_queried

    @property
    def total_slots_queried(self) -> int:
        """
        Summed across all accounts, how many storage slots were queried?
        """
        return sum(
            len(query_tracker.slots_queried)
            for query_tracker in self._accounts_metadata_queried.values()
        )
