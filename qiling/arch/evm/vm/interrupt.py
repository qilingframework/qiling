#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import (
    Optional,
)

from eth_typing import (
    Address,
    Hash32,
)
from eth_utils import (
    encode_hex,
)
from trie.exceptions import (
    MissingTrieNode,
)
from trie.typing import (
    Nibbles,
)
from ..exceptions import (
    PyEVMError,
)


class EVMMissingData(PyEVMError):
    pass


class MissingAccountTrieNode(EVMMissingData, MissingTrieNode):
    """
    Raised when a main state trie node is missing from the DB, to get an account RLP
    """
    @property
    def state_root_hash(self) -> Hash32:
        return self.root_hash

    @property
    def address_hash(self) -> Hash32:
        return self.requested_key

    def __repr__(self) -> str:
        return f"MissingAccountTrieNode: {self}"

    def __str__(self) -> str:
        superclass_str = EVMMissingData.__str__(self)
        return (
            "State trie database is missing node for hash "
            f"{encode_hex(self.missing_node_hash)}, which is needed to look up account "
            f"with address hash {encode_hex(self.address_hash)} "
            f"at root hash {encode_hex(self.state_root_hash)} "
            f"-- {superclass_str}"
        )


class MissingStorageTrieNode(EVMMissingData, MissingTrieNode):
    """
    Raised when a storage trie node is missing from the DB
    """
    def __init__(
            self,
            missing_node_hash: Hash32,
            storage_root_hash: Hash32,
            requested_key: Hash32,
            prefix: Optional[Nibbles],
            account_address: Address,
            *args: bytes) -> None:
        if not isinstance(account_address, bytes):
            raise TypeError(f"Account address must be bytes, was: {account_address!r}")

        super().__init__(
            missing_node_hash,
            storage_root_hash,
            requested_key,
            prefix,
            account_address,
            *args,
        )

    @property
    def storage_root_hash(self) -> Hash32:
        return self.root_hash

    @property
    def account_address(self) -> Address:
        return self.args[4]

    def __repr__(self) -> str:
        return f"MissingStorageTrieNode: {self}"

    def __str__(self) -> str:
        superclass_str = EVMMissingData.__str__(self)
        return (
            "Storage trie database is missing hash "
            f"{encode_hex(self.missing_node_hash)} "
            f"needed to look up key {encode_hex(self.requested_key)} "
            f"at root hash {encode_hex(self.root_hash)} "
            f"in account address {encode_hex(self.account_address)} "
            f"-- {superclass_str}"
        )


class MissingBytecode(EVMMissingData):
    """
    Raised when the bytecode is missing from the database for a known bytecode hash.
    """
    def __init__(self, missing_code_hash: Hash32) -> None:
        if not isinstance(missing_code_hash, bytes):
            raise TypeError(f"Missing code hash must be bytes, was: {missing_code_hash!r}")

        super().__init__(missing_code_hash)

    @property
    def missing_code_hash(self) -> Hash32:
        return self.args[0]

    def __repr__(self) -> str:
        return f"MissingBytecode: {self}"

    def __str__(self) -> str:
        superclass_str = EVMMissingData.__str__(self)
        return (
            f"Database is missing bytecode for code hash "
            f"{encode_hex(self.missing_code_hash)} "
            f"-- {superclass_str}"
        )
