#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    Iterable,
    List,
    Optional,
    NewType,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    TYPE_CHECKING,
    Union,
)

from eth_typing import (
    Address,
    BlockNumber,
    Hash32,
    HexStr,
)
import sys
if sys.version_info[0] == 3 and sys.version_info[1] >= 8:
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

if TYPE_CHECKING:
    from .abc import VirtualMachineAPI  # noqa: F401


JournalDBCheckpoint = NewType('JournalDBCheckpoint', int)

AccountDetails = TypedDict('AccountDetails',
                           {'balance': int,
                            'nonce': int,
                            'code': bytes,
                            'storage': Dict[int, int]
                            })
AccountState = Dict[Address, AccountDetails]

AccountDiff = Iterable[Tuple[Address, str, Union[int, bytes], Union[int, bytes]]]

BlockRange = Tuple[BlockNumber, BlockNumber]

ChainGaps = Tuple[
    # series of gaps before the chain head
    Tuple[BlockRange, ...],
    # the first missing block number at the tip of the chain
    BlockNumber,
]

GeneralState = Union[
    AccountState,
    List[Tuple[Address, Dict[str, Union[int, bytes, Dict[int, int]]]]]
]

GenesisDict = Dict[str, Union[int, BlockNumber, bytes, Hash32]]

BytesOrView = Union[bytes, memoryview]

Normalizer = Callable[[Dict[Any, Any]], Dict[str, Any]]

RawAccountDetails = TypedDict('RawAccountDetails',
                              {'balance': HexStr,
                               'nonce': HexStr,
                               'code': HexStr,
                               'storage': Dict[HexStr, HexStr]
                               })

TransactionDict = TypedDict('TransactionDict',
                            {'nonce': int,
                             'gasLimit': int,
                             'gasPrice': int,
                             'to': Address,
                             'value': int,
                             'data': bytes,
                             'secretKey': bytes,
                             })

TransactionNormalizer = Callable[[TransactionDict], TransactionDict]

VMFork = Tuple[BlockNumber, Type['VirtualMachineAPI']]

VMConfiguration = Sequence[VMFork]

VRS = NewType("VRS", Tuple[int, int, int])

IntConvertible = Union[int, bytes, HexStr, str]


TFunc = TypeVar('TFunc')


class StaticMethod(Generic[TFunc]):
    """
    A property class purely to convince mypy to let us assign a function to an
    instance variable. See more at: https://github.com/python/mypy/issues/708#issuecomment-405812141
    """
    def __get__(self, oself: Any, owner: Any) -> TFunc:
        return self._func

    def __set__(self, oself: Any, value: TFunc) -> None:
        self._func = value


HeaderParams = Union[Optional[int], BlockNumber, bytes, Address, Hash32]
