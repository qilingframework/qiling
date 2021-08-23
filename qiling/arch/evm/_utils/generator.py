#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import itertools
from typing import (
    Generic,
    Iterable,
    Iterator,
    List,
    TypeVar,
)


TItem = TypeVar('TItem')


class CachedIterable(Generic[TItem], Iterable[TItem]):
    def __init__(self, iterable: Iterable[TItem]) -> None:
        self._cached_results: List[TItem] = []
        self._iterator = iter(iterable)

    def __iter__(self) -> Iterator[TItem]:
        return itertools.chain(self._cached_results, self._cache_and_yield())

    def _cache_and_yield(self) -> Iterator[TItem]:
        for item in self._iterator:
            self._cached_results.append(item)
            yield item
