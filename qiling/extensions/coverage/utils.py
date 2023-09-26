#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

from contextlib import contextmanager
from typing import Dict, TYPE_CHECKING, List, Type, TypeVar

from .formats import *
from .formats.base import QlBaseCoverage


if TYPE_CHECKING:
    from qiling import Qiling

CT = TypeVar('CT', bound=QlBaseCoverage)


# Returns subclasses recursively.
def get_all_subclasses(cls: Type[CT]) -> List[Type[CT]]:
    all_subclasses = []

    for subclass in cls.__subclasses__():
        all_subclasses.append(subclass)
        all_subclasses.extend(get_all_subclasses(subclass))

    return all_subclasses


class CoverageFactory:
    def __init__(self):
        self.coverage_collectors: Dict[str, Type[QlBaseCoverage]] = {subcls.FORMAT_NAME: subcls for subcls in get_all_subclasses(QlBaseCoverage)}

    @property
    def formats(self):
        return self.coverage_collectors.keys()

    def get_coverage_collector(self, ql: Qiling, name: str) -> QlBaseCoverage:
        return self.coverage_collectors[name](ql)


factory = CoverageFactory()


@contextmanager
def collect_coverage(ql: Qiling, name: str, coverage_file: str):
    """
    Context manager for emulating a given piece of code with coverage collection turned on.
    Example:
    with collect_coverage(ql, 'drcov', 'output.cov'):
        ql.run(...)
    """

    cov = factory.get_coverage_collector(ql, name)
    cov.activate()

    try:
        yield
    finally:
        cov.deactivate()
        cov.dump_coverage(coverage_file)
