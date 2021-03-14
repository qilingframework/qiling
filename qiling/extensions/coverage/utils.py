#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from contextlib import contextmanager

from .formats import *


# Returns subclasses recursively.
def get_all_subclasses(cls):
    all_subclasses = []

    for subclass in cls.__subclasses__():
        all_subclasses.append(subclass)
        all_subclasses.extend(get_all_subclasses(subclass))

    return all_subclasses

class CoverageFactory():
    def __init__(self):
        self.coverage_collectors = {subcls.FORMAT_NAME:subcls for subcls in get_all_subclasses(base.QlBaseCoverage)}

    @property
    def formats(self):
        return self.coverage_collectors.keys()

    def get_coverage_collector(self, ql, name):
        return self.coverage_collectors[name](ql)

factory = CoverageFactory()

@contextmanager
def collect_coverage(ql, name, coverage_file):
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
        if coverage_file:
            cov.dump_coverage(coverage_file)
