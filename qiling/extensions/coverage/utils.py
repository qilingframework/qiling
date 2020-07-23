#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from .formats import *
from contextlib import contextmanager

class CoverageFactory():
    def __init__(self):
        self.coverage_collectors = {subcls.FORMAT_NAME:subcls for subcls in base.QlBaseCoverage.__subclasses__()}

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
