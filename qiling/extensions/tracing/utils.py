# This code structure is copied and modified from the coverage extension

from contextlib import contextmanager
from .formats import *


# Returns subclasses recursively.
def get_all_subclasses(cls):
    all_subclasses = []

    for subclass in cls.__subclasses__():
        all_subclasses.append(subclass)
        all_subclasses.extend(get_all_subclasses(subclass))

    return all_subclasses

class TraceFactory():
    def __init__(self):
        self.trace_collectors = {subcls.FORMAT_NAME:subcls for subcls in get_all_subclasses(base.QlBaseTrace)}

    @property
    def formats(self):
        return self.trace_collectors.keys()

    def get_trace_collector(self, ql, name):
        return self.trace_collectors[name](ql)

factory = TraceFactory()

@contextmanager
def collect_trace(ql, name: str, trace_file: str):
    """
    Context manager for emulating a given piece of code with tracing.
    Example:
    with collect_trace(ql, 'tenet', 'trace.0.log'):
        ql.run(...)
    """

    trace = factory.get_trace_collector(ql, name)
    trace.activate()
    try:
        yield
    finally:
        trace.deactivate()
        if trace_file:
            trace.dump_trace(trace_file)
