from dataclasses import dataclass
from typing import Iterator, Optional


@dataclass
class CallStack:
    """Linked Frames
    See https://github.com/angr/angr/blob/master/angr/state_plugins/callstack.py
    """
    addr: int
    sp: int
    bp: int
    name: str = None  # 'name + offset'
    next: Optional['CallStack'] = None

    def __iter__(self) -> Iterator['CallStack']:
        """
        Iterate through the callstack, from top to bottom
        (most recent first).
        """
        i = self
        while i is not None:
            yield i
            i = i.next

    def __getitem__(self, k):
        """
        Returns the CallStack at index k, indexing from the top of the stack.
        """
        orig_k = k
        for i in self:
            if k == 0:
                return i
            k -= 1
        raise IndexError(orig_k)

    def __len__(self):
        """
        Get how many frames there are in the current call stack.

        :return: Number of frames
        :rtype: int
        """

        o = 0
        for _ in self:
            o += 1
        return o

    def __repr__(self):
        """
        Get a string representation.

        :return: A printable representation of the CallStack object
        :rtype: str
        """
        return "<CallStack (depth %d)>" % len(self)

    def __str__(self):
        return "Backtrace:\n" + "\n".join(f"Frame {i}: [{f.name}] {f.addr:#x} sp={f.sp:#x}, bp={f.bp:#x}" for i, f in enumerate(self))

    def __eq__(self, other):
        if not isinstance(other, CallStack):
            return False

        if self.addr != other.addr or self.sp != other.sp or self.bp != other.bp:
            return False

        return self.next == other.next

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash(tuple((c.addr, c.sp, c.bp) for c in self))
