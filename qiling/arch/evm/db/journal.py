import collections
from itertools import (
    count,
)
from typing import Callable, cast, Dict, List, Set, Union

from eth_utils.toolz import (
    first,
    nth,
)
from eth_utils import (
    ValidationError,
)

from ..abc import DatabaseAPI
from ..typing import JournalDBCheckpoint

from .backends.base import BaseDB
from .diff import DBDiff, DBDiffTracker


class DeletedEntry:
    pass


# Track two different kinds of deletion:

# 1. key in wrapped
# 2. key modified in journal
# 3. key deleted
DELETE_WRAPPED = DeletedEntry()

# 1. key not in wrapped
# 2. key created in journal
# 3. key deleted
REVERT_TO_WRAPPED = DeletedEntry()

ChangesetValue = Union[bytes, DeletedEntry]
ChangesetDict = Dict[bytes, ChangesetValue]

get_next_checkpoint = cast(Callable[[], JournalDBCheckpoint], count().__next__)


class Journal(BaseDB):
    """
    A Journal provides a mechanism to track a series of changes to a dict, by inserting
    checkpoints, and committing to them or rolling back to them, and ultimitely persisting
    the final changes.

    Internally, it keeps an ordered list of reversion changesets, used to roll back
    on demand. This is optimized for the most common path: lots of checkpoints and commits,
    and not many discards.

    Checkpoints are referenced by an internally-generated integer. This is *not* threadsafe.
    """
    __slots__ = [
        '_journal_data',
        '_clears_at',
        '_current_values',
        '_ignore_wrapped_db',
        '_checkpoint_stack',
    ]

    #
    # This is a high-use class, where we sometimes prefere optimization over readability.
    # It's most important to optimize for record, commit, and persist, which ard the most commonly
    # used methods.
    #

    def __init__(self) -> None:
        # If the journal was persisted right now, these would be the current changes to push:
        self._current_values: ChangesetDict = {}

        # contains a mapping from all of the int checkpoints
        # to a dictionary of key:value pairs that are used to rewind from the current values
        # to the given checkpoint
        self._journal_data: collections.OrderedDict[JournalDBCheckpoint, ChangesetDict] = collections.OrderedDict()  # noqa E501

        # Clears are special operations that enforce that the underlying database and current
        # changes are completely emptied out. Clears are also committable & discardable.
        self._clears_at: Set[JournalDBCheckpoint] = set()

        # If a clear was called, then any missing keys should be treated as missing
        self._ignore_wrapped_db = False

        # To speed up commits, we leave in old recorded checkpoints in self._journal_data, even
        # on commit. Instead of dropping them, we keep a separate list of active checkpoints.
        self._checkpoint_stack: List[JournalDBCheckpoint] = []

    @property
    def root_checkpoint(self) -> JournalDBCheckpoint:
        """
        Returns the starting checkpoint
        """
        return first(self._journal_data.keys())

    @property
    def is_flattened(self) -> bool:
        """
        :return: whether there are any explicitly committed checkpoints
        """
        return len(self._checkpoint_stack) < 2

    @property
    def last_checkpoint(self) -> JournalDBCheckpoint:
        """
        Returns the latest checkpoint
        """
        # last() was iterating through all values, so first(reversed()) gives a 12.5x speedup
        # Interestingly, an attempt to cache this value caused a slowdown.
        return first(reversed(self._journal_data.keys()))

    def has_checkpoint(self, checkpoint: JournalDBCheckpoint) -> bool:
        # another option would be to enforce monotonically-increasing checkpoints, so we can do:
        # checkpoint_idx = bisect_left(self._checkpoint_stack, checkpoint)
        # (then validate against length and value at index)
        return checkpoint in self._checkpoint_stack

    def record_checkpoint(
            self,
            custom_checkpoint: JournalDBCheckpoint = None) -> JournalDBCheckpoint:
        """
        Creates a new checkpoint. Checkpoints are a sequential int chosen by Journal
        to prevent collisions.
        """
        if custom_checkpoint is not None:
            if custom_checkpoint in self._journal_data:
                raise ValidationError(
                    f"Tried to record with an existing checkpoint: {custom_checkpoint!r}"
                )
            else:
                checkpoint = custom_checkpoint
        else:
            checkpoint = get_next_checkpoint()

        self._journal_data[checkpoint] = {}
        self._checkpoint_stack.append(checkpoint)
        return checkpoint

    def discard(self, through_checkpoint_id: JournalDBCheckpoint) -> None:
        while self._checkpoint_stack:
            checkpoint_id = self._checkpoint_stack.pop()
            if checkpoint_id == through_checkpoint_id:
                break
        else:
            # checkpoint not found!
            raise ValidationError(f"No checkpoint {through_checkpoint_id} was found")

        # This might be optimized further by iterating the other direction and
        # ignoring any follow-up rollbacks on the same variable.
        for _ in range(len(self._journal_data)):
            checkpoint_id, rollback_data = self._journal_data.popitem()

            for old_key, old_value in rollback_data.items():
                if old_value is REVERT_TO_WRAPPED:
                    # The current value may not exist, if it was a delete followed by a clear,
                    # so pop it off, or ignore if it is already missing
                    self._current_values.pop(old_key, None)
                elif old_value is DELETE_WRAPPED:
                    self._current_values[old_key] = old_value
                elif type(old_value) is bytes:
                    self._current_values[old_key] = old_value
                else:
                    raise ValidationError(f"Unexpected value, must be bytes: {old_value!r}")

            if checkpoint_id in self._clears_at:
                self._clears_at.remove(checkpoint_id)
                self._ignore_wrapped_db = False

            if checkpoint_id == through_checkpoint_id:
                break

        if self._clears_at:
            # if there is still a clear in older locations, then reinitiate the clear flag
            self._ignore_wrapped_db = True

    def clear(self) -> None:
        """
        Treat as if the *underlying* database will also be cleared by some other mechanism.
        We build a special empty reversion changeset just for marking that all previous data should
        be ignored.
        """
        checkpoint = get_next_checkpoint()
        self._journal_data[checkpoint] = self._current_values
        self._current_values = {}
        self._ignore_wrapped_db = True
        self._clears_at.add(checkpoint)

    def has_clear(self, at_checkpoint: JournalDBCheckpoint) -> bool:
        for reversion_changeset_id in reversed(self._journal_data.keys()):
            if reversion_changeset_id in self._clears_at:
                return True
            elif at_checkpoint == reversion_changeset_id:
                return False
        raise ValidationError(f"Checkpoint {at_checkpoint} is not in the journal")

    def commit_checkpoint(self, commit_to: JournalDBCheckpoint) -> ChangesetDict:
        """
        Collapses all changes since the given checkpoint. Can no longer discard to any of
        the checkpoints that followed the given checkpoint.
        """
        # Another option would be to enforce monotonically-increasing changeset ids, so we can do:
        # checkpoint_idx = bisect_left(self._checkpoint_stack, commit_to)
        # (then validate against length and value at index)
        for positions_before_last, checkpoint in enumerate(reversed(self._checkpoint_stack)):
            if checkpoint == commit_to:
                checkpoint_idx = -1 - positions_before_last
                break
        else:
            raise ValidationError(f"No checkpoint {commit_to} was found")

        if checkpoint_idx == -1 * len(self._checkpoint_stack):
            raise ValidationError(
                "Should not commit root changeset with commit_changeset, use pop_all() instead"
            )

        # delete committed checkpoints from the stack (but keep rollbacks for future discards)
        del self._checkpoint_stack[checkpoint_idx:]

        return self._current_values

    def pop_all(self) -> ChangesetDict:
        final_changes = self._current_values
        self._journal_data.clear()
        self._clears_at.clear()
        self._current_values = {}
        self._checkpoint_stack.clear()
        self.record_checkpoint()
        self._ignore_wrapped_db = False
        return final_changes

    def flatten(self) -> None:
        if self.is_flattened:
            return

        checkpoint_after_root = nth(1, self._checkpoint_stack)
        self.commit_checkpoint(checkpoint_after_root)

    #
    # Database API
    #
    def __getitem__(self, key: bytes) -> ChangesetValue:    # type: ignore # Breaks LSP
        """
        For key lookups we need to iterate through the changesets in reverse
        order, returning from the first one in which the key is present.
        """
        # the default result (the value if not in the local values) depends on whether there
        # was a clear
        if self._ignore_wrapped_db:
            default_result = REVERT_TO_WRAPPED
        else:
            default_result = None  # indicate that caller should check wrapped database
        return self._current_values.get(key, default_result)

    def __setitem__(self, key: bytes, value: bytes) -> None:
        # if the value has not been changed since wrapping, then simply revert to original value
        revert_changeset = self._journal_data[self.last_checkpoint]
        if key not in revert_changeset:
            revert_changeset[key] = self._current_values.get(key, REVERT_TO_WRAPPED)
        self._current_values[key] = value

    def _exists(self, key: bytes) -> bool:
        val = self.get(key)
        return val is not None and val not in (REVERT_TO_WRAPPED, DELETE_WRAPPED)

    def __delitem__(self, key: bytes) -> None:
        raise NotImplementedError("You must delete with one of delete_local or delete_wrapped")

    def delete_wrapped(self, key: bytes) -> None:
        revert_changeset = self._journal_data[self.last_checkpoint]
        if key not in revert_changeset:
            revert_changeset[key] = self._current_values.get(key, REVERT_TO_WRAPPED)
        self._current_values[key] = DELETE_WRAPPED

    def delete_local(self, key: bytes) -> None:
        revert_changeset = self._journal_data[self.last_checkpoint]
        if key not in revert_changeset:
            revert_changeset[key] = self._current_values.get(key, REVERT_TO_WRAPPED)
        self._current_values[key] = REVERT_TO_WRAPPED

    def diff(self) -> DBDiff:
        tracker = DBDiffTracker()

        for key, value in self._current_values.items():
            if value is DELETE_WRAPPED:
                del tracker[key]
            elif value is REVERT_TO_WRAPPED:
                pass
            else:
                tracker[key] = value  # type: ignore  # cast(bytes, value)

        return tracker.diff()


class JournalDB(BaseDB):
    """
    A wrapper around the basic DB objects that keeps a journal of all changes.
    Checkpoints can be recorded at any time. You can then commit or roll back
    to those checkpoints.

    Discarding a checkpoint throws away all changes that happened since that
    checkpoint.
    Commiting a checkpoint simply removes the option of reverting back to it
    later.

    Nothing is written to the underlying db until `persist()` is called.

    The added memory footprint for a JournalDB is one key/value stored per
    database key which is changed, at each checkpoint.  Subsequent changes to the same key
    between two checkpoints will not increase the journal size, since we
    do not permit reverting to a place that has no checkpoint.
    """
    __slots__ = ['_wrapped_db', '_journal', 'record', 'commit']

    def __init__(self, wrapped_db: DatabaseAPI) -> None:
        self._wrapped_db = wrapped_db
        self._journal = Journal()
        self.record = self._journal.record_checkpoint
        self.commit = self._journal.commit_checkpoint
        self.reset()

    def __getitem__(self, key: bytes) -> bytes:

        val = self._journal[key]
        if val is DELETE_WRAPPED:
            raise KeyError(
                key,
                "item is deleted in JournalDB, and will be deleted from the wrapped DB",
            )
        elif val is REVERT_TO_WRAPPED:
            raise KeyError(
                key,
                "item is deleted in JournalDB, and is presumed gone from the wrapped DB",
            )
        elif val is None:
            return self._wrapped_db[key]
        else:
            # mypy doesn't allow custom type guards yet so we need to cast here
            # even though we know it can only be `bytes` at this point.
            return cast(bytes, val)

    def __setitem__(self, key: bytes, value: bytes) -> None:
        """
        - replacing an existing value
        - setting a value that does not exist
        """
        self._journal[key] = value

    def _exists(self, key: bytes) -> bool:
        val = self._journal[key]
        if val in (REVERT_TO_WRAPPED, DELETE_WRAPPED):
            return False
        elif val is None:
            return key in self._wrapped_db
        else:
            return True

    def clear(self) -> None:
        """
        Remove all keys. Immediately after a clear, *all* getitem requests will return a KeyError.
        That includes the changes pending persist and any data in the underlying database.

        (This action is journaled, like all other actions)

        clear will *not* persist the emptying of all keys in the underlying DB.
        It only prevents any updates (or deletes!) before it from being persisted.

        Any caller that wants to use clear must also make sure that the underlying database
        reflects their desired end state (maybe emptied, maybe not).
        """
        self._journal.clear()

    def has_clear(self) -> bool:
        return self._journal.has_clear(self._journal.root_checkpoint)

    def __delitem__(self, key: bytes) -> None:
        if key in self._wrapped_db:
            self._journal.delete_wrapped(key)
        else:
            if key in self._journal:
                self._journal.delete_local(key)
            else:
                raise KeyError(key, "key could not be deleted in JournalDB, because it was missing")

    #
    # Snapshot API
    #
    def has_checkpoint(self, checkpoint: JournalDBCheckpoint) -> bool:
        return self._journal.has_checkpoint(checkpoint)

    def discard(self, checkpoint: JournalDBCheckpoint) -> None:
        """
        Throws away all journaled data starting at the given checkpoint
        """
        self._journal.discard(checkpoint)

    def _reapply_checkpoint_to_journal(
            self,
            journal_data: ChangesetDict) -> None:
        for key, value in journal_data.items():
            if value is DELETE_WRAPPED:
                self._journal.delete_wrapped(key)
            elif value is REVERT_TO_WRAPPED:
                self._journal.delete_local(key)
            else:
                self._journal[key] = cast(bytes, value)

    def persist(self) -> None:
        """
        Persist all changes in underlying db. After all changes have been written the
        JournalDB starts a new recording.
        """
        journal_data = self._journal.pop_all()

        for key, value in journal_data.items():
            try:
                if value is DELETE_WRAPPED:
                    del self._wrapped_db[key]
                elif value is REVERT_TO_WRAPPED:
                    pass
                else:
                    self._wrapped_db[key] = cast(bytes, value)
            except Exception:
                self._reapply_checkpoint_to_journal(journal_data)
                raise

    def flatten(self) -> None:
        """
        Commit everything possible without persisting
        """
        self._journal.flatten()

    def reset(self) -> None:
        """
        Reset the entire journal.
        """
        self._journal.pop_all()

    def diff(self) -> DBDiff:
        """
        Generate a DBDiff of all pending changes.
        These are the changes that would occur if :meth:`persist()` were called.
        """
        return self._journal.diff()
