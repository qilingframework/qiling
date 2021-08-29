#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from eth_typing import Hash32


class PyEVMError(Exception):
    """
    Base class for all py-evm errors.
    """
    pass


class VMNotFound(PyEVMError):
    """
    Raised when no VM is available for the provided block number.
    """
    pass


class StateRootNotFound(PyEVMError):
    """
    Raised when the requested state root is not present in our DB.
    """
    @property
    def missing_state_root(self) -> Hash32:
        return self.args[0]


class HeaderNotFound(PyEVMError):
    """
    Raised when a header with the given number/hash does not exist.
    """


class BlockNotFound(PyEVMError):
    """
    Raised when the block with the given number/hash does not exist.
    This will happen, for example, if the transactions or uncles are not
    saved in the database.
    """
    pass


class TransactionNotFound(PyEVMError):
    """
    Raised when the transaction with the given hash or block index does not exist.
    """
    pass


class ReceiptNotFound(PyEVMError):
    """
    Raised when the Receipt with the given receipt index does not exist.
    """
    pass


class ParentNotFound(HeaderNotFound):
    """
    Raised when the parent of a given block does not exist.
    """
    pass


class CanonicalHeadNotFound(PyEVMError):
    """
    Raised when the chain has no canonical head.
    """
    pass


class GapTrackingCorrupted(PyEVMError):
    """
    Raised when the tracking of chain gaps appears to be corrupted (e.g. overlapping gaps)
    """
    pass


class CheckpointsMustBeCanonical(PyEVMError):
    """
    Raised when a persisted header attempts to de-canonicalize a checkpoint
    """
    pass


class Halt(PyEVMError):
    """
    Raised when an opcode function halts vm execution.
    """
    pass


class VMError(PyEVMError):
    """
    Base class for errors raised during VM execution.
    """
    burns_gas = True
    erases_return_data = True


class OutOfGas(VMError):
    """
    Raised when a VM execution has run out of gas.
    """
    pass


class InsufficientStack(VMError):
    """
    Raised when the stack is empty.
    """
    pass


class FullStack(VMError):
    """
    Raised when the stack is full.
    """
    pass


class InvalidJumpDestination(VMError):
    """
    Raised when the jump destination for a JUMPDEST operation is invalid.
    """
    pass


class InvalidInstruction(VMError):
    """
    Raised when an opcode is invalid.
    """
    pass


class InsufficientFunds(VMError):
    """
    Raised when an account has insufficient funds to transfer the
    requested value.
    """
    pass


class StackDepthLimit(VMError):
    """
    Raised when the call stack has exceeded it's maximum allowed depth.
    """
    pass


class ContractCreationCollision(VMError):
    """
    Raised when there was an address collision during contract creation.
    """
    pass


class IncorrectContractCreationAddress(VMError):
    """
    Raised when the address provided by transaction does not
    match the calculated contract creation address.
    """
    pass


class Revert(VMError):
    """
    Raised when the REVERT opcode occured
    """
    burns_gas = False
    erases_return_data = False


class WriteProtection(VMError):
    """
    Raised when an attempt to modify the state database is made while
    operating inside of a STATICCALL context.
    """
    pass


class OutOfBoundsRead(VMError):
    """
    Raised when an attempt was made to read data beyond the
    boundaries of the buffer (such as with RETURNDATACOPY)
    """
    pass
