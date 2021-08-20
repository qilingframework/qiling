from typing import Iterable

from eth_typing import Address

from eth_utils import to_set

from .... import constants

from ...._utils.address import (
    force_bytes_to_address,
)

from ....vm.computation import BaseComputation


THREE = force_bytes_to_address(b'\x03')


@to_set
def collect_touched_accounts(computation: BaseComputation,
                             ancestor_had_error: bool = False) -> Iterable[Address]:
    """
    Collect all of the accounts that *may* need to be deleted based on
    `EIP-161 <https://eips.ethereum.org/EIPS/eip-161>`_.

    Checking whether they *do* need to be deleted happens in the caller.

    See also: https://github.com/ethereum/EIPs/issues/716
    """
    # collect the coinbase account if it was touched via zero-fee transfer
    if computation.is_origin_computation and computation.transaction_context.gas_price == 0:
        yield computation.state.coinbase

    # collect those explicitly marked for deletion ("beneficiary" is of SELFDESTRUCT)
    for beneficiary in sorted(set(computation.accounts_to_delete.values())):
        if computation.is_error or ancestor_had_error:
            # Special case to account for geth+parity bug
            # https://github.com/ethereum/EIPs/issues/716
            if beneficiary == THREE:
                yield beneficiary
            continue
        else:
            yield beneficiary

    # collect account directly addressed
    if computation.msg.to != constants.CREATE_CONTRACT_ADDRESS:
        if computation.is_error or ancestor_had_error:
            # collect RIPEMD160 precompile even if ancestor computation had error;
            # otherwise, skip collection from children of errored-out computations;
            # if there were no special-casing for RIPEMD160, we'd simply `pass` here
            if computation.msg.to == THREE:
                yield computation.msg.to
        else:
            yield computation.msg.to

    # recurse into nested computations (even errored ones, since looking for RIPEMD160)
    for child in computation.children:
        yield from collect_touched_accounts(
            child,
            ancestor_had_error=(computation.is_error or ancestor_had_error))
