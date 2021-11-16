#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys

sys.path.append("../../../..")
from qiling import *


def underflow(fuzz_balance):
    code = '0x6060604052341561000f57600080fd5b60405160208061031c833981016040528080519060200190919050508060018190556000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555050610299806100836000396000f300606060405260043610610057576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806318160ddd1461005c57806370a0823114610085578063a9059cbb146100d2575b600080fd5b341561006757600080fd5b61006f61012c565b6040518082815260200191505060405180910390f35b341561009057600080fd5b6100bc600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610132565b6040518082815260200191505060405180910390f35b34156100dd57600080fd5b610112600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803590602001909190505061017a565b604051808215151515815260200191505060405180910390f35b60015481565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b600080826000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205403101515156101cb57600080fd5b816000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282540392505081905550816000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828254019250508190555060019050929150505600a165627a7a7230582098f1551a391a3e65b3ce45cfa2b3fa5f91eea9a3e7181a81454e025ea0d7151c0029'
    ql = Qiling(code=code, archtype="evm")

    # Add Balance Var to the contract
    bal = ql.arch.evm.abi.convert(['uint256'], [20])
    contract = code + bal

    user1 = ql.arch.evm.create_account()
    user2 = ql.arch.evm.create_account()
    c1 = ql.arch.evm.create_account()

    def check_balance(sender, destination):
        call_data = '0x70a08231'+ql.arch.evm.abi.convert(['address'], [sender])
        msg2 = ql.arch.evm.create_message(sender, destination, call_data)
        return ql.run(code=msg2)

    # Deploy runtime code
    msg0 = ql.arch.evm.create_message(user1, b'', code=contract, contract_address=c1)
    ql.run(code=msg0)

    # SMART CONTRACT DEPENDENT: check balance of user1, should be 20
    result = check_balance(user1, c1)

    # SMART CONTRACT DEPENDENT: transform 21 from user1 to user2
    call_data = '0xa9059cbb'+ ql.arch.evm.abi.convert(['address'], [user2]) + \
                                    ql.arch.evm.abi.convert(['uint256'], [fuzz_balance])
    msg1 = ql.arch.evm.create_message(user1, c1, call_data)    
    result = ql.run(code=msg1)

    # SMART CONTRACT DEPENDENT: User1 balance underflow, MAX - 1
    result = check_balance(user1, c1)

    if int(result.output_data.hex()[2:], 16) > 20:
        raise OverflowError()

