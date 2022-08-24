#!/usr/bin/env python3

import sys, unittest

sys.path.append("..")
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.r2.r2 import R2


EVM_CODE = bytes.fromhex("6060604052341561000f57600080fd5b60405160208061031c833981016040528080519060200190919050508060018190556000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555050610299806100836000396000f300606060405260043610610057576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806318160ddd1461005c57806370a0823114610085578063a9059cbb146100d2575b600080fd5b341561006757600080fd5b61006f61012c565b6040518082815260200191505060405180910390f35b341561009057600080fd5b6100bc600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610132565b6040518082815260200191505060405180910390f35b34156100dd57600080fd5b610112600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803590602001909190505061017a565b604051808215151515815260200191505060405180910390f35b60015481565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b600080826000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205403101515156101cb57600080fd5b816000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282540392505081905550816000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828254019250508190555060019050929150505600a165627a7a7230582098f1551a391a3e65b3ce45cfa2b3fa5f91eea9a3e7181a81454e025ea0d7151c0029")


class R2Test(unittest.TestCase):
    def test_shellcode_disasm(self):
        ql = Qiling(code=EVM_CODE, archtype="evm", verbose=QL_VERBOSE.DISABLED)
        r2 = R2(ql)
        pd = r2._cmd("pd 32")
        self.assertTrue('callvalue' in pd)

    def test_addr_flag(self):
        ql = Qiling(["../examples/rootfs/x86_windows/bin/x86_hello.exe"], "../examples/rootfs/x86_windows",
                    verbose=QL_VERBOSE.DISABLED)  # x8864_hello does not have 'main'
        r2 = R2(ql)
        print(r2.where('main'))
        self.assertEqual(r2.at(r2.where('main')), 'main')


if __name__ == "__main__":
    unittest.main()
