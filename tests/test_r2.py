#!/usr/bin/env python3

import unittest

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_ARCH, QL_VERBOSE

try:
    from qiling.extensions.r2.r2 import R2
except ImportError:
    test_r2 = False
else:
    test_r2 = True

EVM_CODE = bytes.fromhex("""
    6060604052341561000f57600080fd5b60405160208061031c83398101604052
    8080519060200190919050508060018190556000803373ffffffffffffffffff
    ffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffff
    ff16815260200190815260200160002081905550506102998061008360003960
    00f300606060405260043610610057576000357c010000000000000000000000
    0000000000000000000000000000000000900463ffffffff16806318160ddd14
    61005c57806370a0823114610085578063a9059cbb146100d2575b600080fd5b
    341561006757600080fd5b61006f61012c565b60405180828152602001915050
    60405180910390f35b341561009057600080fd5b6100bc600480803573ffffff
    ffffffffffffffffffffffffffffffffff16906020019091905050610132565b
    6040518082815260200191505060405180910390f35b34156100dd57600080fd
    5b610112600480803573ffffffffffffffffffffffffffffffffffffffff1690
    602001909190803590602001909190505061017a565b60405180821515151581
    5260200191505060405180910390f35b60015481565b60008060008373ffffff
    ffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffff
    ffffffffffffff168152602001908152602001600020549050919050565b6000
    80826000803373ffffffffffffffffffffffffffffffffffffffff1673ffffff
    ffffffffffffffffffffffffffffffffff168152602001908152602001600020
    5403101515156101cb57600080fd5b816000803373ffffffffffffffffffffff
    ffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16
    8152602001908152602001600020600082825403925050819055508160008085
    73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffff
    ffffffffffffffffffffff168152602001908152602001600020600082825401
    9250508190555060019050929150505600a165627a7a7230582098f1551a391a
    3e65b3ce45cfa2b3fa5f91eea9a3e7181a81454e025ea0d7151c0029
""")


@unittest.skipUnless(test_r2, 'libr is missing')
class R2Test(unittest.TestCase):
    def test_shellcode_disasm(self):
        ql = Qiling(code=EVM_CODE, archtype=QL_ARCH.EVM, verbose=QL_VERBOSE.DISABLED)
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
