#!/usr/bin/env python3

import os, platform, sys, unittest

sys.path.append("..")
from qiling import Qiling

SECRET_KEY = os.environ.get('AM_I_IN_A_DOCKER_CONTAINER', False)

if SECRET_KEY:
    sys.exit(0)

if platform.system() == "Darwin" and platform.machine() == "arm64":
    sys.exit(0)    

class Checklist:
    def __init__(self) -> None:
        self.visited_hookcode = False
        self.visited_hookinsn = False
        self.visited_hookaddr = False

class EVMTest(unittest.TestCase):
    def test_underflow_code(self):
        ql = Qiling(code="0x6060604052341561000f57600080fd5b60405160208061031c833981016040528080519060200190919050508060018190556000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555050610299806100836000396000f300606060405260043610610057576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806318160ddd1461005c57806370a0823114610085578063a9059cbb146100d2575b600080fd5b341561006757600080fd5b61006f61012c565b6040518082815260200191505060405180910390f35b341561009057600080fd5b6100bc600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610132565b6040518082815260200191505060405180910390f35b34156100dd57600080fd5b610112600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803590602001909190505061017a565b604051808215151515815260200191505060405180910390f35b60015481565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b600080826000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205403101515156101cb57600080fd5b816000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282540392505081905550816000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828254019250508190555060019050929150505600a165627a7a7230582098f1551a391a3e65b3ce45cfa2b3fa5f91eea9a3e7181a81454e025ea0d7151c0029",archtype="evm", verbose=4)
        testcheck = Checklist()
        argu = ql.arch.evm.abi.convert(['uint256'], [20])
        code = ql.code + argu

        user1 = ql.arch.evm.create_account(balance=100*10**18)
        user2 = ql.arch.evm.create_account(balance=100*10**18)
        c1 = ql.arch.evm.create_account()

        def hookcode_test(ql, *argv):
            testcheck.visited_hookcode = True

        def hookinsn_test(ql, *argv):
            testcheck.visited_hookinsn = True

        def hookaddr_test(ql, *argv):
            testcheck.visited_hookaddr = True

        h0 = ql.hook_code(hookcode_test)
        h1 = ql.hook_address(hookaddr_test, 10)

        # message1: deploy runtime code
        msg0 = ql.arch.evm.create_message(user1, b'', code=code, contract_address=c1)
        ql.run(code=msg0)

        ql.hook_del(h0)
        ql.hook_del(h1)
        h2 = ql.hook_insn(hookinsn_test, 'PUSH4')

        #  # SMART CONTRACT DEPENDENT - message2: check balance of user1, should be 20
        def check_balance(sender, destination):
            call_data = '0x70a08231'+ql.arch.evm.abi.convert(['address'], [sender])
            msg2 = ql.arch.evm.create_message(sender, destination, call_data)
            return ql.run(code=msg2)
        
        result = check_balance(user1, c1)
        print('\n\nuser1 balance =', int(result.output.hex()[2:], 16))
        ql.hook_del(h2)

        # SMART CONTRACT DEPENDENT - message3: transform 21 from user1 to user2
        call_data = '0xa9059cbb'+ ql.arch.evm.abi.convert(['address'], [user2]) + \
                                        ql.arch.evm.abi.convert(['uint256'], [21])
        msg1 = ql.arch.evm.create_message(user1, c1, call_data)    
        result = ql.run(code=msg1)
        print('\n\nis success =', int(result.output.hex()[2:], 16))

        # message4: check balance of user1, should be MAX - 1
        result = check_balance(user1, c1)
        print('\n\nuser1 balance =', hex(int(result.output.hex()[2:], 16)))
        
        self.assertEqual(hex(int(result.output.hex()[2:], 16)), '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
        self.assertTrue(testcheck.visited_hookaddr)
        self.assertTrue(testcheck.visited_hookcode)
        self.assertTrue(testcheck.visited_hookinsn)

    def test_underflow_filename(self):
        ql = Qiling(["../examples/rootfs/evm/Hexagon.hex"], archtype="evm", verbose=4)

        user1 = ql.arch.evm.create_account(balance=100*10**18)
        user2 = ql.arch.evm.create_account(balance=100*10**18)
        c1 = ql.arch.evm.create_account()

        def check_balance(sender, destination):
            call_data = '0x70a08231'+ql.arch.evm.abi.convert(['address'], [sender])
            msg2 = ql.arch.evm.create_message(sender, destination, data=call_data)
            return ql.run(code=msg2)

        # Deploy runtime code
        msg0 = ql.arch.evm.create_message(user1, b'', contract_address=c1)
        ql.run(code=msg0)

        # # SMART CONTRACT DEPENDENT: check balance of user1
        result = check_balance(user1, c1)
        print('User1 balance =', int(result.output.hex()[2:], 16))

        # # SMART CONTRACT DEPENDENT: transform from user1 to user2
        call_data = '0xa9059cbb'+ ql.arch.evm.abi.convert(['address'], [user2]) + \
                                        ql.arch.evm.abi.convert(['uint256'], [0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe])
        msg1 = ql.arch.evm.create_message(user1, c1, data=call_data)    
        result = ql.run(code=msg1)
        if int(result.output.hex()[2:], 16) ==  1:
            print('User1 transfered Token to User1')

        # # SMART CONTRACT DEPENDENT: User1 balance underflow, MAX - 1
        result = check_balance(user1, c1)
        self.assertEqual(int(result.output.hex()[2:], 16), 420000000000000)

        result = check_balance(user2, c1)
        self.assertEqual(int(result.output.hex()[2:], 16), 452312848583266388373324160190187140051835877600158453279131187530910662654)

    def test_abi_encoding(self):
        ql = Qiling(code="0x608060405234801561001057600080fd5b506101a4806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c8063ead710c414610030575b600080fd5b6100e96004803603602081101561004657600080fd5b810190808035906020019064010000000081111561006357600080fd5b82018360208201111561007557600080fd5b8035906020019184600183028401116401000000008311171561009757600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290505050610164565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561012957808201518184015260208101905061010e565b50505050905090810190601f1680156101565780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b606081905091905056fea2646970667358221220cf43353b75256fc42aaffd9632e06963c5c2aad72a91004bfd2f98cd56ae1a0c64736f6c63430006000033",archtype="evm", verbose=4)

        user1 = ql.arch.evm.create_account(balance=100*10**18)
        c1 = ql.arch.evm.create_account()

        # Deploy runtime code
        msg0 = ql.arch.evm.create_message(user1, b'', contract_address=c1)
        ql.run(code=msg0)

        # # SMART CONTRACT DEPENDENT: transform from user1 to user2
        call_param = ['Hello World']
        call_data = ql.arch.evm.abi.encode_function_call('greet(string)', call_param)

        function_abi = {
            'name': 'greet',
            'type': 'function',
            'inputs': [{
                'type': 'string',
                'name': ''
            }]
        }
        call_data2 = ql.arch.evm.abi.encode_function_call_abi(function_abi, call_param)
        call_data3 = '0xead710c4'+ ql.arch.evm.abi.convert(['string'], call_param)

        self.assertEqual(call_data, call_data2)
        self.assertEqual(call_data, call_data3)

        msg1 = ql.arch.evm.create_message(user1, c1, data=call_data)
        result = ql.run(code=msg1)
        
        result_data = ql.arch.evm.abi.decode_params(['string'], result.output)
        self.assertEqual(call_param[0], result_data[0])

if __name__ == "__main__":
    unittest.main()