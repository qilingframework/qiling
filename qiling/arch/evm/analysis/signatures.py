import os
import re
import logging
import json


class solidity_function:
    def __init__(self, xref, start_insn, sign, name, prefered_name) -> None:
        self.xref = xref
        self.start_insn = start_insn
        self.end_insn = None
        self.code = None

        self.sign = sign
        self.name = name
        self.prefered_name = prefered_name

        self.argu_count = 0
        self.most_prefered_name = []

    def analysis_args(self):
        for i in self.code:
            if isinstance(i, dict):
                if i['opcode'] == 'CALLDATALOAD':
                    self.argu_count += 1
            else:
                if i.mnemonic == 'CALLDATALOAD':
                    self.argu_count += 1

        for i in self.prefered_name:
            args = re.findall(r'[(](.*?)[)]', i)
            args_count = 0 if args[0] == '' else len(args[0].split(','))
            if args_count == self.argu_count:
                self.most_prefered_name.append(i)


def analysis_func_sign(insns:list, engine_num=1):
    insns = list(insns.values())
    funcs = []

    for insn in insns:
        try:
            # PUSH4 are used to push the function signature on the stack
            if insn.mnemonic == 'PUSH4':
                index = insns.index(insn)
                list_inst = insns[index:index + 4]
                push4, eq, push, jumpi = list_inst[0], list_inst[1], list_inst[2], list_inst[3]

                # check if this basicblock test function signature
                if eq.mnemonic == 'EQ' and push.mnemonic in ['PUSH1', 'PUSH2'] and jumpi.mnemonic == 'JUMPI':
                    xref = int(push.imm_op[2:] ,16)
                    sign = '0x' + push4.imm_op[2:].rjust(8, '0')
                    name = 'func_' + sign
                    if engine_num == 1:
                        prefered_name = signatures_engine_1.find_signature(sign)
                    else:
                        raise IndexError

                    # find instr with offset == xref
                    func_start_insn = next(filter(lambda i: i.pc == xref, insns))

                    # create new function
                    func = solidity_function(xref, func_start_insn, sign, name, prefered_name)
                    funcs.append(func)

            if insn.mnemonic in ['RETURN', 'STOP']:
                break
                
        except ValueError:
            continue
        except IndexError:
            logging.warning('analysis_func_sign engine number Exception')
            pass
        except:
            logging.warning('analysis_func_sign Failed')
            pass

    for i in funcs:
        start_index = insns.index(i.start_insn)

        for insn in insns[start_index:]:
            if insn.mnemonic in ['RETURN', 'STOP', 'JUMP']:
                insn.end_insn = insn
                end_index = insns.index(insn.end_insn)
                i.code = insns[start_index:end_index+1]
                i.analysis_args()
                break

    return funcs

###
class signatures_engine_1:
    @staticmethod
    def find_signature(sign):
        path = os.path.split(os.path.realpath(__file__))[0] + '/signatures.json'
        with open(path) as data_file:
            data = json.load(data_file)

        list_name = [name for name, hexa in data.items() if hexa == sign]

        if len(list_name) > 1:
            logging.warning('function signatures collision: %s', list_name)
            return '_or_'.join(list_name)
        elif list_name:
            return list_name[0]
        else:
            return None
