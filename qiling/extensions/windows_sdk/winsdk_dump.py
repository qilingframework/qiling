#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

# windows sdk data file can download here: 'https://github.com/ohjeongwook/windows_sdk_data.git'

import json
import os

result_dict = {}


def parse_winsdk(dir):
    def PtrDecl_detect(dic):
        param_dict = {}
        if dic['data_type'] in ['PtrDecl', 'ArrayDecl']:
            return PtrDecl_detect(dic['type'])
        elif dic['data_type'] == 'TypeDecl':
            if 'name' in dic.keys():
                param_dict['name'] = dic['name']
            else:
                param_dict['name'] = 'VOID'
            param_dict['type'] = dic['type']
        elif dic['data_type'] == 'FuncDecl':
            param_dict['name'] = dic['func']['name']
            param_dict['type'] = dic['func']['type']['type']
        else:
            print(dic['data_type'])
            exit(0)
        return param_dict

    if dir != '.DS_Store':
        with open("../data/" + dir, 'r') as f:
            winsdk = json.loads(f.read())
            f.close()
    else:
        return

    entry = 'funcdefs'

    for func in winsdk[entry]:     # read function dict
        if 'name' in func.keys():
            func_name = func['name']
        elif func['type']['data_type'] == 'TypeDecl':
            func_name = func['type']['name']
        else:
            func_name = func['type']['type']['name']

        if 'api_locations' in func.keys():
            func_dll = func['api_locations'][0].lower()
        else:
            continue

        func_dict = {}
        param_list = []
        argument = func['arguments']

        for argu in argument:
            param = PtrDecl_detect(argu)
            param_list.append(param)
            func_dict[func_name] = param_list

        if func_dll in result_dict.keys():
            old_func_dict = result_dict[func_dll].copy()
            result_dict[func_dll] = {}
            result_dict[func_dll] = dict(old_func_dict, **func_dict)
        else:
            result_dict[func_dll] = func_dict


def save2json():
    print("begin to save ...")
    for dllname in result_dict:
        result_json = json.dumps(result_dict[dllname], sort_keys=False, indent=4, separators=(',', ': '))
        print(dllname)
        if dllname[0].isupper():
            dllname = '_'+dllname
        fo = open('./windows_sdk/'+dllname.replace('.', '_')+'.json', 'w+')
        fo.write(result_json)
        fo.close()


if __name__ == '__main__':
    dir = '../data'
    result_dict = {}
    for parent, dirnames, filenames in os.walk(dir, followlinks=True):
        for filename in filenames:
            parse_winsdk(filename)
    save2json()
