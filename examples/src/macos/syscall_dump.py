#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)
# The 'macos_syscall' can be download at 'https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master'.
# The 'ios_syscall' can be download at 'https://github.com/radareorg/radare2/blob/master/libr/include/sflib/darwin-arm-64/ios-syscalls.txt'.

def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        pass

    try:
        import unicodedata
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass

    return False


def readfile_mac(f_mac):
    mac_dict = {}
    indexlist = []
    line = f_mac.readline()
    while line:
        if is_number(line[0]):
            index = line.split(' ')[0].split('\t')[0]
            if index not in indexlist:
                name = line.split(' ')[2]
                if name == '':
                    name = line.split('    ')[3].split(' ')[3].split('(')[0]
                name = name.replace('__', '')
                indexlist.append(index)
                if name == '':
                    name = line.split('    ')[3].split(' ')[3]
                name = name.split('(')[0]
                # print(index, name)
                mac_dict.update({name: index})
        line = f_mac.readline()
    # print(mac_dict)
    return mac_dict


def readfile_ios(f_ios):
    ios_dict = {}
    indexlist = []
    line = f_ios.readline()
    while line:
        if is_number(line[0]):
            index = line.split('\t')[0]
            name = line.split('\t')[1].split('\n')[0]
            name = name.replace('__', '')
            if name[0] == '_':
                name = name[1:]
            if index not in indexlist:
                indexlist.append(index)
                # print(index, name)
                ios_dict.update({name: index})
        line = f_ios.readline()
    # print(ios_dict)
    return ios_dict


def merge(mac_dict, ios_dict):
    # (mac, ios) (mac, -1) (-1, ios)
    for key in mac_dict:
        mac_dict[key] = (mac_dict[key], -1)
    for key in ios_dict:
        if key in mac_dict.keys():
            mac_value = mac_dict[key][0]
            ios_value = ios_dict[key]
            # print(ios_dict[key])
            mac_dict[key] = (int(mac_value), int(ios_value))
        else:
            mac_dict.update({key: (-1, int(ios_dict[key]))})

    for i in mac_dict:
        # print(i, mac_dict[i])
        print('    \"'+i+'\": ('+str(mac_dict[i][0])+', '+str(mac_dict[i][1])+'),')


if __name__ == '__main__':
    file_mac = open('./macos_syscall')
    mac_dict = readfile_mac(file_mac)
    file_ios = open('./ios_syscall')
    ios_dict = readfile_ios(file_ios)
    merge(mac_dict, ios_dict)
