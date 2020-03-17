#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys
sys.path.append("..")
from qiling import *

from capstone import *
from unicorn.x86_const import *
from struct import unpack

sys.path.append("..")

md = Cs(CS_ARCH_X86, CS_MODE_64)

breakOn = False
printOn = False

niBreak = []
bt = []
oldc = ""

def dump_everything(ql, address, size, user_data):
    global breakOn
    global niBreak
    global printOn
    global oldc
    global bt
    buf = ql.uc.mem_read(address, size)
    for i in md.disasm(buf, address):
        # print("PC :: 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        if i.mnemonic == "call":
            bt.append(i.address)
        if i.mnemonic == "ret":
            bt.pop()
        if i.address -  0x0000500000000000 in user_data: # dyld slide 
            breakOn = True
        if i.address in niBreak:
            breakOn = True
            niBreak.remove(i.address)
    if printOn or breakOn:
        eax = ql.uc.reg_read(UC_X86_REG_RAX)
        ebx = ql.uc.reg_read(UC_X86_REG_RBX)
        ecx = ql.uc.reg_read(UC_X86_REG_RCX)
        edx = ql.uc.reg_read(UC_X86_REG_RDX)
        edi = ql.uc.reg_read(UC_X86_REG_RDI)
        esi = ql.uc.reg_read(UC_X86_REG_RSI)
        r8 = ql.uc.reg_read(UC_X86_REG_R8)
        r9 = ql.uc.reg_read(UC_X86_REG_R9)
        r11 = ql.uc.reg_read(UC_X86_REG_R11)
        r12 = ql.uc.reg_read(UC_X86_REG_R12)
        r14 = ql.uc.reg_read(UC_X86_REG_R14)
        r15 = ql.uc.reg_read(UC_X86_REG_R15)
        ebp = ql.uc.reg_read(UC_X86_REG_RBP)
        esp = ql.uc.reg_read(UC_X86_REG_RSP)
        ds = ql.uc.reg_read(UC_X86_REG_DS)
        gs = ql.uc.reg_read(UC_X86_REG_GS)
        ss = ql.uc.reg_read(UC_X86_REG_SS)
        cs = ql.uc.reg_read(UC_X86_REG_CS)

    if printOn:
        print("PC :: 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        print(">>> RAX= 0x%lx, RBX= 0x%lx, RCX= 0x%lx, RDX= 0x%lx, RDI= 0x%lx, RSI= 0x%lx, R8=0x%lx, R9=0x%lx, R11=0x%lx, R12=0x%lx, R14=0x%lx, R15=0x%lx, RBP= 0x%lx, RSP= 0x%lx, DS= 0x%lx, GS= 0x%lx, SS= 0x%lx, CS= 0x%lx " % (
            eax, ebx, ecx, edx, edi, esi, r8, r9, r11, r12, r14, r15, ebp, esp,ds,gs,ss,cs
            ))

    if breakOn:
        print("PC :: 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        print(">>> RAX= 0x%lx, RBX= 0x%lx, RCX= 0x%lx, RDX= 0x%lx, RDI= 0x%lx, RSI= 0x%lx, R8=0x%lx, R9=0x%lx, R11=0x%lx, R12=0x%lx, R14=0x%lx, R15=0x%lx, RBP= 0x%lx, RSP= 0x%lx, DS= 0x%lx, GS= 0x%lx, SS= 0x%lx, CS= 0x%lx " % (
            eax, ebx, ecx, edx, edi, esi, r8, r9, r11, r12, r14, r15, ebp, esp,ds,gs,ss,cs
            ))
        stack_info = ql.uc.mem_read(esp, 20)
        # if i.address - 0x3000000000000000 == 0x129c3:
        #     breakOn = False
        #     # printOn = True
        #     return 

        # print(stack_info)
        print ("")
        while (True):
            c = input()
            if c == "":
                c = oldc
            if c == 'c':
                oldc = c
                breakOn = False
                # printOn = True
                break
            if c == "si" or c == "s":
                oldc = c
                break
            if c == "ni" or c == "n":
                # if i.mnemonic in ["jmp", "jne", "je", "ja", "jns", "js", "jbe"]:
                if i.mnemonic[0] == 'j' or i.mnemonic == "ret":
                    oldc = c
                    break
                else :
                    oldc = c
                    niBreak.append(address + size)
                    breakOn = False
                    break
            if c.startswith("r "):
                oldc = c
                cmdlist = c.split()
                if len(cmdlist) < 3:
                    continue
                else:
                    target_addr = int(cmdlist[1], 16)
                    read_size = int(cmdlist[2], 10)
                    content = ql.uc.mem_read(target_addr, read_size)
                    content_len = len(content)
                    print_str = ""
                    for j in range(0, content_len, 4):
                        if j + 4 <= content_len:
                            data = unpack(">L", content[j:j+4])[0]
                            print_str += "0x{:08X} ".format(data)
                    print(print_str)

            if c.startswith("stack"):
                oldc = c
                if len(c.split()) == 2:
                    slide = int(c.split()[1], 16)
                    print("stack slide: {:X}".format(slide))
                    print(ql.uc.mem_read(ebp-slide, slide))
                else:
                    print(ql.uc.mem_read(esp, ebp-esp))
            if c.startswith("b "):
                niBreak.append(int(c.split()[1], 16))
            if c == "bt":
                for k, item in enumerate(bt):
                    print("{}: 0x{:X}".format(k, item))
            if c == "show":
                ql.show_map_info()
            if c.startswith("r14"):
                if len(c.split()) == 2:
                    val14 = int(c.split()[1], 16)
                    ql.uc.reg_write(UC_X86_REG_R14, val14)
            if c.startswith("rdi"):
                if len(c.split()) == 2:
                    val14 = int(c.split()[1], 16)
                    ql.uc.reg_write(UC_X86_REG_RDI, val14)

if __name__ == "__main__":
    test_env = {
        # "DYLD_ROOT_PATH": "/lib/dyld",
    }
    apples = {
        "executable_path": ""
    }
    ql = Qiling(["rootfs/x8664_macos/bin/x8664_hello"], "rootfs/x8664_macos", env = test_env, output = "debug")
    break_point = [
        # 0x5E4B,
        # 0x5E13,
        # 0x5E96,
        # 0x05E2C,
        # 0x5E39,
        # 0x5E4B,
        # 0x060C8,
        # 0x68a2,
        # 0x6927,
        # 0x6938,
        # 0x06949,
        # 0x0695A,
        # 0x0696B,
        # 0x697F,
        # 0x06A01,
        # 0x06A41,
        # 0x06A5B,
        # 0x06D64,
        # 0x6FE3,
        # 0x70AC,
        # 0x7095,
        # 0x7045,
        # 0x6FEF,
        # 0x4F00,
        # 0x4EE7,
        # 0x4F41,
        # 0x6fe3        # link
        # 0x04f65,      # link-link
        # 0x10ADC,
        # 0x010B03,       # recursiveLoadLibraries
        # 0x0115d3,
        # 0x115fa,
        # 0x115dc,
        # 0x11794,        # load
        # 0xa954,         # load-load
        # 0x349d,         # load parse0
        # 0x37fa,         # load parse1
        # 0x9293,         # load parse3
        # 0x9ac5,         # load parse4
        # 0x34c7,             # load parse2cache
        # 0x3856,               # realpath_DARWIN_EXTSN
        # 0x02a8be,
        # 0x2AC0D,              # getattrlist
        # 0x2A9CD,
        # 0x3897,                  # error ret
        # 0x34C7
        # 0x3133C
        # 0x03AAC
        # 0x317EC,
        # 0x01822
        # 0x030748
        # 0x314A0
        # 0x12992,
        # 0x129BF,
        # 0x0129c3
        # 0x15CD8,         # error call 
        # 0x118BE           # seems like setlibimage
        # 0x15C93,            # libreExported
        # 0x1BB5A,           # library count 
        # 0x1B250,            # add lib image
        # 0x11794,            # load image
        # 0x33f0,             # load
        # 0x349d,             # loadpharse0
        # 0x649d,               # loadpharse0
        # 0x37fa,             # loadpharse1
        # 0x9ac5,             # loadpharse4
        # 0x9d45,             # loadpharse5
        # 0x09DC3,            # jump point
        # 0xa024,             # stat64
        # 0xa0a1,                # findloadedimage
        # 0xA0AC,             # if loaded
        # 0x040AE,            # addimage
        # 0x57470C,              # vm map trap
        # 0x5A2023,              # vm map in kernel platform
        # 0x5747C0
        # 0x5a55fb
        # 0x09f992,
        # 0x5b230f,
        # 0x5b9da3,
        # 0x5b9d00,
        # 0x2e82ec,
        # 0x5b7c21,
        # 0x5a55ed
        # 0x57470C
        # 0x57F9D0,            # write comm page error
        # 0x422CBC,
        # 0x4312C4,
        # 0x5A1EFE,
        # 0x4209E3,
        # 0x42EAEF,
        # 0x430C56
        # 0x5a6c44,
        # 0x5a6c1b,
        # 0x5a6AB8,
        # 0x18e000
        # 0x4235c4
        # 0x6A57DE
        # 0x4C5F
        # 0x6B87D6
        # 0x6A57BE
        # 0x6B87D6,           # call objc.A map_images_nolock
        # # 0x6c673e,           # jmp to stub
        # 0x422cbc,           # call zone->calloc
        # 0x05a1edf,          # _os_once
        # 0x420529,           # malloc_initialize
        # 0x04209e3,          # create_scalable_szone
        # 0x6A59A9,             # 0x19a9
        # 0x6A60D6,             # 0x20d6
        # 0x6A63C7,             # 0x23c7
        # 0x6A78F6,             # 0x38f6
        # 0x6A794C,             # 0x394c
        # 0x6A7A4C,             # 0x3a4c
        # 0x6A7B8B,             # 0x3b8b
        # 0x6A7DCE,             # 0x3dce
        # 0x422CBC,
        # 0x6a7d6e,
        # 0x57D9B8,
        # 0x42e8cc,
        # 0x57470C,
        # 0x5A1EA0
        # 0x6a7d6e,               # malloc zone from ptr
        # 0x422d31                # inside malloc zone from ptr
        # 0x422d31,               # malloc zone from ptr
        # 0x6a78d4,               # create hash table 
        # 0x422869,               # szone_size
        # 0x42fdbc,                 # insert rack region
        # 0xa0
        # 0x57EAE8,               # fstat64
        # 0x6a7092,               # create table from zone 
        # 0x6A7983,               # xxx
        # 0x6A78F6
        # 0x6a5ac0,               # call read_images
        # 0x6a6bf8,                # call NXcreatemaptable
        # 0x6a6bec,
        # 0x6a78d4                # inside createMapTable
        # 0x6a6be5
        # 0x6a6a43,                # inside read_images
        # 0x6a6bec,                # golbal val we concerned
        0x6a6be3                # before globalvar 

        # 0x010b03
    ]
    # ql.hook_code(dump_everything, break_point)
    # ql.gdb = "127.0.0.1:9999"
    ql.run()
