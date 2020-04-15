#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

"""
This module is intended for general purpose functions that are only used in qiling.os
"""

import struct, os, configparser

from binascii import unhexlify

from unicorn import *
from unicorn.arm_const import *
from unicorn.x86_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *

from capstone import *
from capstone.arm_const import *
from capstone.x86_const import *
from capstone.arm64_const import *
from capstone.mips_const import *

from keystone import *

from qiling.const import *
from qiling.exception import *
from qiling.const import *

def ql_lsbmsb_convert(ql, sc, size=4):
    split_bytes = []
    n = size
    for index in range(0, len(sc), n):
        split_bytes.append((sc[index: index + n])[::-1])

    ebsc = b""
    for i in split_bytes:
        ebsc += i

    return ebsc    


def ql_init_configuration(self):
    config = configparser.ConfigParser()
    config.read(self.profile)
    self.ql.dprint(D_RPRT, "[+] Added configuration file")
    for section in config.sections():
        self.ql.dprint(D_RPRT, "[+] Section: %s" % section)
        for key in config[section]:
            self.ql.dprint(D_RPRT, "[-] %s %s" % (key, config[section][key]) )
    return config


def ql_compile_asm(ql, archtype, runcode, arm_thumb= None):
    def ks_convert(arch):
        if ql.archendian == QL_ENDIAN.EB:
            adapter = {
                QL_ARCH.X86: (KS_ARCH_X86, KS_MODE_32),
                QL_ARCH.X8664: (KS_ARCH_X86, KS_MODE_64),
                QL_ARCH.MIPS32: (KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN),
                QL_ARCH.ARM: (KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_BIG_ENDIAN),
                QL_ARCH.ARM_THUMB: (KS_ARCH_ARM, KS_MODE_THUMB),
                QL_ARCH.ARM64: (KS_ARCH_ARM64, KS_MODE_ARM),
            }
        else:
            adapter = {
                QL_ARCH.X86: (KS_ARCH_X86, KS_MODE_32),
                QL_ARCH.X8664: (KS_ARCH_X86, KS_MODE_64),
                QL_ARCH.MIPS32: (KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_LITTLE_ENDIAN),
                QL_ARCH.ARM: (KS_ARCH_ARM, KS_MODE_ARM),
                QL_ARCH.ARM_THUMB: (KS_ARCH_ARM, KS_MODE_THUMB),
                QL_ARCH.ARM64: (KS_ARCH_ARM64, KS_MODE_ARM),
            }

        if arch in adapter:
            return adapter[arch]
        # invalid
        return None, None

    def compile_instructions(fname, archtype, archmode):
        f = open(fname, 'rb')
        assembly = f.read()
        f.close()

        ks = Ks(archtype, archmode)

        shellcode = ''
        try:
            # Initialize engine in X86-32bit mode
            encoding, count = ks.asm(assembly)
            shellcode = ''.join('%02x' % i for i in encoding)
            shellcode = unhexlify(shellcode)

        except KsError as e:
            raise

        return shellcode

    if arm_thumb == True and archtype == QL_ARCH.ARM:
        archtype = QL_ARCH.ARM_THUMB

    archtype, archmode = ks_convert(archtype)
    return compile_instructions(runcode, archtype, archmode)


def ql_transform_to_link_path(ql, path):
    if ql.multithread == True:
        cur_path = ql.os.thread_management.cur_thread.get_current_path()
    else:
        cur_path = ql.os.current_path

    rootfs = ql.rootfs

    if path[0] == '/':
        relative_path = os.path.abspath(path)
    else:
        relative_path = os.path.abspath(cur_path + '/' + path)

    from_path = None
    to_path = None
    for fm, to in ql.fs_mapper:
        fm_l = len(fm)
        if len(relative_path) >= fm_l and relative_path[: fm_l] == fm:
            from_path = fm
            to_path = to
            break

    if from_path != None:
        real_path = os.path.abspath(to_path + relative_path[fm_l:])
    else:
        real_path = os.path.abspath(rootfs + '/' + relative_path)

    return real_path


def ql_transform_to_real_path(ql, path):
    if ql.multithread == True:
        cur_path = ql.os.thread_management.cur_thread.get_current_path()
    else:
        cur_path = ql.os.current_path

    rootfs = ql.rootfs
            
    if path.startswith == '/':
        relative_path = os.path.abspath(path)
    else:
        relative_path = os.path.abspath(cur_path + '/' + path)

    from_path = None
    to_path = None
    for fm, to in ql.fs_mapper:
        fm_l = len(fm)
        if len(relative_path) >= fm_l and relative_path[: fm_l] == fm:
            from_path = fm
            to_path = to
            break

    if from_path != None:
        real_path = os.path.abspath(to_path + relative_path[fm_l:])
    else:
        if rootfs == None:
            rootfs = ""
        real_path = os.path.abspath(rootfs + '/' + relative_path)

        if os.path.islink(real_path):
            link_path = os.readlink(real_path)
            if link_path[0] == '/':
                real_path = ql.os.transform_to_real_path(link_path)
            else:
                real_path = ql.os.transform_to_real_path(os.path.dirname(relative_path) + '/' + link_path)

    return real_path


def ql_transform_to_relative_path(ql, path):
    if ql.multithread == True:
        cur_path = ql.os.thread_management.cur_thread.get_current_path()
    else:
        cur_path = ql.os.current_path

    if path[0] == '/':
        relative_path = os.path.abspath(path)
    else:
        relative_path = os.path.abspath(cur_path + '/' + path)

    return relative_path


def ql_post_report(self):
    self.ql.dprint(D_INFO, "[+] Syscalls and number of invocations")
    self.ql.dprint(D_INFO, "[-] " + str(list(self.ql.os.syscall_count.items())))
