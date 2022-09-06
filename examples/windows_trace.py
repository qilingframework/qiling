#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
import argparse
import pefile

from binascii import hexlify
from capstone import *

import sys
sys.path.append('..')

from qiling import Qiling
from qiling.const import QL_VERBOSE

class colors:
    if sys.stdout.isatty():
        BLUE = '\033[94m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'
    else:
        HEADER = ''
        BLUE = ''
        GREEN = ''
        YELLOW = ''
        RED = ''
        ENDC = ''
        BOLD = ''
        UNDERLINE = ''


def dump_regs(ql: Qiling):
    regs = {
        'eax': ql.reg.eax,
        'ebx': ql.reg.ebx,
        'ecx': ql.reg.ecx,
        'edx': ql.reg.edx,
        'edi': ql.reg.edi,
        'esi': ql.reg.esi,
        'ebp': ql.reg.ebp,
        'esp': ql.reg.esp
    }

    if not hasattr(dump_regs, 'regs'):
        dump_regs.regs = regs

    rtn = ''

    # build string in order
    for reg in ('eax', 'ebx', 'ecx', 'edx', 'edi', 'esi', 'ebp', 'esp'):
        val = '{}: {:08X}    '.format(reg.upper(), regs[reg])

        if regs[reg] != dump_regs.regs[reg]:
            rtn += colors.RED + val + colors.ENDC
        else:
            rtn += val

    dump_regs.regs = regs

    return rtn


def spaced_hex(data):
    return b' '.join(hexlify(data)[i:i + 2] for i in range(0, len(hexlify(data)), 2)).decode('utf-8')


def disasm(count, ql: Qiling, address: int, size: int):
    buf = ql.mem.read(address, size)
    try:
        for i in md.disasm(buf, address):
            return "{:08X}\t{:08X}: {:24s} {:10s} {:16s}".format(count[0], i.address, spaced_hex(buf), i.mnemonic,
                                                                 i.op_str)
    except:
        import traceback
        print(traceback.format_exc())


def trace(ql: Qiling):
    count = [0]
    ql.hook_code(trace_cb, count)


def trace_cb(ql: Qiling, address: int, size: int, count):
    rtn = '{:100s}'.format(disasm(count, ql, address, size))
    if args.reg:
        try:
            rtn += dump_regs(ql)
        except:
            import traceback
            print(traceback.format_exc())
    print(rtn)
    count[0] += 1


def emulate(path, rootfs, verbose=QL_VERBOSE.DEBUG, enable_trace=False):
    ql = Qiling([path], rootfs, verbose=verbose)

    if enable_trace:
        trace(ql)

    ql.run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Trace Windows executable')
    parser.add_argument("-r", "--reg", help="Dump register values with trace option", action='store_true',
                        default=False)
    parser.add_argument("-t", "--trace", help="Enable full trace", action='store_true', default=False)
    parser.add_argument("-R", "--root", help="rootfs", default=None)
    parser.add_argument("-d", "--dump", help="Directory to dump memory regions to", default="dump")
    #parser.add_argument("-a", "--automatize_input", help="Automatize writes on standard input", default=False)
    parser.add_argument("-p ", "--profile", help="customized profile",
                        default="qiling/profiles/windows.ql")
    parser.add_argument('input', nargs='*')
    args = parser.parse_args()
    for path in args.input:
        pe = pefile.PE(path)

        if pe.FILE_HEADER.Machine == 0x14c:
            mode = 32
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        else:
            mode = 64
            md = Cs(CS_ARCH_X86, CS_MODE_64)

        # setup default rootfs if option not provided
        if not args.root:
            if mode == 32:
                args.root = os.path.join(os.getcwd(), 'rootfs', 'x86_windows')
            else:
                args.root = os.path.join(os.getcwd(), 'rootfs', 'x8664_windows')

        emulate(path, args.root, verbose=QL_VERBOSE.DEBUG, enable_trace=args.trace)
