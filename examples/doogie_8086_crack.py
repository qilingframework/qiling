#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, curses, math, struct, string, time
sys.path.append("..")
from qiling import *
from qiling.const import *
from qiling.os.disk import QlDisk
from qiling.os.dos.utils import BIN2BCD
from struct import pack


# https://stackoverflow.com/questions/9829578/fast-way-of-counting-non-zero-bits-in-positive-integer
def CountBits(n):
    n = (n & 0x5555555555555555) + ((n & 0xAAAAAAAAAAAAAAAA) >> 1)
    n = (n & 0x3333333333333333) + ((n & 0xCCCCCCCCCCCCCCCC) >> 2)
    n = (n & 0x0F0F0F0F0F0F0F0F) + ((n & 0xF0F0F0F0F0F0F0F0) >> 4)
    n = (n & 0x00FF00FF00FF00FF) + ((n & 0xFF00FF00FF00FF00) >> 8)
    n = (n & 0x0000FFFF0000FFFF) + ((n & 0xFFFF0000FFFF0000) >> 16)
    n = (n & 0x00000000FFFFFFFF) + ((n & 0xFFFFFFFF00000000) >> 32) # This last & isn't strictly necessary.
    return n

def ham(lhs: int, rhs: int):
    return CountBits(lhs^rhs)

def calavghd(bs: bytes, sz: int):
    groups = len(bs) // sz
    hdsum = 0
    seqs = [ bs[i*sz:(i+1)*sz] for i in range(groups)]
    for i in range(groups-1):
        seq1 = seqs[i]
        seq2 = seqs[(i+1)%groups]
        lc = 0
        for j in range(sz):
            lc += ham(seq1[j], seq2[j])
            hdsum += ham(seq1[j], seq2[j])
    return hdsum / groups, hdsum / groups / sz

def calavghdall(bs: bytes, maxsz: int):
    r = []
    for i in range(1, maxsz):
        r.append((i, *calavghd(bs, i)))
    r.sort(key=lambda x: x[2])
    return r

# Implmentation for https://trustedsignal.blogspot.com/2015/06/xord-play-normalized-hamming-distance.html
def guess_key_size(orig: bytes, maxsz=20):
    avghd = calavghdall(orig, maxsz)
    gcd12 = math.gcd(avghd[0][0], avghd[1][0])
    gcd13 = math.gcd(avghd[0][0], avghd[2][0])
    gcd23 = math.gcd(avghd[1][0], avghd[2][0])
    if gcd12 != 1:
        if gcd12 == gcd13 and gcd12 == gcd23:
            if gcd12 in [t[0] for t in avghd[:5]]:
                if gcd12 == avghd[0][0] or gcd12 == avghd[0][1]:
                    return gcd12
    return avghd[0][0]

def is_all_printable(bs: bytes):
    for b in bs:
        if chr(b) not in string.printable:
            return False
    return True

def countchar(bs: bytes):
    d = {}
    for ch in bs:
        if ch not in d:
            d[ch] = 0
        d[ch] += 1
    r = [(chr(k), v) for k, v in d.items()]
    r.sort(key=lambda x: x[1], reverse=True)
    return r

def cal_count_for_seqs(seqs: dict):
    seqs_keys={}
    for seq in seqs:
        seqs_keys[seq] = {}
        for ch in range(0x20, 0x7E+1):
            xored = bytes([b^ch for b in seq])
            if not is_all_printable(xored):
                continue
            count = countchar(xored)
            seqs_keys[seq][ch] = count
    return seqs_keys

def search_possible_key(seqs: dict, seqs_keys: dict, max_occur=3):
    keys = set()
    cached = {}
    def _impl(seq_idx: bytes, repeated: int, key: str):
        if seq_idx == len(seqs):
            keys.add(key)
            return
        if repeated not in cached[seq_idx]:
            return
        for ch in cached[seq_idx][repeated]:
            _impl(seq_idx + 1, repeated, key + bytes([ch]))
        return
    for idx, seq in enumerate(seqs):
        cached[idx] = {}
        for ch, count in seqs_keys[seq].items():
            for tp in count[:max_occur]:
                if ord(tp[0]) not in cached[idx]:
                    cached[idx][ord(tp[0])] = []
                cached[idx][ord(tp[0])].append(ch)
    for i in range(0x20, 0x7E+1):
        _impl(0, i, b"")
    return keys

def echo_key(ql: Qiling, key):
    # Note: In most cases, users are not supposed to use `ql.os.stdscr`
    # directly. The hack here is to show the corresponding key.
    stdscr = ql.os.stdscr
    y, _ = stdscr.getmaxyx()
    stdscr.addstr(y-2, 0, f"Current key: {key}")
    stdscr.refresh()

def show_once(ql: Qiling, key):
    klen = len(key)
    ql.reg.ax = klen
    ql.mem.write(0x87F4, key)
    # Partial exectution to skip input reading
    ql.run(begin=0x801B, end=0x803d)
    echo_key(ql, key)
    time.sleep(1)

# In this stage, we show every key.
def third_stage(keys):
    # To setup terminal again, we have to restart the whole program.
    ql = Qiling(["rootfs/8086/doogie/doogie.DOS_MBR"], 
                 "rootfs/8086",
                 console=False)
    ql.add_fs_mapper(0x80, QlDisk("rootfs/8086/doogie/doogie.DOS_MBR", 0x80))
    ql.set_api((0x1a, 4), set_required_datetime, QL_INTERCEPT.EXIT)
    hk = ql.hook_code(stop, begin=0x8018, end=0x8018)
    ql.run()
    ql.hook_del(hk)
    # Snapshot API.
    ctx = ql.save()
    for key in keys:
        show_once(ql, key)
        ql.restore(ctx)


# In this stage, we crack the encrypted buffer.
def second_stage(ql: Qiling):
    data = bytes(read_until_zero(ql, 0x8809))
    key_size = guess_key_size(data) # Should be 17
    seqs = []
    for i in range(key_size):
        seq = b""
        j = i
        while j < len(data):
            seq += bytes([data[j]])
            j += key_size
        seqs.append(seq)
    seqs_keys = cal_count_for_seqs(seqs)
    keys = search_possible_key(seqs, seqs_keys)
    return keys


def read_until_zero(ql: Qiling, addr):
    buf = b""
    ch = -1
    while ch != 0:
        ch = ql.mem.read(addr, 1)[0]
        buf += pack("B", ch)
        addr += 1
    return buf

def set_required_datetime(ql: Qiling):
    ql.log.info("Setting Feburary 06, 1990")
    ql.reg.ch = BIN2BCD(19)
    ql.reg.cl = BIN2BCD(1990%100)
    ql.reg.dh = BIN2BCD(2)
    ql.reg.dl = BIN2BCD(6)

def stop(ql, addr, data):
    ql.emu_stop()

# In this stage, we get the encrypted data which xored with the specific date.
def first_stage():
    ql = Qiling(["rootfs/8086/doogie/doogie.DOS_MBR"], 
                 "rootfs/8086",
                 console=False)
    ql.add_fs_mapper(0x80, QlDisk("rootfs/8086/doogie/doogie.DOS_MBR", 0x80))
    # Doogie suggests that the datetime should be 1990-02-06.
    ql.set_api((0x1a, 4), set_required_datetime, QL_INTERCEPT.EXIT)
    # A workaround to stop the program.
    hk = ql.hook_code(stop, begin=0x8018, end=0x8018)
    ql.run()
    ql.hook_del(hk)
    return ql

if __name__ == "__main__":
    ql = first_stage()
    # resume terminal
    curses.endwin()
    keys = second_stage(ql)
    for key in keys:
        print(f"Possible key: {key}")
    # The key of this challenge is not unique. The real
    # result depends on the last ascii art.
    print("Going to try every key.")
    time.sleep(3)
    third_stage(keys)
    # resume terminal
    curses.endwin()