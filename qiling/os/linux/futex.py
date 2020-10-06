#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

class QlLinuxFutexManagement:
    def __init__(self):
        self.wait_list = {}

    FUTEX_BITSET_MATCH_ANY = 0xffffffff
    
    def futex_wait(self, ql, uaddr, t, val, bitset=FUTEX_BITSET_MATCH_ANY):
        # self.wait_list.append(uaddr, t)
        if ql.unpack32(ql.mem.read(uaddr, 4)) != val:
            return -1
        ql.emu_stop()
        if uaddr not in self.wait_list.keys():
            self.wait_list[uaddr] = []
        self.wait_list[uaddr].append({'bitset': bitset, 'thread': t})
        t.blocking()
        t.set_blocking_condition(None, None)
        return 0
    
    def futex_wake(self, uaddr, number, bitset=FUTEX_BITSET_MATCH_ANY):
        if uaddr not in self.wait_list.keys():
            return 0
        
        if number > len(self.wait_list[uaddr]):
            number = len(self.wait_list[uaddr])

        wake_list = []
        for ind, t in enumerate(self.wait_list[uaddr]):
            if t['bitset'] & bitset:
                t['thread'].running()
                wake_list.append(ind)
            if len(wake_list) >= number:
                break
        # remove waked thread
        while wake_list:
            self.wait_list[uaddr].pop(wake_list.pop())

        if self.wait_list[uaddr] == []:
            del self.wait_list[uaddr]
        return number
