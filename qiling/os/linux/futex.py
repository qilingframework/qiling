#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

class QlLinuxFutexManagement:
    def __init__(self):
        self.wait_list = {}
    
    def futex_wait(self, uaddr, t):
        # self.wait_list.append(uaddr, t)
        if uaddr not in self.wait_list.keys():
            self.wait_list[uaddr] = []
        self.wait_list[uaddr].append(t)
        t.blocking()
        t.set_blocking_condition(None, None)
    
    def futex_wake(self, uaddr, number):
        if uaddr not in self.wait_list.keys():
            return -1
        
        if number > len(self.wait_list[uaddr]):
            number = len(self.wait_list[uaddr])

        for i in range(number):
            self.wait_list[uaddr][i].running()
            
        self.wait_list[uaddr] = self.wait_list[uaddr][number : ]

        if self.wait_list[uaddr] == []:
            del self.wait_list[uaddr]