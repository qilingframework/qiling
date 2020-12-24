#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from logging import getLevelName
from gevent.event import Event
from queue import Queue
import gevent
import logging

class QlLinuxFutexManagement:
    
    FUTEX_BITSET_MATCH_ANY = 0xffffffff
    
    def __init__(self):
        self._wait_list = {}
    
    @property
    def wait_list(self):
        return self._wait_list
    
    def futex_wait(self, ql, uaddr, t, val, bitset=FUTEX_BITSET_MATCH_ANY):
        def _sched_wait_event(cur_thread):
            logging.debug(f"[Thread {cur_thread.get_id()}] Wait for notifications.")
            event.wait()
        uaddr_value = ql.unpack32(ql.mem.read(uaddr, 4))
        if uaddr_value != val:
            logging.debug(f"uaddr: {hex(uaddr_value)} != {hex(val)}")
            return -1
        ql.emu_stop()
        if uaddr not in self.wait_list.keys():
            self.wait_list[uaddr] = Queue()
        event = Event()
        self.wait_list[uaddr].put((bitset, t, event))
        t.sched_cb = _sched_wait_event
        return 0
    
    def get_futex_wake_list(self, ql, addr, number, bitset=FUTEX_BITSET_MATCH_ANY):
        wakes = []
        if addr not in self.wait_list or number == 0:
            logging.debug(f"No thread at {hex(addr)}")
            return wakes
        thread_queue = self.wait_list[addr]
        if thread_queue.qsize() < number:
            number = thread_queue.qsize()
        for _ in range(number):
            orig_bitset, thread, event = thread_queue.get()
            if orig_bitset & bitset:
                wakes.append((thread, event))
        if self.wait_list[addr].qsize() == 0:
            del self.wait_list[addr]
        return wakes

    def futex_wake(self, ql, uaddr, t, number, bitset=FUTEX_BITSET_MATCH_ANY):
        def _sched_set_event(cur_thread):
            for t, e in wakes:
                logging.debug(f"[Thread {cur_thread.get_id()}] Notify [Thread {t.get_id()}].")
                e.set()
            # Give up control.
            gevent.sleep(0)

        ql.emu_stop()
        wakes = self.get_futex_wake_list(ql, uaddr, number, bitset)
        t.sched_cb = _sched_set_event

        return len(wakes)
