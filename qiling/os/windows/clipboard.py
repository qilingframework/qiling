#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
# A Simple Windows Clipboard Simulation

NOT_LOCKED = -1


class Clipboard:

    def __init__(self, ql):

        self.locked_by = NOT_LOCKED
        self.data = b"Default Clipboard Data"
        self.ql = ql
        # Valid formats taken from https://doxygen.reactos.org/d8/dd6/base_
        # 2applications_2mstsc_2constants_8h_source.html
        self.formats = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 128, 129, 130, 131, 142, 512, 767,
                        768, 1023]

    def open(self, h_wnd):
        """
        Lock clipboard to hWnd if not already locked. 
        If hWnd is null default to current thead id
        """
        if h_wnd == 0:
            hWnd = self.ql.thread_manager.current_thread.id

        if self.locked_by != NOT_LOCKED and self.locked_by != h_wnd:
            return 0
        else:
            self.locked_by = h_wnd
            return 1

    def format_available(self, fmt):
        if fmt in self.formats:
            return 1
        else:
            return 0

    def close(self):
        if self.locked_by == NOT_LOCKED:
            self.ql.commos.last_error = 0x58A  # ERROR_CLIPBOARD_NOT_OPEN
            return 0
        else:
            self.locked_by = NOT_LOCKED
            return 1

    def set_data(self, fmt, data):
        hWnd = self.ql.thread_manager.current_thread.id
        if self.locked_by != hWnd:
            self.ql.commos.last_error = 0x58A  # ERROR_CLIPBOARD_NOT_OPEN
            return 0
        else:
            if fmt not in self.formats:
                return 0
            self.data = data
            return 1

    def get_data(self, fmt):
        if fmt not in self.formats:
            return 0

        hWnd = self.ql.thread_manager.current_thread.id
        if self.locked_by != hWnd:
            self.ql.commos.last_error = 0x58A  # ERROR_CLIPBOARD_NOT_OPEN
            return 0
        else:
            return self.data
