#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
# A Simple Windows Clipboard Simulation

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from qiling.os.windows.windows import QlOsWindows

NOT_LOCKED = -1
ERROR_CLIPBOARD_NOT_OPEN = 0x58a

class Clipboard:

    def __init__(self, os: 'QlOsWindows'):
        self.locked_by = NOT_LOCKED
        self.data = b"Default Clipboard Data"
        self.os = os

        # Valid formats taken from https://doxygen.reactos.org/d8/dd6/base_
        # 2applications_2mstsc_2constants_8h_source.html
        self.formats = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 128, 129, 130, 131, 142, 512, 767, 768, 1023]

    def open(self, h_wnd: int) -> bool:
        """Lock clipboard to hWnd if not already locked.
        If hWnd is null default to current thead id
        """

        if h_wnd == 0:
            h_wnd = self.os.thread_manager.cur_thread.id

        if self.locked_by != NOT_LOCKED and self.locked_by != h_wnd:
            return False

        self.locked_by = h_wnd

        return True

    def close(self) -> bool:
        if self.locked_by == NOT_LOCKED:
            self.os.last_error = ERROR_CLIPBOARD_NOT_OPEN
            return False

        self.locked_by = NOT_LOCKED

        return True

    def format_available(self, fmt: int) -> bool:
        return fmt in self.formats

    def set_data(self, fmt: int, data: bytes) -> int:
        if fmt not in self.formats:
            return 0

        hWnd = self.os.thread_manager.cur_thread.id

        if self.locked_by != hWnd:
            self.os.last_error = ERROR_CLIPBOARD_NOT_OPEN
            return 0

        self.data = data

        # BUG: this should be the handle of the clipboard object
        return 1

    def get_data(self, fmt: int) -> Optional[bytes]:
        if fmt not in self.formats:
            return None

        hWnd = self.os.thread_manager.cur_thread.id

        if self.locked_by != hWnd:
            self.os.last_error = ERROR_CLIPBOARD_NOT_OPEN
            return None

        return self.data
