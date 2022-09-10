#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
# A Simple Windows Clipboard Simulation

from typing import TYPE_CHECKING, Optional

from qiling.os.windows.const import *

if TYPE_CHECKING:
    from qiling.os.windows.windows import QlOsWindows

NOT_LOCKED = -1

class Clipboard:

    def __init__(self, os: 'QlOsWindows'):
        self.locked_by = NOT_LOCKED
        self.data = b"Default Clipboard Data"
        self.os = os

        self.formats = [
            CF_TEXT, CF_BITMAP, CF_METAFILEPICT, CF_SYLK, CF_DIF, CF_TIFF, CF_OEMTEXT, CF_DIB,
            CF_PALETTE, CF_PENDATA, CF_RIFF, CF_WAVE, CF_UNICODETEXT, CF_ENHMETAFILE, CF_HDROP,
            CF_LOCALE, CF_MAX, CF_OWNERDISPLAY, CF_DSPTEXT, CF_DSPBITMAP, CF_DSPMETAFILEPICT,
            CF_DSPENHMETAFILE, CF_PRIVATEFIRST, CF_PRIVATELAST, CF_GDIOBJFIRST, CF_GDIOBJLAST
        ]

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

    def set_data(self, format: int, address: int) -> int:
        hWnd = self.os.thread_manager.cur_thread.id

        if self.locked_by != hWnd:
            self.os.last_error = ERROR_CLIPBOARD_NOT_OPEN
            return 0

        def __handle_text(a: int) -> bytes:
            return self.os.utils.read_cstring(a).encode()

        def __handle_uctext(a: int) -> bytes:
            return self.os.utils.read_wstring(a).encode()

        # TODO: support more clipboard formats
        format_handlers = {
            CF_TEXT        : __handle_text,
            CF_UNICODETEXT : __handle_uctext
        }

        if format not in format_handlers:
            return 0

        self.data = format_handlers[format](address)

        # TODO: should create a handle for the clipboard object?
        return address

    def get_data(self, format: int) -> Optional[bytes]:
        if format not in self.formats:
            return None

        hWnd = self.os.thread_manager.cur_thread.id

        if self.locked_by != hWnd:
            self.os.last_error = ERROR_CLIPBOARD_NOT_OPEN
            return None

        return self.data
