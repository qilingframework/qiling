
from typing import TYPE_CHECKING, AnyStr, Optional, Sized

if TYPE_CHECKING:
    from qiling.os.linux.linux import QlOsLinux


class QlFileSeekable:

    def __init__(self):
        self.buff: Sized
        self.pos = 0

    def seek(self, offset: int, whence: int) -> int:
        assert whence in (0, 1, 2)

        # SEEK_SET
        if whence == 0:
            pos = offset

        # SEEK_CUR
        elif whence == 1:
            pos = self.pos + offset

        # SEEK_END
        elif whence == 2:
            pos = len(self.buff) + offset

        # make sure pos is within reasonabe boundaries
        self.pos = min(max(pos, 0), len(self.buff))

        return self.pos

    def ftell(self) -> int:
        return self.pos


class QlFileReadable:

    def __init__(self, *, content: Optional[bytearray] = None):
        self.buff = content or bytearray()
        self.pos = 0

    def read(self, length: int = -1) -> bytes:
        if length == -1:
            length = len(self.buff)

        content = self.buff[self.pos:length]
        self.pos = min(self.pos + length, len(self.buff))

        return bytes(content)


class QlFileProcFS(QlFileReadable, QlFileSeekable):

    def __init__(self, content: bytearray):
        QlFileReadable.__init__(self, content=content)
        QlFileSeekable.__init__(self)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.close()

    def close(self):
        pass


class QlProcFS:

    @staticmethod
    def self_auxv(os: 'QlOsLinux') -> QlFileProcFS:
        nbytes = os.ql.arch.bits // 8

        auxv_addr = os.ql.loader.auxv
        null_entry = bytes(nbytes * 2)

        auxv_data = bytearray()

        # keep reading until AUXV.AT_NULL is reached
        while not auxv_data.endswith(null_entry):
            auxv_data.extend(os.ql.mem.read(auxv_addr, nbytes))
            auxv_addr += nbytes

            auxv_data.extend(os.ql.mem.read(auxv_addr, nbytes))
            auxv_addr += nbytes

        return QlFileProcFS(content=auxv_data)


    @staticmethod
    def self_cmdline(os: 'QlOsLinux') -> QlFileProcFS:
        entries = (arg.encode('utf-8') for arg in os.ql.argv)
        cmdline = bytearray(b'\x00'.join(entries) + b'\x00')

        return QlFileProcFS(content=cmdline)


    @staticmethod
    def self_environ(os: 'QlOsLinux') -> QlFileProcFS:
        def __to_bytes(s: AnyStr) -> bytes:
            if isinstance(s, str):
                return s.encode('utf-8')

            return s

        entries = (b'='.join((__to_bytes(k), __to_bytes(v))) for k, v in os.ql.env.items())
        environ = bytearray(b'\x00'.join(entries) + b'\x00')

        return QlFileProcFS(content=environ)


    @staticmethod
    def self_exe(os: 'QlOsLinux') -> QlFileProcFS:
        with open(os.ql.path, 'rb') as exefile:
            content = bytearray(exefile.read())

        return QlFileProcFS(content=content)
