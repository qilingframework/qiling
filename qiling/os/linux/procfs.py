
import io
from typing import TYPE_CHECKING, AnyStr

from qiling.os.mapper import QlFsMappedObject

if TYPE_CHECKING:
    from qiling.os.linux.linux import QlOsLinux
    from qiling.os.memory import QlMemoryManager


class FsMappedStream(io.BytesIO):
    """Wrap stream objects to make them look like a QlFsMappedObject.
    """

    def __init__(self, fname: str, *args) -> None:
        super().__init__(*args)

        # note that the name property should reflect the actual file name
        # on the host file system, and here we get a virtual file name
        # instead. we should be fine, however, since there is no file
        # backing this object anyway
        self.name = fname


class QlProcFS:

    @staticmethod
    def self_auxv(os: 'QlOsLinux') -> QlFsMappedObject:
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

        return FsMappedStream(r'/proc/self/auxv', auxv_data)

    @staticmethod
    def self_cmdline(os: 'QlOsLinux') -> QlFsMappedObject:
        entries = (arg.encode('latin') for arg in os.ql.argv)
        cmdline = b'\x00'.join(entries) + b'\x00'

        return FsMappedStream(r'/proc/self/cmdline', cmdline)

    @staticmethod
    def self_environ(os: 'QlOsLinux') -> QlFsMappedObject:
        def __to_bytes(s: AnyStr) -> bytes:
            if isinstance(s, str):
                return s.encode('latin')

            return s

        entries = (b'='.join((__to_bytes(k), __to_bytes(v))) for k, v in os.ql.env.items())
        environ = b'\x00'.join(entries) + b'\x00'

        return FsMappedStream(r'/proc/self/environ', environ)

    @staticmethod
    def self_exe(os: 'QlOsLinux') -> QlFsMappedObject:
        with open(os.ql.path, 'rb') as exefile:
            content = exefile.read()

        return FsMappedStream(r'/proc/self/exe', content)

    @staticmethod
    def self_map(mem: 'QlMemoryManager') -> QlFsMappedObject:
        content = bytearray()
        mapinfo = mem.get_mapinfo()

        for lbound, ubound, perms, label, container in mapinfo:
            content += f"{lbound:x}-{ubound:x}\t{perms}p\t0\t00:00\t0\t{container if container else label}\n".encode("latin")

        return FsMappedStream(r'/proc/self/map', content)
