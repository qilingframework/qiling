import unittest
from unittest.mock import MagicMock, patch

from qiling.os.posix.const import EINVAL
from qiling.os.posix.syscall.random import ql_syscall_getrandom


class GetRandomZeroLengthTest(unittest.TestCase):
    def test_zero_length_request_returns_without_accessing_memory(self):
        ql = MagicMock()

        self.assertEqual(ql_syscall_getrandom(ql, 0, 0, 0), 0)
        ql.mem.is_mapped.assert_not_called()
        ql.mem.write.assert_not_called()

    def test_positive_length_request_still_writes_random_bytes(self):
        ql = MagicMock()
        ql.mem.is_mapped.return_value = True

        with patch(
            "qiling.os.posix.syscall.random.os.urandom", return_value=b"data"
        ):
            result = ql_syscall_getrandom(ql, 0x1000, 4, 0)

        self.assertEqual(result, 4)
        ql.mem.is_mapped.assert_called_once_with(0x1000, 4)
        ql.mem.write.assert_called_once_with(0x1000, b"data")

    def test_invalid_flags_are_rejected_before_accessing_memory(self):
        ql = MagicMock()

        for buflen, flags in ((0, 0x8), (0, 0x6), (4, 0x8), (4, 0x6)):
            with self.subTest(buflen=buflen, flags=flags):
                self.assertEqual(
                    ql_syscall_getrandom(ql, 0, buflen, flags), -EINVAL
                )

        ql.mem.is_mapped.assert_not_called()
        ql.mem.write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
