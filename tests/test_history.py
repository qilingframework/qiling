import re
import unittest

from typing import List, Optional, Tuple

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.coverage.formats.history import History


class HistoryTest(unittest.TestCase):
    P_LIBC = r".*libc(-\d\.\d+)?.so.*"  # covers both generic (i.e. "libc.so.6") and specific (e.g. "libc-2.27.so")
    P_LD = r"ld-linux.*"

    @staticmethod
    def sanitize_mmap_path(mmap: List[Tuple]) -> List[Tuple[int, int, str, str]]:
        """Removes the path from the mmap tuple so that it can be compared to other mmaps.

        currently because the loader is handling loading ld and the main binary, we get the annotation of the path in
        element 5 of the tuple (index 4) this path is going to be dependent on the users filesystem, so it doesnt quite
        make sense to test for it
        """

        if isinstance(mmap, tuple):
            mmap = [mmap]

        return [tup[:4] for tup in mmap]

    def setUp(self):
        rootfs = '../examples/rootfs/x8664_linux'
        argv = [fr'{rootfs}/bin/x8664_hello']

        ql = Qiling(argv, rootfs, verbose=QL_VERBOSE.OFF)

        self.history = History(ql)
        self.ql = ql

    def get_label(self, basename: str) -> Optional[str]:
        """Return the matching label from mapinfo, ignoring boxes and possible different suffixes.

        For example, on some systems libc label may appear as "libc.so.6" and "libc-2.27.so" on others.
        This method also ignores the boxed prefixes, if exists (e.g. "[mmap]")
        """

        p = re.compile(rf'\A(\[.+\]\s+)?{basename}[.-]')

        return next((label for _, _, _, label, _ in self.ql.mem.map_info if re.match(p, label)), None)

    def test_get_regex_matching_exec_maps(self):
        self.ql.run()

        self.assertListEqual(
            [
                (0x7fffb7dd6000, 0x7fffb7fbd000, 'r-x', self.get_label('libc'), '')
            ],
            self.history.get_regex_matching_exec_maps(self.P_LIBC)
        )

        self.assertListEqual(
            [
                (0x7fffb7dd6000, 0x7fffb7fbd000, 'r-x', self.get_label('libc')),
                (0x7ffff7dd5000, 0x7ffff7dfc000, 'r-x', self.get_label('ld'))
            ],
            self.sanitize_mmap_path(self.history.get_regex_matching_exec_maps([self.P_LIBC, self.P_LD]))
        )

    def test_get_mem_map_from_addr(self):
        self.ql.run()

        mmap = self.history.get_mem_map_from_addr(0x7ffff7df4830)
        self.assertIsNotNone(mmap)

        self.assertTupleEqual(
            (0x7ffff7dd5000, 0x7ffff7dfc000, 'r-x', self.get_label('ld')),
            self.sanitize_mmap_path(mmap)[0]
        )

    def test_get_ins_exclude_lib(self):
        self.ql.run(end=0x55555555465a)

        non_libc_blocks = self.history.get_ins_exclude_lib(self.P_LIBC)
        self.assertGreater(len(non_libc_blocks), 0)

        # this test is going to take a while but oh well
        # also assumes that the get_mem_map_from_addr function works
        for block in non_libc_blocks:
            map_for_ins = self.history.get_mem_map_from_addr(block)

            self.assertIsNotNone(map_for_ins)
            self.assertNotRegex(map_for_ins[3], self.P_LIBC)

        non_libc_blocks_and_ld = self.history.get_ins_exclude_lib([self.P_LIBC, self.P_LD])
        self.assertGreater(len(non_libc_blocks_and_ld), 0)

        for block in non_libc_blocks_and_ld:
            map_for_ins = self.history.get_mem_map_from_addr(block)

            self.assertIsNotNone(map_for_ins)
            self.assertNotRegex(map_for_ins[3], '|'.join((self.P_LIBC, self.P_LD)))

    def test_get_ins_only_lib(self):
        self.ql.run(end=0x55555555465a)

        non_libc_blocks = self.history.get_ins_only_lib(self.P_LIBC)
        self.assertGreater(len(non_libc_blocks), 0)

        # this test is going to take a while but oh well
        # also assumes that the get_mem_map_from_addr function works
        for block in non_libc_blocks:
            map_for_ins = self.history.get_mem_map_from_addr(block)

            self.assertIsNotNone(map_for_ins)
            self.assertRegex(map_for_ins[3], self.P_LIBC)

        non_libc_blocks_and_ld = self.history.get_ins_only_lib([self.P_LIBC, self.P_LD])
        self.assertGreater(len(non_libc_blocks_and_ld), 0)

        for block in non_libc_blocks_and_ld:
            map_for_ins = self.history.get_mem_map_from_addr(block)

            self.assertIsNotNone(map_for_ins)
            self.assertRegex(map_for_ins[3], '|'.join((self.P_LIBC, self.P_LD)))


if __name__ == "__main__":
    unittest.main()
