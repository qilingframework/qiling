import unittest
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.coverage.formats.history import History
from typing import List

class HistoryTest(unittest.TestCase):

    @staticmethod
    def sanitize_mmap_path(mmap: List[tuple]) -> List[tuple]:
        '''Removes the path from the mmap tuple so that it can be compared to other mmaps
        currently because the loader is handling loading ld and the main binary, we get the annotation of the path in element 5 of the tuple (index 4)
        this path is going to be dependent on the users filesystem, so it doesnt quite make sense to test for it
        '''
        if isinstance(mmap, tuple):
            mmap = [mmap]

        return list(map(lambda x: (x[0], x[1], x[2], x[3], ''), mmap))

    def test_get_regex_matching_exec_maps(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_hello"], "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.OFF)
        history = History(ql)
        ql.run()

        self.assertEqual([(0x7fffb7dd6000, 0x7fffb7fbd000, 'r-x', '[mmap] libc.so.6', '')], history.get_regex_matching_exec_maps(".*libc.so.*"))

        self.assertEqual(
            [
                (0x7fffb7dd6000, 0x7fffb7fbd000, 'r-x', '[mmap] libc.so.6', ''),
                (0x7ffff7dd5000, 0x7ffff7dfc000, 'r-x', 'ld-linux-x86-64.so.2', '')
            ],
            self.sanitize_mmap_path(history.get_regex_matching_exec_maps([".*libc.so.*", "ld.*"]))
        )

        del ql

    def test_get_mem_map_from_addr(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_hello"], "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.OFF)
        history = History(ql)
        ql.run()

        self.assertEqual(
            self.sanitize_mmap_path(history.get_mem_map_from_addr(0x7ffff7df4830))[0], 
            (
                0x7ffff7dd5000,
                0x7ffff7dfc000,
                'r-x',
                'ld-linux-x86-64.so.2',
                ''))
    

    def test_get_ins_exclude_lib(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_hello"], "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.OFF)
        history = History(ql)
        ql.run(end=0x55555555465a)

        non_libc_blocks = history.get_ins_exclude_lib(".*libc.so.*")

        # this test is going to take a while but oh well
        # also assumes that the get_mem_map_from_addr function works
        for block in non_libc_blocks:
            map_for_ins = history.get_mem_map_from_addr(block)
            self.assertNotRegex(map_for_ins[3], ".*libc.so.*")

        assert len(non_libc_blocks) > 0

        non_libc_blocks_and_ld = history.get_ins_exclude_lib([".*libc.so.*", "ld-linux.*"])

        for block in non_libc_blocks_and_ld:
            map_for_ins = history.get_mem_map_from_addr(block)
            self.assertNotRegex(map_for_ins[3], ".*libc.so.*|ld-linux.*")

        assert len(non_libc_blocks_and_ld) > 0


    def test_get_ins_only_lib(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_hello"], "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.OFF)
        history = History(ql)
        ql.run(end=0x55555555465a)

        non_libc_blocks = history.get_ins_only_lib(".*libc.so.*")

        # this test is going to take a while but oh well
        # also assumes that the get_mem_map_from_addr function works
        for block in non_libc_blocks:
            map_for_ins = history.get_mem_map_from_addr(block)
            self.assertRegex(map_for_ins[3], ".*libc.so.*")

        assert len(non_libc_blocks) > 0

        non_libc_blocks_and_ld = history.get_ins_only_lib([".*libc.so.*", "ld-linux.*"])

        for block in non_libc_blocks_and_ld :
            map_for_ins = history.get_mem_map_from_addr(block)
            self.assertRegex(map_for_ins[3], ".*libc.so.*|.*ld-linux.*")

        assert len(non_libc_blocks_and_ld) > 0

if __name__ == "__main__":
    unittest.main()