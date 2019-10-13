import unittest
import sys
sys.path.append("..")
from qiling import *
from qiling.utils import *

class BasicTest(unittest.TestCase):
    def test_invalid_module(self):
        self.assertRaises(QlErrorModuleNotFound, get_module_function, "InvalidModule", "InvalidFunction")

    def test_invalid_module_function(self):
        self.assertRaises(QlErrorModuleFunctionNotFound, get_module_function, "qiling.arch.x86", "InvalidFunction")

if __name__ == "__main__":
    unittest.main()