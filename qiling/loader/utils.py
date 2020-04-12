#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from qiling.utils import *
from qiling.const import *

def ql_loader_setup(ql, function_name = None):
    if not ql_is_valid_ostype(ql.ostype):
        raise QlErrorOsType("[!] Invalid OSType")

    if not ql_is_valid_arch(ql.archtype):
        raise QlErrorArch("[!] Invalid Arch %s" % ql.archtype)

    if function_name == None:
        loadertype_str = ql_loadertype_convert_str(ql.ostype)
        function_name = "QlLoader" + loadertype_str
        module_name = ql_build_module_import_name("loader", loadertype_str.lower())
        return ql_get_module_function(module_name, function_name)(ql)