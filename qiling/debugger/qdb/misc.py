#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Callable, Optional

import ast

def check_and_eval(line: str):
    """
    This function will valid all type of nodes and evaluate it if nothing went wrong
    """

    class AST_checker(ast.NodeVisitor):
        def generic_visit(self, node):
            if type(node) in (ast.Module, ast.Expr, ast.BinOp, ast.Constant, ast.Add, ast.Mult, ast.Sub):
                ast.NodeVisitor.generic_visit(self, node)
            else:
                raise ParseError("malform or invalid ast node")

    checker = AST_checker()
    ast_tree = ast.parse(line)
    checker.visit(ast_tree)

    return eval(line)


class Breakpoint:
    """
    dummy class for breakpoint
    """
    def __init__(self, addr: int):
        self.addr = addr
        self.hitted = False


class TempBreakpoint(Breakpoint):
    """
    dummy class for temporay breakpoint
    """
    def __init__(self, addr: int):
        super().__init__(addr)


def read_int(s: str) -> int:
    """
    parse unsigned integer from string
    """
    return int(s, 0)


def parse_int(func: Callable) -> Callable:
    """
    function dectorator for parsing argument as integer
    """
    def wrap(qdb, s: str = "") -> int:
        assert type(s) is str
        try:
            ret = read_int(s)
        except:
            ret = None
        return func(qdb, ret)
    return wrap



if __name__ == "__main__":
    pass
