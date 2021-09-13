#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Any, Mapping, MutableSequence, NamedTuple

from qiling import Qiling

Image = NamedTuple('Image', (('base', int), ('end', int), ('path', str)))

class QlLoader:
    def __init__(self, ql: Qiling):
        self.ql = ql
        self.env = self.ql.env
        self.argv = self.ql.argv
        self.images: MutableSequence[Image] = []
        self.skip_exit_check = False

    def save(self) -> Mapping[str, Any]:
        saved_state = {
            'images': [tuple(img) for img in self.images]
        }

        return saved_state

    def restore(self, saved_state: Mapping[str, Any]):
        self.images = [Image(*img) for img in saved_state['images']]

    # loader main method; derivatives must implement one of their own
    def run(self) -> None:
        raise NotImplementedError
