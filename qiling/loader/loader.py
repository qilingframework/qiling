#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
from typing import Any, Mapping, MutableSequence, NamedTuple, Optional

from qiling import Qiling

class Image(NamedTuple):
    base: int
    end: int
    path: str

class QlLoader:
    def __init__(self, ql: Qiling):
        self.ql = ql
        self.env = self.ql.env
        self.argv = self.ql.argv
        self.images: MutableSequence[Image] = []
        self.skip_exit_check = False

    def find_containing_image(self, address: int) -> Optional[Image]:
        """Retrieve the image object that contains the specified address.

        Returns: image containing the specified address, or `None` if not found
        """

        return next((image for image in self.images if image.base <= address < image.end), None)

    def get_image_by_name(self, name: str, *, casefold: bool = False) -> Optional[Image]:
        """Retrieve an image by its basename.

        Args:
            name     : image base name
            casefold : whether name matching should be case-insensitive (default is case-sensitive)

        Returns: image object whose basename match to the one given, or `None` if not found
        """

        cf = str.casefold if casefold else lambda s: s

        return next((image for image in self.images if cf(os.path.basename(image.path)) == cf(name)), None)

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
