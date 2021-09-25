#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from py_ecc import (
    optimized_bn128 as bn128,
)
from py_ecc.optimized_bn128 import (
    FQP,
    FQ2,
)

from eth_utils import (
    ValidationError,
)

from typing import Tuple


def validate_point(x: int, y: int) -> Tuple[bn128.FQ, bn128.FQ, bn128.FQ]:
    FQ = bn128.FQ

    if x >= bn128.field_modulus:
        raise ValidationError("Point x value is greater than field modulus")
    elif y >= bn128.field_modulus:
        raise ValidationError("Point y value is greater than field modulus")

    if (x, y) != (0, 0):
        p1 = (FQ(x), FQ(y), FQ(1))
        if not bn128.is_on_curve(p1, bn128.b):
            raise ValidationError("Point is not on the curve")
    else:
        p1 = (FQ(1), FQ(1), FQ(0))

    return p1


def FQP_point_to_FQ2_point(pt: Tuple[FQP, FQP, FQP]) -> Tuple[FQ2, FQ2, FQ2]:
    """
    Transform FQP to FQ2 for type hinting.
    """
    return (
        FQ2(pt[0].coeffs),
        FQ2(pt[1].coeffs),
        FQ2(pt[2].coeffs),
    )
