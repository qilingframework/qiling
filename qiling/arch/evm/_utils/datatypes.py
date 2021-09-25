#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from eth_utils.toolz import (
    assoc,
    groupby,
)

from eth_utils import (
    to_dict,
    to_set,
)


from typing import Any, Dict, Tuple, Type, TypeVar, Iterator, List

from ..abc import ConfigurableAPI


def _is_local_prop(prop: str) -> bool:
    return len(prop.split('.')) == 1


def _extract_top_level_key(prop: str) -> str:
    left, _, _ = prop.partition('.')
    return left


def _extract_tail_key(prop: str) -> str:
    _, _, right = prop.partition('.')
    return right


@to_dict
def _get_local_overrides(overrides: Dict[str, Any]) -> Iterator[Tuple[str, Any]]:
    for prop, value in overrides.items():
        if _is_local_prop(prop):
            yield prop, value


@to_dict
def _get_sub_overrides(overrides: Dict[str, Any]) -> Iterator[Tuple[str, Any]]:
    for prop, value in overrides.items():
        if not _is_local_prop(prop):
            yield prop, value


@to_dict
def _get_sub_overrides_by_prop(
        overrides: Dict[str, Any]) -> Iterator[Tuple[str, Dict[str, List[str]]]]:
    # we only want the overrides that are not top level.
    sub_overrides = _get_sub_overrides(overrides)
    key_groups = groupby(_extract_top_level_key, sub_overrides.keys())
    for top_level_key, props in key_groups.items():
        yield top_level_key, {_extract_tail_key(prop): overrides[prop] for prop in props}


@to_set
def _get_top_level_keys(overrides: Dict[str, Any]) -> Iterator[str]:
    for prop in overrides:
        yield _extract_top_level_key(prop)

# Dynamic subclassing is not supported by mypy
# https://github.com/python/mypy/wiki/Unsupported-Python-Features
# Most of the cases where we silence mypy boil down to cases where
# dynamic subclasses where generated through this method


T = TypeVar('T')


class Configurable(ConfigurableAPI):
    """
    Base class for simple inline subclassing
    """
    @classmethod
    def configure(cls: Type[T],
                  __name__: str = None,
                  **overrides: Any) -> Type[T]:

        if __name__ is None:
            __name__ = cls.__name__

        top_level_keys = _get_top_level_keys(overrides)

        # overrides that are *local* to this class.
        local_overrides = _get_local_overrides(overrides)

        for key in top_level_keys:
            if key == '__name__':
                continue
            elif not hasattr(cls, key):
                raise TypeError(
                    f"The {cls.__name__}.configure cannot set attributes that are not "
                    f"already present on the base class. The attribute `{key}` was "
                    f"not found on the base class `{cls}`"
                )

        # overrides that are for sub-properties of this class
        sub_overrides_by_prop = _get_sub_overrides_by_prop(overrides)

        for key, sub_overrides in sub_overrides_by_prop.items():
            sub_cls: Configurable = None
            if key in local_overrides:
                sub_cls = local_overrides[key]
            elif hasattr(cls, key):
                sub_cls = getattr(cls, key)
            else:
                raise Exception(
                    "Invariant: the pre-check that all top level keys are "
                    "present on `cls` should make this code path unreachable"
                )

            if not isinstance(sub_cls, type) or not issubclass(sub_cls, Configurable):
                raise TypeError(
                    f"Unable to configure property `{key}` on class `{cls!r}`.  The "
                    "property being configured must be a subclass of the "
                    "`Configurable` type.  Instead got the following object "
                    f"instance: {sub_cls!r}"
                )

            configured_sub_cls = sub_cls.configure(**sub_overrides)  # type: ignore
            local_overrides = assoc(local_overrides, key, configured_sub_cls)

        return type(__name__, (cls,), local_overrides)
