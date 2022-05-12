#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import json
from typing import Any, List, MutableMapping, Mapping, Optional, Set

class QlOsStats:
    """Record basic OS statistics, such as API calls and strings.
    """

    def __init__(self):
        self.syscalls: MutableMapping[str, List] = {}
        self.strings: MutableMapping[str, Set] = {}

        self.position = 0

    def clear(self):
        """Reset collected stats.
        """

        self.syscalls.clear()
        self.strings.clear()

        self.position = 0

    @staticmethod
    def _banner(caption: str) -> List[str]:
        bar = '-' * 24

        return ['', caption, bar]

    def summary(self) -> List[str]:
        ret = []

        ret.extend(QlOsStats._banner('syscalls called'))

        for key, values in self.syscalls.items():
            ret.append(f'{key}:')
            ret.extend(f'  {json.dumps(value):s}' for value in values)

        ret.extend(QlOsStats._banner('strings ocurrences'))

        for key, values in self.strings.items():
            ret.append(f'{key}: {", ".join(str(word) for word in values)}')

        return ret

    def log_api_call(self, address: int, name: str, params: Mapping, retval: Any, retaddr: int) -> None:
        """Record API calls along with their details.

        Args:
            address : location of the calling instruction
            name    : api function name
            params  : mapping of the parameters name to their effective values
            retval  : value returned by the api function
            retaddr : address to which the api function returned
        """

        if name.startswith('hook_'):
            name = name[5:]

        self.syscalls.setdefault(name, []).append({
            'params'   : params,
            'retval'   : retval,
            'address'  : address,
            'retaddr'  : retaddr,
            'position' : self.position
        })

        self.position += 1

    def log_string(self, s: str) -> None:
        """Record strings appearance as they are encountered during emulation.

        Args:
            s : string to record
        """

        for token in s.split(' '):
            self.strings.setdefault(token, set()).add(self.position)


class QlWinStats(QlOsStats):
    """OS statistics object for Windows OS. Includes registry access stats.
    """

    def __init__(self):
        super().__init__()

        self.registry: MutableMapping[str, List] = {}

    def clear(self):
        super().clear()

        self.registry.clear()

    def summary(self) -> List[str]:
        ret = super().summary()

        ret.extend(QlOsStats._banner('registry keys accessed'))

        for key, values in self.registry.items():
            ret.append(f'{key}:')
            ret.extend(f'  {json.dumps(value):s}' for value in values)

        return ret

    def log_reg_access(self, key: str, item: Optional[str], type: Optional[int], value: Any) -> None:
        """Record registry access.

        Args:
            key   : accessed key name
            name  : sub item name (if provided)
            type  : sub item type (if provided)
            value : value set to item, in case of a registry modification
        """

        self.registry.setdefault(key, []).append({
            'item'     : item,
            'type'     : type,
            'value'    : value,
            'position' : self.position
        })


class QlOsNullStats(QlOsStats):
    """Nullified OS statistics object.
    """

    def clear(self):
        pass

    def summary(self) -> List[str]:
        return []

    def log_api_call(self, address: int, name: str, params: Mapping, retval: Any, retaddr: int) -> None:
        pass

    def log_string(self, s: str) -> None:
        pass


class QlWinNullStats(QlOsNullStats):
    """Nullified Windows statistics object.
    """

    def log_reg_access(self, key: str, item: Optional[str], type: Optional[int], value: Any) -> None:
        pass
