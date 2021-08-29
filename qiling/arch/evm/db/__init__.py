import os
from typing import (
    Any,
    Type,
    cast
)

from eth_utils import import_string

from ..abc import AtomicDatabaseAPI


DEFAULT_DB_BACKEND = 'eth.db.atomic.AtomicDB'


def get_db_backend_class(import_path: str = None) -> Type[AtomicDatabaseAPI]:
    if import_path is None:
        import_path = os.environ.get(
            'CHAIN_DB_BACKEND_CLASS',
            DEFAULT_DB_BACKEND,
        )
    return cast(Type[AtomicDatabaseAPI], import_string(import_path))


def get_db_backend(import_path: str = None, **init_kwargs: Any) -> AtomicDatabaseAPI:
    backend_class = get_db_backend_class(import_path)
    # mypy doesn't understand the constructor  of AtomicDatabaseAPI
    return backend_class(**init_kwargs)  # type: ignore
