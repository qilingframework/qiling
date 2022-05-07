import importlib.metadata
from .core import Qiling

try:
    __version__ = importlib.metadata.version(__package__ or __name__)
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = ['Qiling']
