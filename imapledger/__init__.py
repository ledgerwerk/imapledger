"""Security-scoped IMAP automation."""

try:
    from ._version import __version__
except ImportError:  # source tree before setuptools-scm generated the file
    __version__ = "0.0.0"

from .config import Settings

__all__ = ["Settings", "__version__"]
