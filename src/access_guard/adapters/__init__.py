"""
Permission adapters for different permission systems.
"""

from .permission_adapter_abc import PermissionAdapter
from .exceptions import PermissionDeniedError
from .factory import *

__all__ = [
    'PermissionAdapter',
    'PermissionDeniedError'
] 