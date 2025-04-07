import logging

from .casbin.casbin_permissions import CasbinPermissions
from .pa_type import PermissionAdapterType
from .permission_adapter_abc import PermissionAdapter

logger = logging.getLogger(__name__)


def get_permission_adapter(adapter_type: PermissionAdapterType = PermissionAdapterType.CASBIN, engine=None):
    """
    Get a permission adapter instance. If it doesn't exist, create it.

    Args:
        adapter_type: The type of adapter to get
        engine: Optional SQLAlchemy engine for database adapters

    Returns:
        PermissionAdapter: An instance of the specified permission adapter
    """
    if adapter_type == PermissionAdapterType.CASBIN:
        return CasbinPermissions.get_instance(engine)
    else:
        raise ValueError(f"Unknown adapter type: {adapter_type}")