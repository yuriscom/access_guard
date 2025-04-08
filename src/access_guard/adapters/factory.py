import logging
from typing import Optional

from .adapter_params import AdapterParams
from .casbin.casbin_permissions import CasbinPermissions
from .casbin.casbin_adapter_params import CasbinAdapterParams
from .pa_type import PermissionAdapterType
from .permission_adapter_abc import PermissionAdapter

logger = logging.getLogger(__name__)


def get_permission_adapter(
    adapter_type: PermissionAdapterType = PermissionAdapterType.CASBIN,
    engine=None,
    adapter_params: Optional[AdapterParams] = None,
    settings=None,
) -> PermissionAdapter:
    """
    Get a permission adapter instance. If it doesn't exist, create it.

    Args:
        adapter_type: The type of adapter to get
        engine: Optional SQLAlchemy engine for database adapters
        adapter_params: Optional pre-built adapter parameters
        settings: Optional application config used to build adapter-specific params

    Returns:
        PermissionAdapter: An instance of the specified permission adapter
    """

    # If adapter_params not passed explicitly, try building from settings
    if adapter_params is None and settings is not None:
        adapter_params = _build_adapter_params(adapter_type, settings)

    if adapter_type == PermissionAdapterType.CASBIN:
        if isinstance(adapter_params, CasbinAdapterParams):
            return CasbinPermissions.get_instance(engine, adapter_params)
        return CasbinPermissions.get_instance(engine)

    raise ValueError(f"Unknown adapter type: {adapter_type}")


def _build_adapter_params(adapter_type: PermissionAdapterType, settings) -> Optional[AdapterParams]:
    if adapter_type == PermissionAdapterType.CASBIN:
        return CasbinAdapterParams(
            rbac_model_path=settings.rbac_model_path
        )
    return None
