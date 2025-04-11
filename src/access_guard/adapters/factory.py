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
        if not isinstance(adapter_params, CasbinAdapterParams):
            raise ValueError(f"Unknown params type for adapter: {adapter_type}")

        adapter_params.engine = engine
        return CasbinPermissions.get_instance(adapter_params)


    raise ValueError(f"Unknown adapter type: {adapter_type}")


def _build_adapter_params(adapter_type: PermissionAdapterType, settings) -> Optional[AdapterParams]:
    if adapter_type == PermissionAdapterType.CASBIN:
        return CasbinAdapterParams(
            rbac_model_path=getattr(settings, 'rbac_model_path', None),
            casbin_adapter_type=getattr(settings, 'casbin_adapter', None),
            access_api_url=getattr(settings, 'access_api_url', None),
            access_api_client=getattr(settings, 'access_api_client', None),
            access_api_secret=getattr(settings, 'access_api_secret', None)
        )
    return None
