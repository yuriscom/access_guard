from .casbin_adapter_params import CasbinAdapterParams
from .casbin_database_adapter import CasbinDatabaseAdapter
from .casbin_adapter_abc import CasbinAdapterABC
from .casbin_remote_adapter import CasbinRemoteAdapter
from .domain.adapter_type import CasbinAdapterType


def get_adapter(params : CasbinAdapterParams) -> CasbinAdapterABC:
    params.validate()

    if params.casbin_adapter_type == CasbinAdapterType.DB:
        return CasbinDatabaseAdapter(params.engine)
    elif params.casbin_adapter_type == CasbinAdapterType.REMOTE:
        return CasbinRemoteAdapter(
            api_url=params.access_api_url
        )
    else:
        raise ValueError(f"Unknown adapter type: {params.casbin_adapter_type}")
