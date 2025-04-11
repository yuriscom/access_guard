from ..adapters.casbin.domain.adapter_type import CasbinAdapterType
from ..adapters.pa_type import PermissionAdapterType
import logging

logger = logging.getLogger(__name__)

def parse_adapter_type(value: str) -> PermissionAdapterType:
    try:
        return PermissionAdapterType(value.lower())
    except ValueError:
        logger.warning(f"Unknown adapter type '{value}', defaulting to 'casbin'")
        return PermissionAdapterType.CASBIN


def parse_casbin_adapter_type(value: str) -> CasbinAdapterType:
    try:
        return CasbinAdapterType(value.lower())
    except ValueError:
        logger.warning(f"Unknown adapter type '{value}', defaulting to 'remote'")
        return CasbinAdapterType.REMOTE