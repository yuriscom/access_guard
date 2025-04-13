import logging

from access_guard.authz.models.enums import PolicyLoaderType, PermissionsAdapterType

logger = logging.getLogger(__name__)

def parse_adapter_type(value: str) -> PermissionsAdapterType:
    try:
        return PermissionsAdapterType(value.lower())
    except ValueError:
        logger.warning(f"Unknown adapter type '{value}', defaulting to 'casbin'")
        return PermissionsAdapterType.CASBIN


def parse_policy_loader_type(value: str) -> PolicyLoaderType:
    try:
        return PolicyLoaderType(value.lower())
    except ValueError:
        logger.warning(f"Unknown adapter type '{value}', defaulting to 'remote'")
        return PolicyLoaderType.REMOTE