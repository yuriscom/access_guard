from access_guard.authz.models.enums import PolicyLoaderType
from access_guard.authz.permissions_enforcer_params import PermissionsEnforcerParams
from access_guard.authz.policy_api_loader import PolicyApiLoader
from access_guard.authz.policy_db_loader import PolicyDbLoader
from access_guard.authz.policy_loader_abc import PolicyLoaderABC


def get_policy_loader(params: PermissionsEnforcerParams, engine=None, query_provider=None) -> PolicyLoaderABC:
    """
    Factory method to create appropriate PolicyLoader based on adapter type.

    :param params: AdapterParams containing configuration
    :param engine: SQLAlchemy engine (required for DB loader)
    :return: PolicyLoaderABC instance
    """
    if params.policy_loader_type == PolicyLoaderType.DB:
        if engine is None or query_provider is None:
            raise ValueError("Database policy loader requires both SQLAlchemy engine and query_provider")
        return PolicyDbLoader(engine, query_provider=query_provider)

    if params.policy_loader_type == PolicyLoaderType.REMOTE:
        if not all([params.policy_api_url, params.policy_api_client, params.policy_api_secret]):
            raise ValueError(
                "policy_api_url, policy_api_client and policy_api_secret must be provided for adapter type REMOTE")
        return PolicyApiLoader(params.policy_api_url)

    raise ValueError(f"Unsupported policy loader type: {params.policy_loader_type}")
