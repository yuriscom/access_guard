from typing import Callable, List, Tuple, Optional

from access_guard.authz.loaders.policy_loader_abc import PolicyLoaderABC
from access_guard.authz.loaders.policy_provider_abc import PolicyProvider
from access_guard.authz.permissions_enforcer import PermissionsEnforcer
from access_guard.authz.models.permissions_enforcer_params import PermissionsEnforcerParams
from access_guard.authz.loaders.poicy_query_provider import PolicyQueryProvider


def _build_params(settings, rbac_model_path: Optional[str] = None) -> PermissionsEnforcerParams:
    return PermissionsEnforcerParams(
        # policy_loader_type=settings.policy_loader_type,
        rbac_model_path=rbac_model_path,
        # policy_api_url=getattr(settings, "policy_api_url", None),
        # policy_api_client=getattr(settings, "policy_api_client", None),
        # policy_api_secret=getattr(settings, "policy_api_secret", None),
        filter=getattr(settings, "filter", None),  # fully agnostic filter dict
    )


def get_permissions_enforcer(
        settings=None,
        rbac_model_path: Optional[str] = None,
        policy_loaders: Optional[List[PolicyLoaderABC]] = [],
        new_instance: bool = False,
        skip_initial_policy_load: bool = False
) -> PermissionsEnforcer:
    """
        Factory method to create or retrieve an instance of PermissionsEnforcer.

        This method builds and returns a configured PermissionsEnforcer instance,
        responsible for loading and enforcing access control policies using Casbin.

        Args:
            settings: Optional configuration object containing settings for the enforcer,
                      including policy_loader_type, rbac_model_path, and filter.
            engine: Optional SQLAlchemy engine instance, required if using DB loader.
            new_instance (bool): If True, returns a new PermissionsEnforcer instance.
                                 If False, uses a singleton for reuse and caching.
            query_provider (PolicyQueryProvider): Required for DB loaders. Supplies SQL queries
                                                  used to fetch policies based on filter or entity.
            synthetic_policy_provider: Optional callable that returns additional synthetic
                                       (in-memory or virtual) policies to load into the enforcer.
                                       Useful for defining implicit platform-level permissions.
            skip_initial_policy_load (bool): If True, disables automatic policy loading during enforcer
                                             initialization. Useful when the caller wants full control
                                             over when and how policies are loaded (e.g., to load policies
                                             for a specific user or role only).

        Returns:
            PermissionsEnforcer: A fully initialized or reusable enforcer instance,
                                 depending on the configuration.
        """
    params = _build_params(settings, rbac_model_path)

    if new_instance:
        return PermissionsEnforcer(
            params,
            policy_loaders,
            skip_initial_policy_load=skip_initial_policy_load
        )

    return PermissionsEnforcer.get_instance(
        params,
        policy_loaders,
        skip_initial_policy_load=skip_initial_policy_load
    )
