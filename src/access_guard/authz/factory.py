from typing import Callable, List, Tuple

from access_guard.authz.permissions_enforcer import PermissionsEnforcer
from access_guard.authz.models.permissions_enforcer_params import PermissionsEnforcerParams
from access_guard.authz.loaders.poicy_query_provider import PolicyQueryProvider


def _build_params(settings) -> PermissionsEnforcerParams:
    return PermissionsEnforcerParams(
        policy_loader_type=settings.policy_loader_type,
        rbac_model_path=getattr(settings, "rbac_model_path", None),
        policy_api_url=getattr(settings, "policy_api_url", None),
        policy_api_client=getattr(settings, "policy_api_client", None),
        policy_api_secret=getattr(settings, "policy_api_secret", None),
        filter=getattr(settings, "filter", None),  # fully agnostic filter dict
    )


def get_permissions_enforcer(
        settings=None,
        engine=None,
        new_instance: bool = False,
        query_provider: PolicyQueryProvider = None,
        synthetic_policy_provider: Callable[[], List[Tuple[str, ...]]] = None
) -> PermissionsEnforcer:
    params = _build_params(settings)

    if new_instance:
        return PermissionsEnforcer(
            params,
            engine,
            query_provider=query_provider,
            synthetic_policy_provider=synthetic_policy_provider
        )

    return PermissionsEnforcer.get_instance(
        params,
        engine,
        query_provider=query_provider,
        synthetic_policy_provider=synthetic_policy_provider
    )
