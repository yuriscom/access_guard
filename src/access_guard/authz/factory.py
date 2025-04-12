from access_guard.authz.enums import PolicyLoaderType
from access_guard.authz.permissions_enforcer import PermissionsEnforcer
from access_guard.authz.permissions_enforcer_params import PermissionsEnforcerParams


def _build_params(settings) -> PermissionsEnforcerParams:
    return PermissionsEnforcerParams(
        policy_loader_type=settings.policy_loader_type,
        rbac_model_path=getattr(settings, "rbac_model_path", None),
        policy_api_url=getattr(settings, "policy_api_url", None),
        policy_api_client=getattr(settings, "policy_api_client", None),
        policy_api_secret=getattr(settings, "policy_api_secret", None),
        scope=getattr(settings, 'policy_api_scope', None),
        user_id=getattr(settings, 'policy_api_userid', None),
        app_id=getattr(settings, 'policy_api_appid', None)
    )


def get_permissions_enforcer(settings=None, engine=None,
                             new_instance: bool = False) -> PermissionsEnforcer:
    params = _build_params(settings)

    if new_instance:
        return PermissionsEnforcer(params, engine)

    return PermissionsEnforcer.get_instance(params, engine)
