
import logging
from pathlib import Path
from typing import List, Union, Optional, ClassVar

import casbin
from casbin import Model

from access_guard.authz.entities import User
from access_guard.authz.load_policy_result import LoadPolicyResult
from access_guard.authz.poicy_query_provider import PolicyQueryProvider
from access_guard.authz.policy_loader_factory import get_policy_loader
from access_guard.authz.exceptions import PermissionDeniedError
from access_guard.authz.permissions_enforcer_params import PermissionsEnforcerParams

logger = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = Path(__file__).parent / "config" / "rbac_model.conf"


class PermissionsEnforcer:
    _instance: ClassVar[Optional["PermissionsEnforcer"]] = None

    def __init__(self, params: PermissionsEnforcerParams, engine=None, query_provider: PolicyQueryProvider = None):
        self._engine = engine
        self._query_provider = query_provider
        self._params = params
        self._resource_prefix = ""
        self._initialize_enforcer()

    @classmethod
    def get_instance(cls, params, engine=None, query_provider: PolicyQueryProvider = None) -> "PermissionsEnforcer":
        if cls._instance is None:
            cls._instance = cls(params, engine, query_provider)
        return cls._instance

    def _initialize_enforcer(self):
        model = Model()
        model_path = (
            Path(self._params.rbac_model_path)
            if self._params and self._params.rbac_model_path
            else DEFAULT_MODEL_PATH
        )
        model.load_model(model_path)

        loader = get_policy_loader(self._params, self._engine, self._query_provider)
        loader.set_filtered(True)
        self._enforcer = casbin.Enforcer(model, loader)
        if self._params.filter:
            result: LoadPolicyResult = self._enforcer.adapter.load_policy(model, filter=self._params.filter)
        else:
            result: LoadPolicyResult = self._enforcer.adapter.load_policy(model)

        self._resource_prefix = result.resource_prefix or ""
        self._enforcer.build_role_links()
        self._model = model

    def has_permission(self, user: User, resource: str, actions: Union[str, List[str]]) -> bool:
        if isinstance(actions, str):
            actions = [actions]

        qualified_resource = f"{self._resource_prefix}{resource}" if self._resource_prefix else resource

        logger.debug(
            f"Enforcing for user: {user.id}, resource: {resource}, actions: {actions}, qualified_resource: {qualified_resource}")

        for sec in ["p", "g"]:
            for ptype, ast in self._model.model.get(sec, {}).items():
                for rule in ast.policy:
                    logger.debug(f"Loaded policy [{sec}] {ptype}: {rule}")

        return any(self._enforcer.enforce(str(user.id), qualified_resource, action) for action in actions)

    def require_permission(self, user: User, resource: str, actions: Union[str, List[str]]) -> None:
        if not self.has_permission(user, resource, actions):
            actions_str = ", ".join(actions if isinstance(actions, list) else [actions])
            raise PermissionDeniedError(str(user.id), resource, actions_str)
