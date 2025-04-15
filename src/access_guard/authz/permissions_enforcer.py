import logging
from pathlib import Path
from typing import List, Union, Optional, ClassVar, Callable, Tuple

import casbin
from casbin import Model
from casbin.util import key_match2, key_match3

from access_guard.authz.exceptions import PermissionDeniedError
from access_guard.authz.models.entities import User
from access_guard.authz.models.enums import PolicyLoaderType
from access_guard.authz.models.load_policy_result import LoadPolicyResult
from access_guard.authz.models.permissions_enforcer_params import PermissionsEnforcerParams
from access_guard.authz.loaders.poicy_query_provider import PolicyQueryProvider
from access_guard.authz.loaders.policy_loader_factory import get_policy_loader

logger = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = Path(__file__).parent / "config" / "rbac_model.conf"


class PermissionsEnforcer:
    _instance: ClassVar[Optional["PermissionsEnforcer"]] = None

    def __init__(
            self,
            params: PermissionsEnforcerParams,
            engine=None,
            query_provider: PolicyQueryProvider = None,
            synthetic_policy_provider: Optional[Callable[[], List[Tuple[str, str, str]]]] = None,
            skip_initial_policy_load: bool = False
    ):
        self._engine = engine
        self._query_provider = query_provider
        self._params = params
        self._resource_prefix = ""
        self._synthetic_policy_provider = synthetic_policy_provider
        self._skip_initial_policy_load = skip_initial_policy_load
        self._initialize_enforcer()

    @classmethod
    def get_instance(
            cls,
            params,
            engine=None,
            query_provider: PolicyQueryProvider = None,
            synthetic_policy_provider: Optional[Callable[[], List[Tuple[str, str, str]]]] = None,
            skip_initial_policy_load: bool = False
    ) -> "PermissionsEnforcer":
        if cls._instance is None:
            cls._instance = cls(params, engine, query_provider, synthetic_policy_provider)
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

        # Register key_match2 for wildcard resource matching
        self._enforcer.add_function("key_match2", key_match2)
        self._enforcer.add_function("key_match3", key_match3)

        if not self._skip_initial_policy_load:
            if self._params.filter:
                result: LoadPolicyResult = self._enforcer.adapter.load_policy(model, filter=self._params.filter)
            else:
                result: LoadPolicyResult = self._enforcer.adapter.load_policy(model)

            self._resource_prefix = result.resource_prefix or ""

            if self._synthetic_policy_provider:
                synthetic_loader = get_policy_loader(
                    PermissionsEnforcerParams(policy_loader_type=PolicyLoaderType.SYNTHETIC),
                    policy_provider = self._synthetic_policy_provider)
                synthetic_loader.load_policy(model)

        self._enforcer.build_role_links()
        self._model = model

    def has_permission(self, user: User, resource: str, actions: Union[str, List[str]]) -> bool:
        if isinstance(actions, str):
            actions = [actions]

        qualified_resource = f"{self._resource_prefix}{resource}" if self._resource_prefix else resource

        return any(self._enforcer.enforce(str(user.id), qualified_resource, action) for action in actions)

    def require_permission(self, user: User, resource: str, actions: Union[str, List[str]]) -> None:
        if not self.has_permission(user, resource, actions):
            actions_str = ", ".join(actions if isinstance(actions, list) else [actions])
            raise PermissionDeniedError(str(user.id), resource, actions_str)
