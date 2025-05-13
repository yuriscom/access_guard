import logging
from pathlib import Path
from typing import List, Union, Optional, ClassVar

import casbin
from access_guard.authz.exceptions import PermissionDeniedError
from access_guard.authz.loaders.multi_adapter import MultiAdapter
from access_guard.authz.loaders.policy_provider_abc import PolicyProvider
from access_guard.authz.models.entities import User
from access_guard.authz.models.load_policy_result import LoadPolicyResult
from access_guard.authz.models.permissions_enforcer_params import PermissionsEnforcerParams
from casbin import Model
from casbin.util import key_match2, key_match3

logger = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = Path(__file__).parent / "config" / "rbac_model.conf"


class PermissionsEnforcer:
    _instance: ClassVar[Optional["PermissionsEnforcer"]] = None

    def __init__(
            self,
            params: PermissionsEnforcerParams,
            policy_loaders: List[PolicyProvider],
            skip_initial_policy_load: bool = False
    ):
        self._params = params
        self._resource_prefix = ""
        self._skip_initial_policy_load = skip_initial_policy_load
        self._policy_loaders = policy_loaders
        self._adapter = MultiAdapter(self._policy_loaders)
        self._initialize_enforcer()

    @classmethod
    def get_instance(
            cls,
            params,
            policy_loaders: List[PolicyProvider],
            skip_initial_policy_load: bool = False
    ) -> "PermissionsEnforcer":
        if cls._instance is None:
            cls._instance = cls(
                params,
                policy_loaders,
                skip_initial_policy_load)
        return cls._instance

    def _initialize_enforcer(self):
        model = Model()
        model_path = (
            Path(self._params.rbac_model_path)
            if self._params and self._params.rbac_model_path
            else DEFAULT_MODEL_PATH
        )
        model.load_model(model_path)
        self._model = model

        # need filtered flag here for casbin to not load the policies automatically. We will trigger them later
        self._adapter.set_filtered(True)
        self._enforcer = casbin.Enforcer(self._model, self._adapter)

        # Register key_match functions for wildcard resource matching
        self._enforcer.add_function("key_match2", key_match2)
        self._enforcer.add_function("key_match3", key_match3)

        if not self._skip_initial_policy_load:
            self._load_policies()

        self._enforcer.build_role_links()

    def _load_policies(self) -> None:
        # self._adapter.load_policy(self._model, filter=self._params.filter)

        for loader in self._policy_loaders:
            result: LoadPolicyResult = loader.load_policy(self._model, filter=self._params.filter)
            # todo: right now only applying the first resource_prefix.
            #  update _resource_prefix to be list
            if result.resource_prefix and not self._resource_prefix:
                self._resource_prefix = result.resource_prefix

        self._enforcer.build_role_links()
        # self.log_loaded_policies()

    def has_permission(self, user: User, resource: str, actions: Union[str, List[str]]) -> bool:
        if isinstance(actions, str):
            actions = [actions]

        qualified_resource = f"{self._resource_prefix}{resource}" if self._resource_prefix else resource

        return any(self._enforcer.enforce(str(user.id), qualified_resource, action) for action in actions)

    def require_permission(self, user: User, resource: str, actions: Union[str, List[str]]) -> None:
        if not self.has_permission(user, resource, actions):
            actions_str = ", ".join(actions if isinstance(actions, list) else [actions])
            raise PermissionDeniedError(str(user.id), resource, actions_str)

    def refresh_policies(self):
        self._enforcer.clear_policy()
        self._load_policies()
        self._enforcer.build_role_links()

    def log_loaded_policies(self):
        for sec in self._model.model:
            for ptype in self._model.model[sec]:
                for rule in self._model.model[sec][ptype].policy:
                    logger.debug(f"Loaded policy rule: {ptype}, {', '.join(rule)}")
