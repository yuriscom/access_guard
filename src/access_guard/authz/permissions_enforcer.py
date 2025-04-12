
import logging
from pathlib import Path
from typing import List, Union, Optional, ClassVar

import casbin
from casbin import Model

from access_guard.authz.entities import User
from access_guard.authz.policy_loader_factory import get_policy_loader
from access_guard.authz.exceptions import PermissionDeniedError
from access_guard.authz.permissions_enforcer_params import PermissionsEnforcerParams

logger = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = Path(__file__).parent / "config" / "rbac_model.conf"


class PermissionsEnforcer:
    _instance: ClassVar[Optional["PermissionsEnforcer"]] = None

    def __init__(self, params: PermissionsEnforcerParams, engine=None):
        self._engine = engine
        self._params = params
        self._initialize_enforcer()

    @classmethod
    def get_instance(cls, params, engine=None) -> "PermissionsEnforcer":
        if cls._instance is None:
            cls._instance = cls(params, engine)
        return cls._instance

    def _initialize_enforcer(self):
        model = Model()
        model_path = (
            Path(self._params.rbac_model_path)
            if self._params and self._params.rbac_model_path
            else DEFAULT_MODEL_PATH
        )
        model.load_model(model_path)

        loader = get_policy_loader(self._params, self._engine)
        loader.set_filtered(True)

        self._enforcer = casbin.Enforcer(model, loader)
        self._enforcer.adapter.load_policy(model)

        self._model = model

    def _qualify(self, name: str, is_role_or_resource: bool = True) -> str:
        if not name:
            return name
        if is_role_or_resource and self._params.scope and self._params.app_id:
            return f"{self._params.scope}:{self._params.app_id}:{name}"
        return name

    def has_permission(self, user: User, resource: str, actions: Union[str, List[str]]) -> bool:
        if isinstance(actions, str):
            actions = [actions]

        qualified_resource = self._qualify(resource, is_role_or_resource=True)

        return any(self._enforcer.enforce(str(user.id), qualified_resource, action) for action in actions)

    def require_permission(self, user: User, resource: str, actions: Union[str, List[str]]) -> None:
        if not self.has_permission(user, resource, actions):
            actions_str = ", ".join(actions if isinstance(actions, list) else [actions])
            raise PermissionDeniedError(user.id, resource, actions_str)
