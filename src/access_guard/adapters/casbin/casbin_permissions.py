import logging
from pathlib import Path
from typing import List, Union, ClassVar, Optional

import casbin
from casbin import Model
from sqlalchemy.engine import Engine

from .casbin_database_adapter import CasbinDatabaseAdapter
from .casbin_adapter_params import CasbinAdapterParams

from ..exceptions import PermissionDeniedError
from ..permission_adapter_abc import PermissionAdapter

logger = logging.getLogger(__name__)

# Get the path to the model file relative to this module
DEFAULT_MODEL_PATH = Path(__file__).parent / "config" / "rbac_model.conf"


class CasbinPermissions(PermissionAdapter):
    _instance: ClassVar[Optional['CasbinPermissions']] = None
    _model = None
    _enforcer = None
    _engine = None
    _params = None

    def __init__(self, engine: Engine = None, params: Optional[CasbinAdapterParams] = None):
        if self._enforcer is not None:
            return
        if engine is None:
            raise ValueError("Engine must be provided for first initialization")
        self._engine = engine
        self._params = params
        self._initialize_enforcer()

    @classmethod
    def get_instance(cls, engine: Engine = None, params: Optional[CasbinAdapterParams] = None) -> 'CasbinPermissions':
        if cls._instance is None:
            if engine is None:
                raise ValueError("Engine is required to create the singleton instance")
            cls._instance = cls(engine, params)
        return cls._instance

    def _initialize_enforcer(self):
        adapter = CasbinDatabaseAdapter(self._engine)
        model = Model()
        # model_path = Path(self._params.rbac_model_path) if self._params and self._params.rbac_model_path else DEFAULT_MODEL_PATH

        if self._params and self._params.rbac_model_path:
            model_path = Path(self._params.rbac_model_path)
        else:
            model_path = DEFAULT_MODEL_PATH

        model.load_model(model_path)
        self._enforcer = casbin.Enforcer(model, adapter)
        self._model = model

    @property
    def model(self):
        return self._model

    @property
    def enforcer(self):
        return self._enforcer

    @property
    def engine(self):
        return self._engine

    def has_permission(self, user: str, resource: str, actions: Union[str, List[str]]) -> bool:
        """
        Check if the user has at least one of the specified actions permitted on the resource.

        Args:
            user: The user identifier (typically username)
            resource: The resource identifier (policy object string)
            actions: Single action or list of actions to check

        Returns:
            bool: True if the user has permission for at least one action, False otherwise
        """
        if isinstance(actions, str):
            actions = [actions]

        return any(self.enforce(user, resource, action) for action in actions)

    def require_permission(self, user: str, resource: str, actions: Union[str, List[str]]) -> None:
        """
        Check permissions and raise PermissionDeniedError if not allowed.
        
        Args:
            user: The user identifier (typically username)
            resource: The resource identifier (policy object string)
            actions: Single action or list of actions to check
            
        Raises:
            PermissionDeniedError: If the user doesn't have the required permissions
        """
        if not self.has_permission(user, resource, actions):
            actions_str = ", ".join(actions if isinstance(actions, list) else [actions])
            raise PermissionDeniedError(user, resource, actions_str)

    def refresh_policies(self) -> None:
        """
        Reload all policies from the adapter into the enforcer.
        Call this when policies have been updated in the database.
        """
        logger.info("Refreshing Casbin policies...")
        self._enforcer.load_policy()
        logger.info("Casbin policies refreshed successfully")

    def enforce(self, user: str, resource: str, action: str) -> bool:
        """
        Direct enforcement check for a specific user, resource, and action.
        
        Args:
            user: The user identifier
            resource: The resource identifier
            action: The action to check
            
        Returns:
            bool: True if the action is allowed, False otherwise
        """
        return self._enforcer.enforce(user, resource, action)

    def load_policy(self, entity) -> List[str]:
        """
        Load policies for a specific entity (user or role).
        
        Args:
            entity: The entity (user or role) to load policies for
            
        Returns:
            List[str]: List of policy strings in the format "p, subject, resource, action, effect"
                      or "g, user, role" for role assignments
        """
        # Create a fresh adapter instance to avoid caching issues
        adapter = CasbinDatabaseAdapter(self.engine, True)
        local_enforcer = casbin.Enforcer(self.model, adapter)

        # Load policies for the entity
        local_enforcer.adapter.load_policy(local_enforcer.model, entity)

        # Extract and format policies
        policies = local_enforcer.model.model["p"]["p"].policy
        roles = local_enforcer.model.model["g"]["g"].policy

        formatted_policies = []
        for p in policies:
            if len(p) == 4:  # Allow/deny effect included
                formatted_policies.append(f"p, {p[1]}, {p[2]}, {p[3]}, {p[0]}")
            else:  # No effect (default to allow)
                formatted_policies.append(f"p, {p[0]}, {p[1]}, {p[2]}, allow")

        # Format roles
        for r in roles:
            formatted_policies.append(f"g, {r[0]}, {r[1]}")

        return formatted_policies
