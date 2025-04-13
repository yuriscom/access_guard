import logging
from typing import List, Optional, Union

from casbin import persist
from casbin.model import Model
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from access_guard.authz.models.entities import Role, User
from access_guard.authz.models.load_policy_result import LoadPolicyResult
from access_guard.authz.loaders.poicy_query_provider import PolicyQueryProvider
from access_guard.authz.loaders.policy_loader_abc import PolicyLoaderABC

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class PolicyDbLoader(PolicyLoaderABC):
    def __init__(self, engine, query_provider: PolicyQueryProvider):
        super().__init__()
        self.engine = engine
        self.Session = sessionmaker(bind=engine)
        self.query_provider = query_provider

    def set_filtered(self, is_filtered: bool = True):
        self._is_filtered = is_filtered

    def is_filtered(self) -> bool:
        return getattr(self, "_is_filtered", False)

    def load_policy(self, model: Model,
                    entity: Optional[Union[User, Role]] = None,
                    filter: dict = None
                    ) -> None:
        if entity:
            if isinstance(entity, User):
                logger.debug(f"Loading policies for User: {entity.id}")
                query, params = self.query_provider.get_user_policy_query(entity.id)
            elif isinstance(entity, Role):
                logger.debug(f"Loading policies for Role: {entity.role_name}")
                query, params = self.query_provider.get_role_policy_query(entity.id)
            else:
                logger.warning(f"Unsupported subject type: {entity.__class__.__name__}")
                return
        elif filter:
            query, params = self.query_provider.get_filtered_policies_query(filter)
        else:
            logger.debug("Loading all policies...")
            query, params = self.query_provider.get_all_policies_query()

        self._run_load_policy(query, params, model)

        return LoadPolicyResult()

    def _run_load_policy(self, query: str, params: dict, model: Model) -> None:
        """
        Private method to execute the query and load policies into the Casbin model.
        """
        session = self.Session()
        try:
            result = session.execute(text(query), params)
            for row in result:
                if row.ptype == "p":  # Only add effect for permission policies
                    effect = row.effect if row.effect else "allow"  # Default to "allow" if missing
                    line = f"{row.ptype}, {row.subject}, {row.object}, {row.action}, {effect}"
                elif row.ptype == "g":
                    line = f"{row.ptype}, {row.subject}, {row.object}"
                else:
                    logger.warning(f"Unknown policy type: {row.ptype}")
                    continue
                logger.debug(f"Loading policy rule: {line}")
                persist.load_policy_line(line, model)
        except Exception as e:
            logger.error(f"Error loading policies: {e}")
            logger.exception(e)  # This will print the full stack trace
        finally:
            session.close()

    def save_policy(self, model: Model) -> bool:
        """Save policy to database."""
        # This is now handled by the IAM service
        return True

    def add_policy(self, sec: str, ptype: str, rule: List[str]) -> bool:
        """Add policy rule to the storage."""
        # This is now handled by the IAM service
        return True

    def remove_policy(self, sec: str, ptype: str, rule: List[str]) -> bool:
        """Remove policy rule from the storage."""
        # This is now handled by the IAM service
        return True

    def remove_filtered_policy(self, sec: str, ptype: str, field_index: int, *field_values: str) -> bool:
        """Remove policy rules that match the filter from the storage."""
        # This is now handled by the IAM service
        return True
