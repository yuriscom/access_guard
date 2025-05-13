import logging
from typing import List

from casbin import persist
from casbin.model import Model

from access_guard.authz.loaders.casbin_policy_provider import CasbinPolicyProvider
from access_guard.authz.loaders.policy_loader_abc import PolicyLoaderABC
from access_guard.authz.models.load_policy_result import LoadPolicyResult

logger = logging.getLogger(__name__)


class PolicyCodeLoader(PolicyLoaderABC):
    def __init__(self, policy_provider: CasbinPolicyProvider):
        self.policy_provider = policy_provider

    def load_policy(self, model: Model, entity=None, filter=None):
        casbin_policies = self.policy_provider.get_policies(filter)
        policy_tuples = []
        for p in casbin_policies:
            tup, line = p.to_tuple_and_string()
            persist.load_policy_line(line, model)
            logger.debug(f"Loading policy rule: {line}")
            policy_tuples.append(tup)

        return LoadPolicyResult(
            resource_prefix="",  # todo: see if needed here
            policies=policy_tuples
        )

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
