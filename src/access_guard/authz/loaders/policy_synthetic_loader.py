import logging
from typing import Callable, List, Tuple

from casbin import Model, persist
from access_guard.authz.loaders.policy_loader_abc import PolicyLoaderABC

logger = logging.getLogger(__name__)


class PolicySyntheticLoader(PolicyLoaderABC):
    def __init__(self, policy_provider: Callable[[], List[Tuple[str, ...]]]):
        self.policy_provider = policy_provider

    def load_policy(self, model: Model):
        entries = self.policy_provider()
        for entry in entries:
            policy_line = ", ".join(entry)
            logger.debug(f"Loading synthetic policy rule: {policy_line}")
            persist.load_policy_line(policy_line, model)

    def save_policy(self, model: Model):
        raise NotImplementedError("SyntheticPolicyLoader does not support saving policies.")

    def add_policy(self, sec, ptype, rule):
        raise NotImplementedError("SyntheticPolicyLoader does not support adding policies.")

    def remove_policy(self, sec, ptype, rule):
        raise NotImplementedError("SyntheticPolicyLoader does not support removing policies.")
