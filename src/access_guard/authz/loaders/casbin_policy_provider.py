from abc import ABC, abstractmethod
from typing import List

from access_guard.authz.loaders.policy_provider_abc import PolicyProvider
from access_guard.authz.models.casbin_policy import CasbinPolicy


class CasbinPolicyProvider(PolicyProvider):
    @abstractmethod
    def get_policies(self) -> List[CasbinPolicy]:
        pass

