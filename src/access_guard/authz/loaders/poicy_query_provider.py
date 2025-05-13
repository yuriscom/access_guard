from abc import ABC, abstractmethod

from access_guard.authz.loaders.policy_provider_abc import PolicyProvider


class PolicyQueryProvider(PolicyProvider):
    @abstractmethod
    def get_all_policies_query(self) -> tuple[str, dict]:
        pass

    @abstractmethod
    def get_filtered_policies_query(self, filter: dict) -> tuple[str, dict]:
        pass

    @abstractmethod
    def get_user_policies_query(self, user_id: str) -> tuple[str, dict]:
        pass

    @abstractmethod
    def get_role_policies_query(self, role_id: str) -> tuple[str, dict]:
        pass
