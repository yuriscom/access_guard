from abc import ABC, abstractmethod


class PolicyQueryProvider(ABC):
    @abstractmethod
    def get_all_policies_query(self) -> tuple[str, dict]:
        pass

    @abstractmethod
    def get_filtered_policies_query(self, filter: dict) -> tuple[str, dict]:
        pass

    @abstractmethod
    def get_user_policy_query(self, user_id: str) -> tuple[str, dict]:
        pass

    @abstractmethod
    def get_role_policy_query(self, role_id: str) -> tuple[str, dict]:
        pass
