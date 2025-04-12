import logging

import requests
from casbin import persist
from casbin.model import Model

from .policy_loader_abc import PolicyLoaderABC

logger = logging.getLogger(__name__)


class PolicyApiLoader(PolicyLoaderABC):
    def __init__(self, api_url: str):
        """
        Initialize the adapter with API details.
        :param api_url: Base URL of the access management API (e.g., https://iam.example.com)
        :param api_token: System-to-system token for authorization
        """
        super().__init__()
        self.api_url = api_url.rstrip("/")

    def is_filtered(self) -> bool:
        return self._is_filtered

    def set_filtered(self, is_filtered: bool = True):
        self._is_filtered = is_filtered

    def load_policy(self, model: Model) -> None:

        self.set_filtered(True)

        ### TODO: should be replaced by bearer token, this should be added by API Gateway
        headers = {
            # "Authorization": f"Bearer {self.api_token}",
            "Accept": "application/json",
            "app_id": "1",
            "user_id": "3",
            "scope": "APP"
        }

        try:
            url = f"{self.api_url}/iam/policies"
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            policies = response.json()
        except Exception as e:
            logger.error(f"Failed to fetch policies from {url}: {e}")
            raise

        for entry in policies:
            parts = [entry["ptype"], entry["subject"], entry["object"]]
            if entry.get("action") is not None:
                parts.append(entry["action"])
            if entry.get("effect") is not None:
                parts.append(entry["effect"])
            policy_line = ", ".join(parts)
            logger.debug(f"Loading policy rule: {policy_line}")
            persist.load_policy_line(policy_line, model)

