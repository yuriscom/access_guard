import logging

import requests
from casbin import persist
from casbin.model import Model

from access_guard.authz.models.load_policy_result import LoadPolicyResult
from access_guard.authz.loaders.policy_loader_abc import PolicyLoaderABC

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

    def load_policy(self, model: Model) -> LoadPolicyResult:

        self.set_filtered(True)

        ### TODO: should be replaced by bearer token, this should be added by API Gateway
        headers = {
            # "Authorization": f"Bearer {self.api_token}",
            "Accept": "application/json",
            "app_id": "9e43b935-d443-4505-aaea-4d02dc7ba667",
            "user_id": "a2c49b9a-d36b-499d-adce-bb1196b353d2",
            "scope": "APP"
        }

        try:
            url = f"{self.api_url}/iam/policies"
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            if "policies" not in data or not isinstance(data["policies"], list):
                raise ValueError(f"Invalid policies response from {url}")

            loaded_policies = []

            for entry in data["policies"]:
                parts = [entry["ptype"], entry["subject"], entry["object"]]
                if entry.get("action") is not None:
                    parts.append(entry["action"])
                if entry.get("effect") is not None:
                    parts.append(entry["effect"])

                policy_tuple = tuple(parts)
                loaded_policies.append(policy_tuple)

                policy_line = ", ".join(parts)
                logger.debug(f"Loading policy rule: {policy_line}")
                persist.load_policy_line(policy_line, model)

            return LoadPolicyResult(
                resource_prefix=data.get("resource_prefix", ""),
                policies=loaded_policies
            )

        except Exception as e:
            logger.error(f"Failed to fetch policies from {url}: {e}")
            raise



