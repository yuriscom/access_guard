
from typing import Optional, Dict, Any

from pydantic import BaseModel

from access_guard.authz.models.enums import PolicyLoaderType


class PermissionsEnforcerParams(BaseModel):
    policy_loader_type: PolicyLoaderType = PolicyLoaderType.REMOTE
    rbac_model_path: Optional[str] = None

    # remote specific
    policy_api_url: Optional[str] = None
    policy_api_client: Optional[str] = None
    policy_api_secret: Optional[str] = None

    # generic filter to be passed as-is to loaders
    filter: Optional[Dict[str, Any]] = None

    class Config:
        arbitrary_types_allowed = True
