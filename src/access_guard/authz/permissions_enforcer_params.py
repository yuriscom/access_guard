from typing import Optional

from pydantic import BaseModel

from access_guard.authz.enums import PolicyLoaderType


class PermissionsEnforcerParams(BaseModel):
    policy_loader_type: PolicyLoaderType = PolicyLoaderType.REMOTE
    rbac_model_path: Optional[str] = None

    # remote specific
    policy_api_url: Optional[str] = None
    policy_api_client: Optional[str] = None
    policy_api_secret: Optional[str] = None

    ### temp
    scope: Optional[str] = None
    app_id: Optional[str] = None
    user_id: Optional[str] = None

    class Config:
        arbitrary_types_allowed = True
