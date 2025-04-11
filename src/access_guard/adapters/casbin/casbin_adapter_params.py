from typing import Optional

from sqlalchemy import Engine
from pydantic import Field, validator

from .domain.adapter_type import CasbinAdapterType
from ..adapter_params import AdapterParams


class CasbinAdapterParams(AdapterParams):
    rbac_model_path: Optional[str] = None
    engine: Optional[Engine] = None
    casbin_adapter_type: Optional[CasbinAdapterType] = None
    access_api_url: Optional[str] = None
    access_api_client: Optional[str] = None
    access_api_secret: Optional[str] = None
    scope: Optional[str] = None
    app_id: Optional[str] = None

    class Config:
        arbitrary_types_allowed = True

    @validator("casbin_adapter_type", pre=True, always=True)
    def default_if_none(cls, v):
        if v is None:
            return CasbinAdapterType.REMOTE
        return v

    def validate(self):
        if self.casbin_adapter_type == CasbinAdapterType.DB:
            if self.engine is None:
                raise ValueError("Engine must be provided for adapter type DB")
            return

        if self.casbin_adapter_type == CasbinAdapterType.REMOTE:
            if not all([self.access_api_url, self.access_api_client, self.access_api_secret]):
                raise ValueError(
                    "access_api_url, access_api_client and access_api_secret must be provided for adapter type REMOTE")
            return

        raise ValueError(f"Unsupported adapter type: {self.casbin_adapter_type}")
