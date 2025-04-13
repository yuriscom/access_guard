from typing import Optional
from pydantic import BaseModel


class LoadPolicyResult(BaseModel):
    resource_prefix: Optional[str] = None
