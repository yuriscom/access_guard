from typing import Optional, List, Tuple

from pydantic import BaseModel


class LoadPolicyResult(BaseModel):
    resource_prefix: Optional[str] = None
    policies: List[Tuple[str, ...]] = []  # default empty list, always a list of tuples
