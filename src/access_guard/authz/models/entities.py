from dataclasses import dataclass
from typing import Optional

@dataclass
class Role:
    role_name: str
    scope: Optional[str] = None
    app_id: Optional[int] = None
    org_id: Optional[int] = None

@dataclass
class User:
    id: str
