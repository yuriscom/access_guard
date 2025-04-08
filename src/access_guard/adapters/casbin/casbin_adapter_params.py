from typing import Optional

from ..adapter_params import AdapterParams

class CasbinAdapterParams(AdapterParams):
    rbac_model_path: Optional[str] = None
