# Access Guard

A framework-agnostic IAM library with Casbin-based permission enforcer.

## Installation (Local Development)

This library is intended to be consumed as a local or Git-based dependency in your application.

### Add as a local editable dependency (recommended for dev)

```bash
poetry add ../access-guard --editable
```

### Alternatively, use a Git URL (for production installs)

```bash
poetry add git+https://github.com/your-org/access-guard.git
```

## Configuration

Access Guard is fully configurable through the `settings` object provided to the factory method.

The settings can be a Pydantic model or a simple dictionary. 

### Required Settings

| Field                | Description                                          | Required | Notes                                    |
|---------------------|------------------------------------------------------|-----------|------------------------------------------|
| policy_loader_type  | Source of policies: DB or REMOTE                    | Yes       | Enum: PolicyLoaderType.DB or REMOTE     |
| rbac_model_path     | Path to Casbin model.conf                           | Optional  | Defaults to internal config if omitted  |
| policy_api_url      | URL of Access Management API                        | Required for REMOTE loader | Only for API Loader |
| policy_api_client   | API client ID                                       | Optional  | For remote API loader if applicable     |
| policy_api_secret   | API client secret                                   | Optional  | For remote API loader if applicable     |
| filter              | Dict containing filter parameters for policies      | Optional  | Fully agnostic structure                |


## Usage

### Get Permissions Enforcer (Client Side)

```python
from access_guard.authz.factory import get_permissions_enforcer
from access_guard.authz.models.enums import PolicyLoaderType
from access_guard.authz.models.permissions_enforcer_params import PermissionsEnforcerParams

params_dict = {
    "policy_loader_type": PolicyLoaderType.REMOTE,
    "rbac_model_path": "path/to/your/rbac_model.conf",
    "policy_api_url": ...,
    "policy_api_client": ...,
    "policy_api_secret": ...
}

params = PermissionsEnforcerParams(**params_dict)

enforcer = get_permissions_enforcer(
    settings=params
)
```

### Get Permissions Enforcer (Access Management Microservice Side)

```python
from access_guard.authz.factory import get_permissions_enforcer
from access_guard.authz.models.enums import PolicyLoaderType
from access_guard.authz.models.permissions_enforcer_params import PermissionsEnforcerParams
from access_manager_api.providers.policy_query_provider import AccessManagementQueryProvider

params_dict = {
    "policy_loader_type": PolicyLoaderType.DB,
    "rbac_model_path": "path/to/your/rbac_model.conf",
    "filter": {
        "policy_api_scope": "SMC",
        "policy_api_appid": None
    }
}

params = PermissionsEnforcerParams(**params_dict)

enforcer = get_permissions_enforcer(
    settings=params,
    engine=get_engine(),
    query_provider=AccessManagementQueryProvider()
)
```


## Checking Permissions

```python
    try:
        # Check permission using require_permission which will raise PermissionDeniedError if not allowed
        access_guard_enforcer.require_permission(user, "resource1", "read")
    except PermissionDeniedError as e:
        raise HTTPException(status_code=403, detail=str(e))
```
OR
```python
has_access = access_guard_enforcer.has_permission(user, "resource1", "read")
```

## Adapters

Currently supported loaders:
- PolicyDbLoader (Database)
- PolicyApiLoader (Remote API)
- PolicySyntheticLoader (Synthetically generated policies)
