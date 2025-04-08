# Access Guard

A framework-agnostic IAM library with Casbin-based permission adapter.

## Installation (Local Development)

This library is intended to be consumed as a local or Git-based dependency in your application.

### Add as a local editable dependency (recommended for dev)

```bash
poetry add ../access-guard --editable
```

This will install the package in editable mode and allow your application to reflect changes instantly.

### Alternatively, use a Git URL (for production installs)

```bash
poetry add git+https://github.com/your-org/access-guard.git
```

## Configuration

Access Guard does not enforce a specific configuration format. It is the responsibility of the application using the library to parse and pass the required configuration values.

### Supported Configuration Options

- `adapter_type` (str): Required. Indicates which permission adapter to use.  
  - Currently supported: `"casbin"`

- `rbac_model_path` (str, optional): Path to a custom Casbin model configuration file.  
  - If not provided, Access Guard will use its built-in default model.

More configuration options will be supported as the library evolves.

## Usage

### Creating the permission adapter

```python
from sqlalchemy import create_engine
from access_guard.adapters.factory import get_permission_adapter

# Example usage
engine = create_engine(database_url)
permissions = get_permission_adapter(adapter_type, engine)
```

### Checking permissions

```python
# Check if a user has permission
has_access = permissions.has_permission("user1", "resource1", "read")

# Require permission (will raise PermissionDeniedError if not allowed)
permissions.require_permission("user1", "resource1", "write")
```

## Adapter Support

Currently supported:
- Casbin

The system is extensible with a pluggable adapter architecture. You can add your own adapter by implementing the `PermissionAdapter` interface and registering it in the factory.

## FastAPI Integration

Access Guard is framework-agnostic. You may choose to use it within FastAPI or any other web framework by injecting the permission adapter wherever needed.

For example, in FastAPI, you can create a dependency wrapper:

```python
from fastapi import Depends, HTTPException
from access_guard.adapters.exceptions import PermissionDeniedError

def require_permission(subject: str, resource: str, action: str):
    def checker():
        try:
            permissions.require_permission(subject, resource, action)
        except PermissionDeniedError:
            raise HTTPException(status_code=403, detail="Permission denied")
    return checker
```
