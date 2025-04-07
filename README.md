# Permission Adapter

A framework-agnostic permission adapter with Casbin implementation.

## Installation

```bash
pip install permission-adapter
```

For FastAPI integration:

```bash
pip install permission-adapter[fastapi]
```

## Usage

### Basic Usage

```python
from sqlalchemy import create_engine
from permission_adapter.adapters.factory import create_permission_adapter

# Create a database engine
engine = create_engine("sqlite:///permissions.db")

# Create a permission adapter
permissions = create_permission_adapter(engine)

# Check if a user has permission
has_access = permissions.has_permission("user1", "resource1", "read")

# Require permission (will raise PermissionDeniedError if not allowed)
permissions.require_permission("user1", "resource1", "write")
```

### FastAPI Integration

```python
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from permission_adapter.adapters.exceptions import PermissionDeniedError
from permission_adapter.adapters.factory import get_permission_adapter

app = FastAPI()

# Dependency to get the permission adapter
def get_permissions():
    engine = create_engine("sqlite:///permissions.db")
    return get_permission_adapter(engine=engine)

@app.get("/resource/{resource_id}")
async def get_resource(resource_id: str, user_id: int, permissions = Depends(get_permissions)):
    try:
        # Check permission
        permissions.require_permission(f"user_{user_id}", f"resource_{resource_id}", "read")
        
        # If we get here, the user has permission
        return {"resource_id": resource_id, "data": "resource data"}
    except PermissionDeniedError as e:
        # Convert to HTTP exception
        raise HTTPException(status_code=403, detail=str(e))
```

## License

MIT
