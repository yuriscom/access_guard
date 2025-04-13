from enum import Enum


class PolicyLoaderType(Enum):
    REMOTE = "remote"
    DB = "db"

class PermissionsAdapterType(Enum):
    """
    Enum for different types of permission adapters.
    """
    CASBIN = "casbin"
