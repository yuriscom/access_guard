from enum import Enum


class PolicyLoaderType(Enum):
    REMOTE = "remote"
    DB = "db"
    SYNTHETIC = "synthetic"

class PermissionsAdapterType(Enum):
    """
    Enum for different types of permission adapters.
    """
    CASBIN = "casbin"
