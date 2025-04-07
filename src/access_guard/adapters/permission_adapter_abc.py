from abc import ABC, abstractmethod
from typing import List, Union

class PermissionAdapter(ABC):
    """
    Abstract base class for permission adapters.
    This defines the interface that all permission adapters must implement.
    """
    
    @abstractmethod
    def has_permission(self, user: str, resource: str, actions: Union[str, List[str]]) -> bool:
        """
        Check if the user has at least one of the specified actions permitted on the resource.
        
        Args:
            user: The user identifier (typically username)
            resource: The resource identifier (policy object string)
            actions: Single action or list of actions to check
            
        Returns:
            bool: True if the user has permission for at least one action, False otherwise
        """
        pass
    
    @abstractmethod
    def require_permission(self, user: str, resource: str, actions: Union[str, List[str]]) -> None:
        """
        Check permissions and raise PermissionDeniedError if not allowed.
        
        Args:
            user: The user identifier (typically username)
            resource: The resource identifier (policy object string)
            actions: Single action or list of actions to check
            
        Raises:
            PermissionDeniedError: If the user doesn't have the required permissions
        """
        pass
    
    @abstractmethod
    def refresh_policies(self) -> None:
        """
        Reload all policies from the adapter into the enforcer.
        Call this when policies have been updated in the database.
        """
        pass
    
    @abstractmethod
    def enforce(self, user: str, resource: str, action: str) -> bool:
        """
        Direct enforcement check for a specific user, resource, and action.
        
        Args:
            user: The user identifier
            resource: The resource identifier
            action: The action to check
            
        Returns:
            bool: True if the action is allowed, False otherwise
        """
        pass
    
    @abstractmethod
    def load_policy(self, entity) -> List[str]:
        """
        Load policies for a specific entity (user or role).
        
        Args:
            entity: The entity (user or role) to load policies for
            
        Returns:
            List[str]: List of policy strings in the format "p, subject, resource, action, effect"
                      or "g, user, role" for role assignments
        """
        pass 