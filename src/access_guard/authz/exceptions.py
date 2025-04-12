class PermissionDeniedError(Exception):
    """
    Exception raised when a user doesn't have the required permissions.
    """
    
    def __init__(self, user: str, resource: str, actions: str):
        """
        Initialize the exception.
        
        Args:
            user: The user identifier
            resource: The resource identifier
            actions: The actions that were denied
        """
        self.user = user
        self.resource = resource
        self.actions = actions
        self.message = f"User '{user}' does not have permission to perform '{actions}' on '{resource}'"
        super().__init__(self.message) 