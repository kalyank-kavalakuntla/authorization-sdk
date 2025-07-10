"""Decorator module for authorization checks."""

import functools
from .client import AuthClient
from .exceptions import AuthorizationError

def requires_auth(resource_id=None, resource_type=None, action=None, include_auth_data=False):
    """Decorator to check authorization before executing a function.
    
    Args:
        resource_id (str, optional): ID of the resource to validate access for
        resource_type (str, optional): Type of the resource (e.g., 'TENANT', 'USER')
        action (str, optional): Action to validate (e.g., 'READ', 'WRITE', 'DELETE')
        include_auth_data (bool, optional): If True, passes auth response data to the decorated function
    
    Returns:
        function: Decorated function that checks authorization
    
    Raises:
        AuthenticationError: If JWT token is invalid
        AuthorizationError: If access is denied
        ApiError: If API request fails
    
    Example:
        @requires_auth(resource_id="resource123", include_auth_data=True)
        def protected_function(auth_data=None):
            # auth_data contains user, tenant, and resource information
            user = auth_data.get('user')
            print(f"Hello {user['name']}")
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            client = AuthClient()
            auth_result = client.validate_access(
                resource_id=resource_id,
                resource_type=resource_type,
                action=action,
                return_data=include_auth_data
            )
            
            if include_auth_data:
                if not auth_result.get('authorized', False):
                    raise AuthorizationError(
                        f"Access denied to resource: {resource_id}"
                    )
                kwargs['auth_data'] = auth_result
            else:
                if not auth_result:
                    raise AuthorizationError(
                        f"Access denied to resource: {resource_id}"
                    )
            
            return func(*args, **kwargs)
        return wrapper
    return decorator
