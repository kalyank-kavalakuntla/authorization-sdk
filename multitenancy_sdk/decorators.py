"""Decorator module for authorization checks."""

import functools
from fastapi import Header, Request, HTTPException
from .client import AuthClient, AuthenticationError, AuthorizationError, ApiError

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
        async def wrapper(
            request: Request,
            *args, 
            **kwargs
        ):
            try:
                # Get headers directly from request
                authorization = request.headers.get('Authorization')
                x_tenant = request.headers.get('x-tenant')
                
                if not authorization:
                    raise AuthenticationError("Authorization header is required")
                if not x_tenant:
                    raise AuthenticationError("x-tenant header is required")
                    
                client = AuthClient(authorization=authorization, x_tenant=x_tenant)
                auth_result = client.validate_access(
                    resource_id=resource_id,
                    resource_type=resource_type,
                    action=action,
                    return_data=include_auth_data
                )
                
                # Check authorization result
                if include_auth_data:
                    if not auth_result.get('authorized', False):
                        raise AuthorizationError(
                            f"Access denied to resource: {resource_id or resource_type}"
                        )
                    # Only add auth_data if function accepts it
                    import inspect
                    sig = inspect.signature(func)
                    if 'auth_data' in sig.parameters:
                        kwargs['auth_data'] = auth_result
                else:
                    if not auth_result:
                        raise AuthorizationError(
                            f"Access denied to resource: {resource_id or resource_type}"
                        )
                
                # Check if function requires request parameter
                sig = inspect.signature(func)
                if 'request' in sig.parameters and sig.parameters['request'].default == inspect.Parameter.empty:
                    kwargs['request'] = request
                
                # Check if function is async
                import asyncio
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                return func(*args, **kwargs)
                
            except AuthenticationError as e:
                raise HTTPException(status_code=401, detail=str(e))
            except AuthorizationError as e:
                raise HTTPException(status_code=403, detail=str(e))
            except ApiError as e:
                raise HTTPException(status_code=500, detail=str(e))
                
        return wrapper
    return decorator
