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
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(
            request: Request,
            *args,
            **kwargs
        ):
            try:
                authorization = request.headers.get('Authorization')
                x_tenant = request.headers.get('x-tenant')
                
                if not authorization:
                    raise HTTPException(status_code=401, detail="Authorization header is required")
                if not x_tenant:
                    raise HTTPException(status_code=401, detail="x-tenant header is required")
                    
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
                
                # Check if function expects request parameter
                import inspect
                sig = inspect.signature(func)
                if 'request' in sig.parameters:
                    kwargs['request'] = request
                
                # Call the function
                return await func(*args, **kwargs)
                
            except AuthenticationError as e:
                raise HTTPException(status_code=401, detail=str(e))
            except AuthorizationError as e:
                raise HTTPException(status_code=403, detail=str(e))
            except ApiError as e:
                raise HTTPException(status_code=500, detail=str(e))
                
        return wrapper
    return decorator
