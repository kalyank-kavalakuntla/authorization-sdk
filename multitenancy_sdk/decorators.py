"""Decorator module for authorization checks."""

import functools
import asyncio
from typing import Callable, Optional
from fastapi import Header, Request, HTTPException, Depends
from .client import AuthClient, AuthenticationError, AuthorizationError, ApiError

def get_auth_headers(request: Request = Depends()) -> tuple[str, str]:
    """FastAPI dependency to extract and validate auth headers."""
    authorization = request.headers.get('Authorization')
    x_tenant = request.headers.get('x-tenant')
    
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header is required")
    if not x_tenant:
        raise HTTPException(status_code=401, detail="x-tenant header is required")
        
    return authorization, x_tenant

def requires_auth(resource_id: Optional[str] = None, 
                 resource_type: Optional[str] = None, 
                 action: Optional[str] = None, 
                 include_auth_data: bool = False) -> Callable:
    """Decorator to check authorization before executing a function.
    
    Args:
        resource_id (str, optional): ID of the resource to validate access for
        resource_type (str, optional): Type of the resource (e.g., 'TENANT', 'USER')
        action (str, optional): Action to validate (e.g., 'READ', 'WRITE', 'DELETE')
        include_auth_data (bool, optional): If True, passes auth response data to the decorated function
    """
    def decorator(func: Callable) -> Callable:
        # Create a FastAPI dependency for auth validation
        async def auth_dependency(headers: tuple[str, str] = Depends(get_auth_headers)):
            authorization, x_tenant = headers
            client = AuthClient(authorization=authorization, x_tenant=x_tenant)
            auth_result = client.validate_access(
                resource_id=resource_id,
                resource_type=resource_type,
                action=action,
                return_data=include_auth_data
            )
            
            if include_auth_data:
                if not auth_result.get('authorized', False):
                    raise HTTPException(
                        status_code=403,
                        detail=f"Access denied to resource: {resource_id or resource_type}"
                    )
                return auth_result
            
            if not auth_result:
                raise HTTPException(
                    status_code=403,
                    detail=f"Access denied to resource: {resource_id or resource_type}"
                )
            
            return True
        
        # Create the wrapper function
        if asyncio.iscoroutinefunction(func):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                auth_result = await auth_dependency()
                if include_auth_data and auth_result is not True:
                    kwargs['auth_data'] = auth_result
                return await func(*args, **kwargs)
        else:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                auth_result = asyncio.run(auth_dependency())
                if include_auth_data and auth_result is not True:
                    kwargs['auth_data'] = auth_result
                return func(*args, **kwargs)
        # Add the auth dependency to the function
        wrapper.__dependencies__ = getattr(func, '__dependencies__', [])
        wrapper.__dependencies__.append(Depends(auth_dependency))
        
        return wrapper
    return decorator
