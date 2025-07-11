"""Decorator module for authorization checks."""

import functools
from typing import Optional
from fastapi import Request, HTTPException, Depends
from .client import AuthClient

async def validate_auth(request: Request = Depends(),
                       resource_id: Optional[str] = None,
                       resource_type: Optional[str] = None,
                       action: Optional[str] = None,
                       include_auth_data: bool = False):
    """FastAPI dependency to validate authorization."""
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
    
    if include_auth_data:
        if not auth_result.get('authorized', False):
            raise HTTPException(status_code=403, 
                detail=f"Access denied to resource: {resource_id or resource_type}")
        return auth_result
    
    if not auth_result:
        raise HTTPException(status_code=403, 
            detail=f"Access denied to resource: {resource_id or resource_type}")
    
    return True

def requires_auth(resource_id: Optional[str] = None, 
                 resource_type: Optional[str] = None, 
                 action: Optional[str] = None, 
                 include_auth_data: bool = False):
    """Decorator to check authorization before executing a function.
    
    Args:
        resource_id (str, optional): ID of the resource to validate access for
        resource_type (str, optional): Type of the resource (e.g., 'TENANT', 'USER')
        action (str, optional): Action to validate (e.g., 'READ', 'WRITE', 'DELETE')
        include_auth_data (bool, optional): If True, passes auth response data to the decorated function
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Add auth validation as a dependency
            auth_result = await validate_auth(
                resource_id=resource_id,
                resource_type=resource_type,
                action=action,
                include_auth_data=include_auth_data
            )
            
            # Add auth_data to kwargs if needed
            if include_auth_data and auth_result is not True:
                kwargs['auth_data'] = auth_result
            
            # Call the original function
            return await func(*args, **kwargs)
            
        # Add the auth dependency to the function
        wrapper.__dependencies__ = getattr(func, '__dependencies__', [])
        wrapper.__dependencies__.append(
            Depends(lambda: validate_auth(
                resource_id=resource_id,
                resource_type=resource_type,
                action=action,
                include_auth_data=include_auth_data
            ))
        )
        
        return wrapper
    return decorator
