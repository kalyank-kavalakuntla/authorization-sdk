"""Decorator module for authorization checks."""

import functools
from typing import Optional
from fastapi import Request, HTTPException, Depends
from .client import AuthClient

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
            from fastapi import Request, Depends
            
            # Get request from FastAPI's dependency injection
            request = kwargs.get('request')
            if not request:
                async def get_request(request: Request = Depends()) -> Request:
                    return request
                request = await get_request()
            try:
                # Get headers from request
                authorization = request.headers.get('Authorization')
                x_tenant = request.headers.get('x-tenant')
                
                if not authorization:
                    raise HTTPException(status_code=401, detail="Authorization header is required")
                if not x_tenant:
                    raise HTTPException(status_code=401, detail="x-tenant header is required")
                
                # Validate access
                client = AuthClient(authorization=authorization, x_tenant=x_tenant)
                auth_result = client.validate_access(
                    resource_id=resource_id,
                    resource_type=resource_type,
                    action=action,
                    return_data=include_auth_data
                )
                
                # Handle auth result
                if include_auth_data:
                    if not auth_result.get('authorized', False):
                        raise HTTPException(status_code=403, 
                            detail=f"Access denied to resource: {resource_id or resource_type}")
                    kwargs['auth_data'] = auth_result
                elif not auth_result:
                    raise HTTPException(status_code=403, 
                        detail=f"Access denied to resource: {resource_id or resource_type}")
                
                # Call the original function
                return await func(*args, **kwargs)
                
            except Exception as e:
                if isinstance(e, HTTPException):
                    raise e
                raise HTTPException(status_code=500, detail=str(e))
                
        return wrapper
    return decorator
