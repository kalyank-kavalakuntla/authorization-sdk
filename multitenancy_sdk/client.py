from fastapi import Header, HTTPException
from typing import Optional
import os
from functools import wraps
import requests

class AuthenticationError(Exception):
    pass

class AuthorizationError(Exception):
    pass

class ApiError(Exception):
    pass

class AuthClient:
    def __init__(self, authorization: str = None, x_tenant: str = None):
        """Initialize AuthClient with authorization headers.
        
        Args:
            authorization (str): The authorization header value (required)
            x_tenant (str): The x-tenant header value (required)
        """
        self.auth_url = os.getenv('AUTH_SERVICE_URL')
        if not self.auth_url:
            raise ValueError("AUTH_SERVICE_URL environment variable is required")
        self.authorization = authorization
        self.x_tenant = x_tenant

    def validate_access(
        self,
        resource_id: str = None,
        resource_type: str = None,
        action: str = None,
        authorization: str = None,
        x_tenant: str = None,
        return_data: bool = False,
        auth_only: bool = False
    ):
        """Validate access using provided or instance headers
        
        Args:
            resource_id (str, optional): ID of the specific resource to check access for
            resource_type (str, optional): Type of resource to check (e.g., 'USER', 'TENANT')
            action (str, optional): Action to check permission for (e.g., 'READ', 'WRITE')
            authorization (str, optional): Authorization header override
            x_tenant (str, optional): x-tenant header override
            return_data (bool, optional): If True, returns the full validation response
            auth_only (bool, optional): If True, performs authentication-only validation without checking permissions
        
        Returns:
            bool or dict: If return_data is False, returns True if authorized, otherwise returns the full validation response
        
        Raises:
            AuthenticationError: If authentication fails
            AuthorizationError: If authorization fails
            ApiError: If API request fails
        """
        if not authorization and not self.authorization:
            raise AuthenticationError("Authorization header is required")
        if not x_tenant and not self.x_tenant:
            raise AuthenticationError("x-tenant header is required")

        headers = {
            'Content-Type': 'application/json',
            'Authorization': authorization or self.authorization,
            'x-tenant': x_tenant or self.x_tenant
        }
        
        # Prepare query parameters
        params = {}
        if auth_only:
            params['authOnly'] = 'true'
        else:
            # Only include resource/action params if not in auth_only mode
            if resource_id:
                params['resourceId'] = resource_id
            if resource_type:
                params['resource'] = resource_type.upper()  # API expects uppercase
            if action:
                params['action'] = action.upper()  # API expects uppercase

        try:
            response = requests.post(
                f'{self.auth_url}/validate',
                headers=headers,
                params=params  # Send as query parameters
            )
            
            response_data = response.json()
            
            if response.status_code == 400:
                raise AuthenticationError(response_data.get('message', 'Validation failed'))
                
            if response.status_code == 403:
                raise AuthorizationError(response_data.get('message', 'Access denied'))
                
            if response.status_code != 200:
                raise ApiError(f"API request failed: {response.text}")
                
            # Extract data from the ApiResponse wrapper
            if not response_data.get('success', False):
                raise AuthorizationError(response_data.get('message', 'Access denied'))
                
            validation_response = response_data.get('data', {})
            
            if return_data:
                return validation_response
            return validation_response.get('authorized', False)
            
        except requests.exceptions.RequestException as e:
            raise ApiError(f"Failed to connect to auth service: {str(e)}")

def requires_auth(
    resource_id: str = None,
    resource_type: str = None,
    action: str = None,
    include_auth_data: bool = False
):
    """Authorization decorator that uses request headers.
    
    Args:
        resource_id (str, optional): The ID of the resource to check access for
        resource_type (str, optional): The type of resource (e.g., 'USER', 'DOCUMENT')
        action (str, optional): The action being performed (e.g., 'READ', 'WRITE')
        include_auth_data (bool, optional): If True, injects auth_data into the decorated function
    
    The decorator automatically extracts the Authorization and x-tenant headers from the request.
    No manual token handling is required.
    
    Usage:
        @app.get("/api/resource")
        @requires_auth(resource_type="RESOURCE", action="READ")
        async def get_resource():
            return {"message": "Access granted"}
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(
            authorization: str = Header(...),  # Required header
            x_tenant: str = Header(...),      # Required header
            *args,
            **kwargs
        ):
            try:
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
                    kwargs['auth_data'] = auth_result
                else:
                    if not auth_result:
                        raise HTTPException(
                            status_code=403,
                            detail=f"Access denied to resource: {resource_id or resource_type}"
                        )
                
                return await func(*args, **kwargs)
                
            except AuthenticationError as e:
                raise HTTPException(status_code=401, detail=str(e))
            except AuthorizationError as e:
                raise HTTPException(status_code=403, detail=str(e))
            except ApiError as e:
                raise HTTPException(status_code=500, detail=str(e))
                
        return wrapper
    return decorator