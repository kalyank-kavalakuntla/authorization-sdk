from fastapi import FastAPI, Header, Depends, HTTPException
from typing import Optional
import os
from functools import wraps
import requests

class AuthClient:
    def __init__(self, authorization: str = None, x_tenant: str = None):
        """Initialize AuthClient with optional headers."""
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
        return_data: bool = False
    ):
        """Validate access using provided or instance headers"""
        headers = {
            'Content-Type': 'application/json',
            'Authorization': authorization or self.authorization,
        }
        
        if x_tenant or self.x_tenant:
            headers['x-tenant'] = x_tenant or self.x_tenant
        
        params = {}
        if resource_id:
            params['resourceId'] = resource_id
        if resource_type:
            params['resourceType'] = resource_type
        if action:
            params['action'] = action

        try:
            response = requests.get(
                f'{self.auth_url}/validate',
                headers=headers,
                params=params
            )
            
            if response.status_code == 401:
                raise AuthenticationError("Invalid or expired token")
            
            if response.status_code == 403:
                raise AuthorizationError(f"Access denied to resource: {resource_id}")
            
            if response.status_code != 200:
                raise ApiError(f"API request failed: {response.text}")
            
            data = response.json()
            return data if return_data else data.get('authorized', False)
            
        except requests.exceptions.RequestException as e:
            raise ApiError(f"Failed to connect to auth service: {str(e)}")

def requires_auth(
    resource_id: str = None,
    resource_type: str = None,
    action: str = None,
    include_auth_data: bool = False
):
    """Authorization decorator that uses request headers"""
    def decorator(func):
        @wraps(func)
        async def wrapper(
            authorization: str = Header(...),
            x_tenant: str = Header(None),
            *args,
            **kwargs
        ):
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
                        detail=f"Access denied to resource: {resource_id}"
                    )
                kwargs['auth_data'] = auth_result
            else:
                if not auth_result:
                    raise HTTPException(
                        status_code=403,
                        detail=f"Access denied to resource: {resource_id}"
                    )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator

# Example usage:
app = FastAPI()

@app.get("/users/{user_id}")
@requires_auth(
    resource_id="user-123",
    resource_type="USER",
    action="READ",
    include_auth_data=True
)
async def get_user(
    user_id: str,
    auth_data: dict = None
):
    return {
        "user_id": user_id,
        "authorized_by": auth_data['user']['name'],
        "tenant": auth_data['tenant']['name']
    }

# Direct client usage
@app.post("/documents")
async def create_document(
    document: dict,
    authorization: str = Header(...),
    x_tenant: str = Header(None)
):
    client = AuthClient(authorization=authorization, x_tenant=x_tenant)
    auth_result = client.validate_access(
        resource_type="DOCUMENT",
        action="CREATE",
        return_data=True
    )
    
    if not auth_result['authorized']:
        raise HTTPException(status_code=403, detail="Permission denied")
    
    return {
        "message": "Document created",
        "user": auth_result['user']['name'],
        "tenant": auth_result['tenant']['name']
    }