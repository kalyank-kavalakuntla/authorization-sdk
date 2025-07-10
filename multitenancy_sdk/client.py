"""Client module for interacting with the authorization service."""

import requests
from .config import get_config
from .exceptions import (
    AuthenticationError,
    AuthorizationError,
    ApiError
)

class AuthClient:
    """Client for making authorization requests."""
    
    def __init__(self):
        self.config = get_config()
    
    def validate_access(self, resource_id=None, resource_type=None, action=None, return_data=False):
        """Validate access to a resource.
        
        Args:
            resource_id (str, optional): ID of the resource to validate access for
            resource_type (str, optional): Type of the resource (e.g., 'TENANT', 'USER', etc.)
            action (str, optional): Action to validate (e.g., 'READ', 'WRITE', 'DELETE')
            return_data (bool, optional): If True, returns full response data
        
        Returns:
            Union[bool, dict]: If return_data is False, returns bool indicating access.
                             If return_data is True, returns full response dict containing:
                             - authorized (bool): Whether access is granted
                             - user (dict): User details
                             - tenant (dict): Tenant details
                             - resources (list): Available resources
                             - message (str): Response message
        
        Raises:
            AuthenticationError: If JWT token is invalid
            AuthorizationError: If access is denied
            ApiError: If API request fails
        """
        headers = {
            'Authorization': f'Bearer {self.config.jwt_token}',
            'Content-Type': 'application/json'
        }
        
        if self.config.x_tenant:
            headers['x-tenant'] = str(self.config.x_tenant)
        
        params = {}
        if resource_id:
            params['resourceId'] = resource_id
        if resource_type:
            params['resourceType'] = resource_type
        if action:
            params['action'] = action
        
        try:
            response = requests.get(
                f'{self.config.auth_url}/validate',
                headers=headers,
                params=params
            )
            
            if response.status_code == 401:
                raise AuthenticationError("Invalid or expired JWT token")
            
            if response.status_code == 403:
                raise AuthorizationError(f"Access denied to resource: {resource_id}")
            
            if response.status_code != 200:
                raise ApiError(f"API request failed: {response.text}")
            
            data = response.json()
            
            # Return full response data if requested
            if return_data:
                return data
            
            return data.get('authorized', False)
            
        except requests.exceptions.RequestException as e:
            raise ApiError(f"Failed to connect to auth service: {str(e)}")
    
    def get_user_resources(self):
        """Get all resources accessible to the current user.
        
        Returns:
            dict: JSON response containing user's resources
        
        Raises:
            AuthenticationError: If JWT token is invalid
            ApiError: If API request fails
        """
        headers = {
            'Authorization': f'Bearer {self.config.jwt_token}',
            'Content-Type': 'application/json'
        }
        
        if self.config.tenant_id:
            headers['x-tenant'] = str(self.config.tenant_id)
        
        try:
            response = requests.get(
                f'{self.config.auth_url}/resources',
                headers=headers
            )
            
            if response.status_code == 401:
                raise AuthenticationError("Invalid or expired JWT token")
            
            if response.status_code != 200:
                raise ApiError(f"API request failed: {response.text}")
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            raise ApiError(f"Failed to connect to auth service: {str(e)}")
