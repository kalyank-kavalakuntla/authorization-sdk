# Multitenancy SDK

Python SDK for interacting with the Multitenancy Authorization Service.

## Installation

```bash
pip install multitenancy-sdk
```

## Usage

```python
from multitenancy_sdk import requires_auth

# Configure the SDK
from multitenancy_sdk import config
config.init(
    auth_url="http://localhost:8080/api/v1/auth",
    jwt_token="your-jwt-token",
    x_tenant="your-tenant-header"  # Optional: for multi-tenant requests
)

# Use as a decorator
@requires_auth(resource_id="resource123")
def protected_function():
    # This function will only execute if authorization is successful
    pass

# Or use directly
from multitenancy_sdk import AuthClient
client = AuthClient()
is_authorized = client.validate_access("resource123")
```

## Features

- JWT-based authentication
- Resource-based authorization
- Easy-to-use decorator syntax
- Configurable client settings
- Automatic token validation

## Error Handling

The SDK provides custom exceptions for different error scenarios:

- `AuthenticationError`: JWT token is invalid or expired
- `AuthorizationError`: User doesn't have access to the resource
- `ConfigurationError`: SDK is not properly configured
- `ApiError`: API request failed
