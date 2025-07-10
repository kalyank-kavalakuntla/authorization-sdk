"""Configuration module for the Multitenancy SDK."""

class Config:
    """Configuration class for storing SDK settings."""
    
    def __init__(self):
        self._auth_url = None
        self._jwt_token = None
        self._x_tenant = None
    
    @property
    def auth_url(self):
        """Get the authorization service URL."""
        if not self._auth_url:
            raise ConfigurationError("Auth URL not configured. Call config.init() first.")
        return self._auth_url
    
    @property
    def jwt_token(self):
        """Get the JWT token."""
        if not self._jwt_token:
            raise ConfigurationError("JWT token not configured. Call config.init() first.")
        return self._jwt_token
    
    @property
    def x_tenant(self):
        """Get the x-tenant header value."""
        return self._x_tenant

    def init(self, auth_url, jwt_token, x_tenant=None):
        """Initialize the SDK configuration.
        
        Args:
            auth_url (str): Base URL of the authorization service
            jwt_token (str): JWT token for authentication
            x_tenant (str, optional): Value for x-tenant header
        """
        self._auth_url = auth_url.rstrip('/')
        self._jwt_token = jwt_token
        self._x_tenant = x_tenant

class ConfigurationError(Exception):
    """Raised when the SDK is not properly configured."""
    pass

# Global configuration instance
_config = Config()

# Module-level interface
def init(auth_url, jwt_token, tenant_id=None):
    """Initialize the SDK configuration."""
    _config.init(auth_url, jwt_token, tenant_id)

def get_config():
    """Get the current configuration."""
    return _config
