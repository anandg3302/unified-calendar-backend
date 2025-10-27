"""
Microsoft Identity Platform Authentication Service

This module handles Microsoft OAuth 2.0 authentication flow for Outlook Calendar integration.
Uses msal library for secure token management.
"""

import os
import logging
from typing import Dict, Optional, Any
from datetime import datetime, timedelta
import msal
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

class MicrosoftAuthService:
    """
    Service class for Microsoft Identity Platform authentication.
    
    This class handles:
    - Microsoft OAuth 2.0 authentication
    - Token management and refresh
    - Secure credential storage
    """
    
    # Microsoft Identity Platform endpoints
    AUTHORITY = "https://login.microsoftonline.com/common"
    
    # Required scopes for calendar access
    SCOPES = [
        "User.Read",
        "Calendars.Read",
        "Calendars.ReadWrite",
        "offline_access"
    ]
    
    def __init__(self):
        """
        Initialize Microsoft Auth service with client credentials.
        """
        self.client_id = os.getenv("MICROSOFT_CLIENT_ID")
        self.client_secret = os.getenv("MICROSOFT_CLIENT_SECRET")
        self.tenant_id = os.getenv("MICROSOFT_TENANT_ID")
        self.redirect_uri = os.getenv("MICROSOFT_REDIRECT_URI")
        
        if not all([self.client_id, self.client_secret]):
            logger.warning("Microsoft credentials not configured in environment")
    
    def get_auth_url(self, state: str = None) -> str:
        """
        Generate Microsoft OAuth authorization URL.
        
        Args:
            state (str): Optional state parameter for CSRF protection
            
        Returns:
            str: Authorization URL
        """
        try:
            app = msal.ConfidentialClientApplication(
                self.client_id,
                authority=self.AUTHORITY,
                client_credential=self.client_secret
            )
            
            # Generate authorization URL
            auth_url = app.get_authorization_request_url(
                scopes=self.SCOPES,
                state=state,
                redirect_uri=self.redirect_uri
            )
            
            logger.info(f"Generated Microsoft auth URL with state: {state}")
            return auth_url
            
        except Exception as e:
            logger.error(f"Error generating Microsoft auth URL: {str(e)}")
            raise
    
    def handle_callback(self, code: str, state: str = None) -> Dict[str, Any]:
        """
        Handle OAuth callback and exchange authorization code for tokens.
        
        Args:
            code (str): Authorization code from Microsoft
            state (str): State parameter for CSRF verification
            
        Returns:
            Dict: Token information and user data
        """
        try:
            app = msal.ConfidentialClientApplication(
                self.client_id,
                authority=self.AUTHORITY,
                client_credential=self.client_secret
            )
            
            # Exchange authorization code for tokens
            result = app.acquire_token_by_authorization_code(
                code,
                scopes=self.SCOPES,
                redirect_uri=self.redirect_uri
            )
            
            if "error" in result:
                logger.error(f"Token acquisition failed: {result.get('error_description')}")
                raise Exception(f"Failed to acquire tokens: {result.get('error_description')}")
            
            # Extract token information
            token_data = {
                "access_token": result.get("access_token"),
                "refresh_token": result.get("refresh_token"),
                "expires_at": datetime.utcnow() + timedelta(seconds=result.get("expires_in", 3600)),
                "scope": result.get("scope", " ".join(self.SCOPES)),
                "user_data": {
                    "id": result.get("id_token_claims", {}).get("oid"),
                    "name": result.get("id_token_claims", {}).get("name"),
                    "email": result.get("id_token_claims", {}).get("email"),
                    "upn": result.get("id_token_claims", {}).get("upn")
                }
            }
            
            logger.info(f"Successfully acquired Microsoft tokens for user: {token_data['user_data'].get('email')}")
            return token_data
            
        except Exception as e:
            logger.error(f"Error handling Microsoft callback: {str(e)}")
            raise
    
    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh Microsoft access token using refresh token.
        
        Args:
            refresh_token (str): Microsoft refresh token
            
        Returns:
            Dict: New token information
        """
        try:
            app = msal.ConfidentialClientApplication(
                self.client_id,
                authority=self.AUTHORITY,
                client_credential=self.client_secret
            )
            
            # Refresh the token
            result = app.acquire_token_by_refresh_token(
                refresh_token,
                scopes=self.SCOPES
            )
            
            if "error" in result:
                logger.error(f"Token refresh failed: {result.get('error_description')}")
                raise Exception(f"Failed to refresh token: {result.get('error_description')}")
            
            # Return new token data
            token_data = {
                "access_token": result.get("access_token"),
                "refresh_token": result.get("refresh_token") or refresh_token,  # Keep old if not provided
                "expires_at": datetime.utcnow() + timedelta(seconds=result.get("expires_in", 3600))
            }
            
            logger.info("Successfully refreshed Microsoft token")
            return token_data
            
        except Exception as e:
            logger.error(f"Error refreshing Microsoft token: {str(e)}")
            raise
    
    def validate_token(self, access_token: str) -> bool:
        """
        Validate Microsoft access token.
        
        Args:
            access_token (str): Microsoft access token
            
        Returns:
            bool: True if token is valid
        """
        try:
            # Basic validation - check if token exists and is not empty
            return bool(access_token and len(access_token) > 0)
            
        except Exception as e:
            logger.error(f"Error validating Microsoft token: {str(e)}")
            return False
