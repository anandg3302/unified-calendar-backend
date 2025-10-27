"""
Sign in with Apple Authentication Service

This module handles Sign in with Apple authentication flow, including:
- JWT token validation
- User identity verification
- Token management and refresh

Author: AI Assistant
Date: 2024
"""

import json
import base64
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, List
import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt as jose_jwt
import secrets
import string

logger = logging.getLogger(__name__)

class AppleAuthService:
    """
    Service class for Sign in with Apple authentication.
    
    This class handles:
    - Apple ID token validation
    - User identity verification
    - Token management
    - Secure credential storage
    """
    
    def __init__(self, team_id: str, client_id: str, key_id: str, private_key: str):
        """
        Initialize Apple Auth service.
        
        Args:
            team_id (str): Apple Developer Team ID
            client_id (str): App's bundle identifier
            key_id (str): Apple Sign in Key ID
            private_key (str): Apple Sign in Private Key (PEM format)
        """
        self.team_id = team_id
        self.client_id = client_id
        self.key_id = key_id
        self.private_key = private_key
        self.apple_public_keys_url = "https://appleid.apple.com/auth/keys"
        self.apple_token_url = "https://appleid.apple.com/auth/token"
        
    async def validate_apple_token(self, identity_token: str) -> Optional[Dict[str, Any]]:
        """
        Validate Apple ID token and extract user information.
        
        Args:
            identity_token (str): Apple ID token from client
            
        Returns:
            Optional[Dict]: User information if valid, None otherwise
        """
        try:
            # Get Apple's public keys
            public_keys = await self._get_apple_public_keys()
            
            # Decode token header to get key ID
            header = jwt.get_unverified_header(identity_token)
            key_id = header.get('kid')
            
            if not key_id:
                logger.error("No key ID found in Apple token header")
                return None
            
            # Find the correct public key
            public_key = None
            for key in public_keys:
                if key['kid'] == key_id:
                    public_key = self._construct_public_key(key)
                    break
            
            if not public_key:
                logger.error(f"Public key not found for key ID: {key_id}")
                return None
            
            # Verify and decode the token
            try:
                payload = jwt.decode(
                    identity_token,
                    public_key,
                    algorithms=['RS256'],
                    audience=self.client_id,
                    issuer='https://appleid.apple.com'
                )
                
                # Extract user information
                user_info = {
                    'apple_user_id': payload.get('sub'),
                    'email': payload.get('email'),
                    'email_verified': payload.get('email_verified', False),
                    'name': payload.get('name', {}),
                    'auth_time': payload.get('auth_time'),
                    'expires_at': datetime.fromtimestamp(payload.get('exp', 0)),
                    'issued_at': datetime.fromtimestamp(payload.get('iat', 0))
                }
                
                logger.info(f"Successfully validated Apple token for user: {user_info['apple_user_id']}")
                return user_info
                
            except jwt.ExpiredSignatureError:
                logger.error("Apple token has expired")
                return None
            except jwt.InvalidTokenError as e:
                logger.error(f"Invalid Apple token: {str(e)}")
                return None
                
        except Exception as e:
            logger.error(f"Error validating Apple token: {str(e)}")
            return None
    
    async def create_app_specific_password(self, apple_id: str, password: str) -> Optional[str]:
        """
        Create an app-specific password for CalDAV access.
        
        Note: This is a placeholder implementation. In practice, users need to
        create app-specific passwords manually in their Apple ID settings.
        
        Args:
            apple_id (str): User's Apple ID
            password (str): User's Apple ID password
            
        Returns:
            Optional[str]: App-specific password if successful
        """
        try:
            # In a real implementation, this would require:
            # 1. User authentication with Apple ID
            # 2. Two-factor authentication
            # 3. App-specific password generation
            
            # For now, we'll return a placeholder
            # Users should create app-specific passwords manually
            logger.warning("App-specific password creation requires manual setup by user")
            return None
            
        except Exception as e:
            logger.error(f"Error creating app-specific password: {str(e)}")
            return None
    
    async def refresh_user_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """
        Refresh user's Apple authentication token.
        
        Args:
            refresh_token (str): Apple refresh token
            
        Returns:
            Optional[Dict]: New token information
        """
        try:
            # Create client secret for token refresh
            client_secret = self._create_client_secret()
            
            # Prepare token refresh request
            data = {
                'client_id': self.client_id,
                'client_secret': client_secret,
                'refresh_token': refresh_token,
                'grant_type': 'refresh_token'
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.apple_token_url,
                    data=data,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                )
                
                if response.status_code == 200:
                    token_data = response.json()
                    
                    # Validate the new identity token
                    user_info = await self.validate_apple_token(token_data.get('id_token'))
                    
                    if user_info:
                        return {
                            'access_token': token_data.get('access_token'),
                            'refresh_token': token_data.get('refresh_token'),
                            'id_token': token_data.get('id_token'),
                            'expires_in': token_data.get('expires_in'),
                            'user_info': user_info
                        }
                
                logger.error(f"Token refresh failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error refreshing Apple token: {str(e)}")
            return None
    
    async def _get_apple_public_keys(self) -> List[Dict[str, Any]]:
        """
        Fetch Apple's public keys for token validation.
        
        Returns:
            List[Dict]: Apple's public keys
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.apple_public_keys_url)
                
                if response.status_code == 200:
                    keys_data = response.json()
                    return keys_data.get('keys', [])
                else:
                    logger.error(f"Failed to fetch Apple public keys: {response.status_code}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error fetching Apple public keys: {str(e)}")
            return []
    
    def _construct_public_key(self, key_data: Dict[str, Any]) -> str:
        """
        Construct RSA public key from Apple's key data.
        
        Args:
            key_data (Dict): Apple's key information
            
        Returns:
            str: PEM formatted public key
        """
        try:
            # Extract key components
            n = base64.urlsafe_b64decode(key_data['n'] + '==')
            e = base64.urlsafe_b64decode(key_data['e'] + '==')
            
            # Convert to integers
            n_int = int.from_bytes(n, 'big')
            e_int = int.from_bytes(e, 'big')
            
            # Create RSA public key
            public_key = rsa.RSAPublicNumbers(e_int, n_int).public_key()
            
            # Serialize to PEM format
            pem_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return pem_key.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Error constructing public key: {str(e)}")
            raise
    
    def _create_client_secret(self) -> str:
        """
        Create client secret for Apple authentication.
        
        Returns:
            str: JWT client secret
        """
        try:
            # Create JWT header
            header = {
                'kid': self.key_id,
                'alg': 'ES256'
            }
            
            # Create JWT payload
            now = datetime.utcnow()
            payload = {
                'iss': self.team_id,
                'iat': int(now.timestamp()),
                'exp': int((now + timedelta(minutes=10)).timestamp()),
                'aud': 'https://appleid.apple.com',
                'sub': self.client_id
            }
            
            # Sign the JWT
            client_secret = jwt.encode(
                payload,
                self.private_key,
                algorithm='ES256',
                headers=header
            )
            
            return client_secret
            
        except Exception as e:
            logger.error(f"Error creating client secret: {str(e)}")
            raise
    
    def generate_app_specific_password_instructions(self) -> Dict[str, str]:
        """
        Generate instructions for users to create app-specific passwords.
        
        Returns:
            Dict[str, str]: Instructions for creating app-specific passwords
        """
        return {
            'title': 'Create App-Specific Password for Apple Calendar',
            'instructions': [
                '1. Go to appleid.apple.com and sign in with your Apple ID',
                '2. In the "Security" section, click "Generate Password" under "App-Specific Passwords"',
                '3. Enter a label for this password (e.g., "Calendar App")',
                '4. Click "Create" and copy the generated password',
                '5. Use this password in the app instead of your regular Apple ID password',
                '6. Keep this password secure and do not share it'
            ],
            'note': 'App-specific passwords are required for CalDAV access to iCloud Calendar'
        }
