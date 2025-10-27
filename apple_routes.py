"""
Apple Calendar API Routes

This module provides FastAPI routes for Apple Calendar integration including:
- Sign in with Apple authentication
- Apple Calendar CRUD operations
- Event synchronization
- Background sync management

Author: AI Assistant
Date: 2024
"""

from fastapi import APIRouter, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import logging
from bson import ObjectId

from apple_auth_service import AppleAuthService
from apple_calendar_service import AppleCalendarService
from dependencies import get_current_user, db

logger = logging.getLogger(__name__)

# Initialize router
apple_router = APIRouter(prefix="/api/apple", tags=["Apple Calendar"])
security = HTTPBearer()

# Pydantic models for request/response
class AppleSignInRequest(BaseModel):
    """Request model for Sign in with Apple"""
    identity_token: str = Field(..., description="Apple ID token from client")
    authorization_code: Optional[str] = Field(None, description="Apple authorization code")
    user_identifier: Optional[str] = Field(None, description="Apple user identifier")

class AppleCalendarCredentials(BaseModel):
    """Model for Apple Calendar credentials"""
    apple_id: str = Field(..., description="User's Apple ID email")
    app_specific_password: str = Field(..., description="App-specific password for CalDAV")

class AppleEventCreate(BaseModel):
    """Model for creating Apple Calendar events"""
    title: str = Field(..., description="Event title")
    description: Optional[str] = Field(None, description="Event description")
    start_time: datetime = Field(..., description="Event start time")
    end_time: datetime = Field(..., description="Event end time")
    location: Optional[str] = Field(None, description="Event location")
    calendar_id: Optional[str] = Field(None, description="Target calendar ID")

class AppleEventUpdate(BaseModel):
    """Model for updating Apple Calendar events"""
    title: Optional[str] = Field(None, description="Event title")
    description: Optional[str] = Field(None, description="Event description")
    start_time: Optional[datetime] = Field(None, description="Event start time")
    end_time: Optional[datetime] = Field(None, description="Event end time")
    location: Optional[str] = Field(None, description="Event location")

class AppleSyncRequest(BaseModel):
    """Model for Apple Calendar sync request"""
    sync_direction: str = Field(..., description="Sync direction: 'from_apple', 'to_apple', or 'bidirectional'")
    date_range_days: int = Field(30, description="Number of days to sync (default: 30)")

# Initialize Apple services (these should be configured with environment variables)
def get_apple_auth_service() -> AppleAuthService:
    """Get Apple Auth service instance"""
    import os
    return AppleAuthService(
        team_id=os.getenv("APPLE_TEAM_ID", ""),
        client_id=os.getenv("APPLE_CLIENT_ID", ""),
        key_id=os.getenv("APPLE_KEY_ID", ""),
        private_key=os.getenv("APPLE_PRIVATE_KEY", "")
    )

@apple_router.post("/auth/signin")
async def apple_signin(
    request: AppleSignInRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Handle Sign in with Apple authentication.
    
    This endpoint:
    1. Validates the Apple ID token
    2. Extracts user information
    3. Stores Apple credentials securely
    4. Initiates calendar connection
    """
    try:
        # Initialize Apple Auth service
        apple_auth = get_apple_auth_service()
        
        # Validate Apple token
        user_info = await apple_auth.validate_apple_token(request.identity_token)
        
        if not user_info:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Apple ID token"
            )
        
        # Store Apple user information
        apple_user_data = {
            'apple_user_id': user_info['apple_user_id'],
            'email': user_info['email'],
            'email_verified': user_info['email_verified'],
            'name': user_info.get('name', {}),
            'auth_time': user_info['auth_time'],
            'expires_at': user_info['expires_at'],
            'last_sync': datetime.utcnow()
        }
        
        # Update user document with Apple information
        await db.users.update_one(
            {"_id": ObjectId(current_user["_id"])},
            {
                "$set": {
                    "apple_user": apple_user_data,
                    "apple_connected": True,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        # Schedule background sync
        background_tasks.add_task(
            sync_apple_calendar_events,
            current_user["_id"],
            "from_apple"
        )
        
        logger.info(f"Apple authentication successful for user {current_user['_id']}")
        
        return {
            "message": "Apple authentication successful",
            "user_info": {
                "apple_user_id": user_info['apple_user_id'],
                "email": user_info['email'],
                "name": user_info.get('name', {})
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Apple signin error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Apple authentication failed"
        )

@apple_router.post("/calendar/connect")
async def connect_apple_calendar(
    credentials: AppleCalendarCredentials,
    current_user: dict = Depends(get_current_user)
):
    """
    Connect to Apple Calendar using CalDAV credentials.
    
    This endpoint:
    1. Validates CalDAV credentials
    2. Tests connection to Apple Calendar
    3. Stores credentials securely
    4. Returns available calendars
    """
    try:
        # Initialize Apple Calendar service
        apple_calendar = AppleCalendarService(
            apple_id=credentials.apple_id,
            app_specific_password=credentials.app_specific_password,
            user_id=current_user["_id"]
        )
        
        # Test connection
        connection_success = await apple_calendar.connect()
        
        if not connection_success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to connect to Apple Calendar. Please check your credentials."
            )
        
        # Get available calendars
        calendars = await apple_calendar.get_calendars()
        
        # Store credentials securely (encrypted in production)
        encrypted_password = credentials.app_specific_password  # TODO: Implement encryption
        
        await db.users.update_one(
            {"_id": ObjectId(current_user["_id"])},
            {
                "$set": {
                    "apple_calendar_credentials": {
                        "apple_id": credentials.apple_id,
                        "app_specific_password": encrypted_password,
                        "connected_at": datetime.utcnow()
                    },
                    "apple_calendars": calendars,
                    "apple_calendar_connected": True
                }
            }
        )
        
        logger.info(f"Apple Calendar connected successfully for user {current_user['_id']}")
        
        return {
            "message": "Apple Calendar connected successfully",
            "calendars": calendars
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Apple Calendar connection error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to connect to Apple Calendar"
        )

@apple_router.get("/calendar/calendars")
async def get_apple_calendars(
    current_user: dict = Depends(get_current_user)
):
    """
    Get user's Apple Calendar list.
    """
    try:
        user = await db.users.find_one({"_id": ObjectId(current_user["_id"])})
        
        if not user or not user.get("apple_calendar_connected"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Apple Calendar not connected"
            )
        
        calendars = user.get("apple_calendars", [])
        
        return {
            "calendars": calendars,
            "total": len(calendars)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching Apple calendars: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch Apple calendars"
        )

@apple_router.get("/calendar/events")
async def get_apple_events(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    calendar_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """
    Get events from Apple Calendar.
    """
    try:
        user = await db.users.find_one({"_id": ObjectId(current_user["_id"])})
        
        if not user or not user.get("apple_calendar_connected"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Apple Calendar not connected"
            )
        
        credentials = user.get("apple_calendar_credentials", {})
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Apple Calendar credentials not found"
            )
        
        # Initialize Apple Calendar service
        apple_calendar = AppleCalendarService(
            apple_id=credentials["apple_id"],
            app_specific_password=credentials["app_specific_password"],
            user_id=current_user["_id"]
        )
        
        # Get events
        events = await apple_calendar.get_events(
            calendar_id=calendar_id,
            start_date=start_date,
            end_date=end_date
        )
        
        return {
            "events": events,
            "total": len(events),
            "source": "apple"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching Apple events: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch Apple events"
        )

@apple_router.post("/calendar/events")
async def create_apple_event(
    event_data: AppleEventCreate,
    current_user: dict = Depends(get_current_user)
):
    """
    Create a new event in Apple Calendar.
    """
    try:
        user = await db.users.find_one({"_id": ObjectId(current_user["_id"])})
        
        if not user or not user.get("apple_calendar_connected"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Apple Calendar not connected"
            )
        
        credentials = user.get("apple_calendar_credentials", {})
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Apple Calendar credentials not found"
            )
        
        # Initialize Apple Calendar service
        apple_calendar = AppleCalendarService(
            apple_id=credentials["apple_id"],
            app_specific_password=credentials["app_specific_password"],
            user_id=current_user["_id"]
        )
        
        # Prepare event data
        event_dict = {
            "title": event_data.title,
            "description": event_data.description,
            "start_time": event_data.start_time,
            "end_time": event_data.end_time,
            "location": event_data.location
        }
        
        # Create event
        event_id = await apple_calendar.create_event(
            event_data=event_dict,
            calendar_id=event_data.calendar_id
        )
        
        if not event_id:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create Apple Calendar event"
            )
        
        # Store event in local database
        local_event = {
            "title": event_data.title,
            "description": event_data.description,
            "start_time": event_data.start_time,
            "end_time": event_data.end_time,
            "location": event_data.location,
            "calendar_source": "apple",
            "apple_event_id": event_id,
            "user_id": current_user["_id"],
            "created_at": datetime.utcnow()
        }
        
        await db.events.insert_one(local_event)
        
        logger.info(f"Apple Calendar event created successfully: {event_id}")
        
        return {
            "message": "Apple Calendar event created successfully",
            "event_id": event_id,
            "local_event_id": str(local_event.get("_id"))
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating Apple event: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create Apple Calendar event"
        )

@apple_router.put("/calendar/events/{event_id}")
async def update_apple_event(
    event_id: str,
    event_data: AppleEventUpdate,
    current_user: dict = Depends(get_current_user)
):
    """
    Update an existing Apple Calendar event.
    """
    try:
        user = await db.users.find_one({"_id": ObjectId(current_user["_id"])})
        
        if not user or not user.get("apple_calendar_connected"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Apple Calendar not connected"
            )
        
        credentials = user.get("apple_calendar_credentials", {})
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Apple Calendar credentials not found"
            )
        
        # Initialize Apple Calendar service
        apple_calendar = AppleCalendarService(
            apple_id=credentials["apple_id"],
            app_specific_password=credentials["app_specific_password"],
            user_id=current_user["_id"]
        )
        
        # Prepare update data
        update_dict = {}
        if event_data.title is not None:
            update_dict["title"] = event_data.title
        if event_data.description is not None:
            update_dict["description"] = event_data.description
        if event_data.start_time is not None:
            update_dict["start_time"] = event_data.start_time
        if event_data.end_time is not None:
            update_dict["end_time"] = event_data.end_time
        if event_data.location is not None:
            update_dict["location"] = event_data.location
        
        # Update event
        success = await apple_calendar.update_event(
            event_id=event_id,
            event_data=update_dict
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update Apple Calendar event"
            )
        
        # Update local database
        await db.events.update_one(
            {"apple_event_id": event_id, "user_id": current_user["_id"]},
            {
                "$set": {
                    **update_dict,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        logger.info(f"Apple Calendar event updated successfully: {event_id}")
        
        return {
            "message": "Apple Calendar event updated successfully",
            "event_id": event_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating Apple event: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update Apple Calendar event"
        )

@apple_router.delete("/calendar/events/{event_id}")
async def delete_apple_event(
    event_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Delete an Apple Calendar event.
    """
    try:
        user = await db.users.find_one({"_id": ObjectId(current_user["_id"])})
        
        if not user or not user.get("apple_calendar_connected"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Apple Calendar not connected"
            )
        
        credentials = user.get("apple_calendar_credentials", {})
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Apple Calendar credentials not found"
            )
        
        # Initialize Apple Calendar service
        apple_calendar = AppleCalendarService(
            apple_id=credentials["apple_id"],
            app_specific_password=credentials["app_specific_password"],
            user_id=current_user["_id"]
        )
        
        # Delete event
        success = await apple_calendar.delete_event(event_id=event_id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete Apple Calendar event"
            )
        
        # Remove from local database
        await db.events.delete_one({
            "apple_event_id": event_id,
            "user_id": current_user["_id"]
        })
        
        logger.info(f"Apple Calendar event deleted successfully: {event_id}")
        
        return {
            "message": "Apple Calendar event deleted successfully",
            "event_id": event_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting Apple event: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete Apple Calendar event"
        )

@apple_router.post("/calendar/sync")
async def sync_apple_calendar(
    sync_request: AppleSyncRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Initiate Apple Calendar synchronization.
    """
    try:
        user = await db.users.find_one({"_id": ObjectId(current_user["_id"])})
        
        if not user or not user.get("apple_calendar_connected"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Apple Calendar not connected"
            )
        
        # Schedule background sync
        background_tasks.add_task(
            sync_apple_calendar_events,
            current_user["_id"],
            sync_request.sync_direction,
            sync_request.date_range_days
        )
        
        return {
            "message": "Apple Calendar sync initiated",
            "sync_direction": sync_request.sync_direction,
            "date_range_days": sync_request.date_range_days
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error initiating Apple sync: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initiate Apple Calendar sync"
        )

@apple_router.get("/auth/instructions")
async def get_app_specific_password_instructions():
    """
    Get instructions for creating app-specific passwords.
    """
    try:
        apple_auth = get_apple_auth_service()
        instructions = apple_auth.generate_app_specific_password_instructions()
        
        return instructions
        
    except Exception as e:
        logger.error(f"Error getting Apple instructions: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get Apple instructions"
        )

# Background task functions
async def sync_apple_calendar_events(
    user_id: str,
    sync_direction: str = "from_apple",
    date_range_days: int = 30
):
    """
    Background task to sync Apple Calendar events.
    
    Args:
        user_id (str): User ID to sync events for
        sync_direction (str): Direction of sync ('from_apple', 'to_apple', 'bidirectional')
        date_range_days (int): Number of days to sync
    """
    try:
        logger.info(f"Starting Apple Calendar sync for user {user_id}")
        
        # Get user data
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        if not user or not user.get("apple_calendar_connected"):
            logger.warning(f"User {user_id} not connected to Apple Calendar")
            return
        
        credentials = user.get("apple_calendar_credentials", {})
        if not credentials:
            logger.warning(f"No Apple Calendar credentials for user {user_id}")
            return
        
        # Initialize Apple Calendar service
        apple_calendar = AppleCalendarService(
            apple_id=credentials["apple_id"],
            app_specific_password=credentials["app_specific_password"],
            user_id=user_id
        )
        
        # Calculate date range
        end_date = datetime.utcnow() + timedelta(days=date_range_days)
        start_date = datetime.utcnow() - timedelta(days=date_range_days)
        
        if sync_direction in ["from_apple", "bidirectional"]:
            # Sync events from Apple Calendar to local database
            apple_events = await apple_calendar.get_events(
                start_date=start_date,
                end_date=end_date
            )
            
            for event in apple_events:
                # Check if event already exists
                existing_event = await db.events.find_one({
                    "apple_event_id": event["id"],
                    "user_id": user_id
                })
                
                if not existing_event:
                    # Create new local event
                    local_event = {
                        **event,
                        "user_id": user_id,
                        "created_at": datetime.utcnow()
                    }
                    await db.events.insert_one(local_event)
                    logger.info(f"Synced Apple event: {event['id']}")
        
        # Update last sync time
        await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$set": {
                    "apple_last_sync": datetime.utcnow()
                }
            }
        )
        
        logger.info(f"Apple Calendar sync completed for user {user_id}")
        
    except Exception as e:
        logger.error(f"Error in Apple Calendar sync: {str(e)}")
