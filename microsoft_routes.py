"""
Microsoft Outlook Calendar Routes

FastAPI routes for Microsoft Calendar integration.
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import RedirectResponse, JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from datetime import datetime, timedelta
import logging
import secrets

from dependencies import db, get_current_user
from microsoft_auth_service import MicrosoftAuthService
from microsoft_calendar_service import MicrosoftCalendarService

logger = logging.getLogger(__name__)

# Create router
microsoft_router = APIRouter(prefix="/microsoft")

# Initialize service
microsoft_auth = MicrosoftAuthService()

# In-memory state store for OAuth (use Redis in production)
oauth_states = {}

# ───────────────────────────────────────────────
# Authentication Routes
# ───────────────────────────────────────────────

@microsoft_router.get("/auth/login")
async def microsoft_login(request: Request):
    """
    Initiate Microsoft OAuth login flow.
    Redirects user to Microsoft Identity Platform.
    """
    try:
        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)
        oauth_states[state] = datetime.utcnow()
        
        # Get authorization URL
        auth_url = microsoft_auth.get_auth_url(state=state)
        
        return RedirectResponse(url=auth_url)
        
    except Exception as e:
        logger.error(f"Error initiating Microsoft login: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to initiate Microsoft login: {str(e)}")


@microsoft_router.get("/auth/callback")
async def microsoft_callback(request: Request):
    """
    Handle Microsoft OAuth callback.
    Exchange authorization code for tokens and save to database.
    """
    try:
        # Get query parameters
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        error = request.query_params.get("error")
        
        # Check for errors
        if error:
            error_description = request.query_params.get("error_description", error)
            logger.error(f"Microsoft OAuth error: {error} - {error_description}")
            raise HTTPException(status_code=400, detail=f"OAuth error: {error_description}")
        
        if not code:
            raise HTTPException(status_code=400, detail="Authorization code not provided")
        
        # Verify state
        if state not in oauth_states:
            raise HTTPException(status_code=400, detail="Invalid state parameter")
        
        # Exchange code for tokens
        token_data = microsoft_auth.handle_callback(code=code, state=state)
        
        # Store tokens in database
        user_data = token_data.get("user_data", {})
        user_email = user_data.get("email") or user_data.get("upn")
        
        if not user_email:
            raise HTTPException(status_code=400, detail="Could not retrieve user email")
        
        # Find user by email and update with Microsoft credentials
        user = await db.users.find_one({"email": user_email})
        
        if user:
            await db.users.update_one(
                {"email": user_email},
                {
                    "$set": {
                        "microsoft_refresh_token": token_data.get("refresh_token"),
                        "microsoft_access_token": token_data.get("access_token"),
                        "microsoft_token_expires": token_data.get("expires_at"),
                        "microsoft_calendar_connected": True,
                        "microsoft_connected_at": datetime.utcnow()
                    }
                }
            )
            logger.info(f"Linked Microsoft calendar to existing user: {user_email}")
        else:
            # Create new user (should not happen in normal flow, but handle it)
            logger.warning(f"Microsoft user not found: {user_email}")
        
        # Clean up state
        del oauth_states[state]
        
        # Return success response
        return JSONResponse({
            "status": "success",
            "message": "Microsoft Calendar connected successfully",
            "user": user_data
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error handling Microsoft callback: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to handle callback: {str(e)}")


@microsoft_router.get("/auth/disconnect")
async def microsoft_disconnect(current_user: dict = Depends(get_current_user)):
    """
    Disconnect Microsoft Calendar integration.
    Remove tokens from database.
    """
    try:
        user_id = str(current_user["_id"])
        
        await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$unset": {
                    "microsoft_refresh_token": "",
                    "microsoft_access_token": "",
                    "microsoft_token_expires": "",
                    "microsoft_calendar_connected": "",
                    "microsoft_connected_at": ""
                }
            }
        )
        
        logger.info(f"Disconnected Microsoft Calendar for user: {user_id}")
        
        return JSONResponse({
            "status": "success",
            "message": "Microsoft Calendar disconnected successfully"
        })
        
    except Exception as e:
        logger.error(f"Error disconnecting Microsoft Calendar: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to disconnect: {str(e)}")


# ───────────────────────────────────────────────
# Calendar Routes
# ───────────────────────────────────────────────

@microsoft_router.get("/calendar/events")
async def get_microsoft_events(current_user: dict = Depends(get_current_user)):
    """
    Fetch Microsoft Outlook calendar events.
    Returns events in unified format.
    """
    try:
        user_id = str(current_user["_id"])
        
        # Check if Microsoft is connected
        if not current_user.get("microsoft_calendar_connected"):
            raise HTTPException(status_code=400, detail="Microsoft Calendar not connected")
        
        # Get access token
        access_token = current_user.get("microsoft_access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="Microsoft access token not found")
        
        # Check if token is expired
        token_expires = current_user.get("microsoft_token_expires")
        if token_expires and datetime.utcnow() > token_expires:
            # Refresh token
            try:
                refresh_token = current_user.get("microsoft_refresh_token")
                if refresh_token:
                    new_token_data = microsoft_auth.refresh_token(refresh_token)
                    access_token = new_token_data.get("access_token")
                    
                    # Update token in database
                    await db.users.update_one(
                        {"_id": ObjectId(user_id)},
                        {
                            "$set": {
                                "microsoft_access_token": access_token,
                                "microsoft_token_expires": new_token_data.get("expires_at")
                            }
                        }
                    )
            except Exception as e:
                logger.error(f"Token refresh failed: {str(e)}")
                raise HTTPException(status_code=401, detail="Failed to refresh Microsoft token")
        
        # Initialize calendar service
        calendar_service = MicrosoftCalendarService(access_token)
        
        # Get events for next 30 days
        start_date = datetime.utcnow()
        end_date = datetime.utcnow() + timedelta(days=30)
        
        events = calendar_service.get_events(
            start_date=start_date,
            end_date=end_date,
            max_results=100
        )
        
        return JSONResponse({
            "status": "success",
            "events": events,
            "count": len(events)
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching Microsoft events: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch events: {str(e)}")


@microsoft_router.post("/calendar/events")
async def create_microsoft_event(event_data: dict, current_user: dict = Depends(get_current_user)):
    """
    Create a new event in Microsoft Outlook calendar.
    """
    try:
        user_id = str(current_user["_id"])
        
        # Check if Microsoft is connected
        if not current_user.get("microsoft_calendar_connected"):
            raise HTTPException(status_code=400, detail="Microsoft Calendar not connected")
        
        # Get access token
        access_token = current_user.get("microsoft_access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="Microsoft access token not found")
        
        # Initialize calendar service
        calendar_service = MicrosoftCalendarService(access_token)
        
        # Create event
        created_event = calendar_service.create_event(event_data)
        
        logger.info(f"Created Microsoft event: {created_event.get('title')}")
        
        return JSONResponse({
            "status": "success",
            "message": "Event created successfully",
            "event": created_event
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating Microsoft event: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create event: {str(e)}")


@microsoft_router.put("/calendar/events/{event_id}")
async def update_microsoft_event(event_id: str, event_data: dict, current_user: dict = Depends(get_current_user)):
    """
    Update an existing event in Microsoft Outlook calendar.
    """
    try:
        user_id = str(current_user["_id"])
        
        # Check if Microsoft is connected
        if not current_user.get("microsoft_calendar_connected"):
            raise HTTPException(status_code=400, detail="Microsoft Calendar not connected")
        
        # Get access token
        access_token = current_user.get("microsoft_access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="Microsoft access token not found")
        
        # Initialize calendar service
        calendar_service = MicrosoftCalendarService(access_token)
        
        # Update event
        updated_event = calendar_service.update_event(event_id, event_data)
        
        logger.info(f"Updated Microsoft event: {updated_event.get('title')}")
        
        return JSONResponse({
            "status": "success",
            "message": "Event updated successfully",
            "event": updated_event
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating Microsoft event: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to update event: {str(e)}")


@microsoft_router.delete("/calendar/events/{event_id}")
async def delete_microsoft_event(event_id: str, current_user: dict = Depends(get_current_user)):
    """
    Delete an event from Microsoft Outlook calendar.
    """
    try:
        user_id = str(current_user["_id"])
        
        # Check if Microsoft is connected
        if not current_user.get("microsoft_calendar_connected"):
            raise HTTPException(status_code=400, detail="Microsoft Calendar not connected")
        
        # Get access token
        access_token = current_user.get("microsoft_access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="Microsoft access token not found")
        
        # Initialize calendar service
        calendar_service = MicrosoftCalendarService(access_token)
        
        # Delete event
        success = calendar_service.delete_event(event_id)
        
        if success:
            logger.info(f"Deleted Microsoft event: {event_id}")
            return JSONResponse({
                "status": "success",
                "message": "Event deleted successfully"
            })
        else:
            raise HTTPException(status_code=500, detail="Failed to delete event")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting Microsoft event: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to delete event: {str(e)}")
