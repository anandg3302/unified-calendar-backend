# Import multiprocessing setup first (must be before any MongoDB imports)
import multiprocessing_setup

import sys
import os

from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
from bson import ObjectId
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import logging

# ───────────────────────────────────────────────
# Load environment
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

# ───────────────────────────────────────────────
# Import shared dependencies
from dependencies import db, get_current_user, security, SECRET_KEY, ALGORITHM

# ───────────────────────────────────────────────
# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ACCESS_TOKEN_EXPIRE_MINUTES = 30 * 24 * 60  # 30 days

# ───────────────────────────────────────────────
# App setup
app = FastAPI()
api_router = APIRouter(prefix="/api")

# ───────────────────────────────────────────────
# Google OAuth configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/api/google/callback")
SCOPES = ["https://www.googleapis.com/auth/calendar.readonly"]

# ───────────────────────────────────────────────
# Models
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user: dict

class Event(BaseModel):
    id: Optional[str] = None
    title: str
    description: Optional[str] = None
    start_time: datetime
    end_time: datetime
    calendar_source: str
    location: Optional[str] = None
    is_invite: bool = False
    invite_status: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    user_id: Optional[str] = None

class EventCreate(BaseModel):
    title: str
    description: Optional[str] = None
    start_time: datetime
    end_time: datetime
    calendar_source: str
    location: Optional[str] = None

class EventUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    location: Optional[str] = None

class CalendarSource(BaseModel):
    id: str
    name: str
    type: str
    color: str
    is_active: bool = True

# ───────────────────────────────────────────────
# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# get_current_user is now imported from dependencies

# ───────────────────────────────────────────────
# Health check routes
@api_router.get("/health")
async def health_check():
    """Check if the server and database are running properly"""
    try:
        # Test database connection
        await db.command("ping")
        return {
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

@api_router.get("/health/db")
async def database_health_check():
    """Detailed database connection health check"""
    try:
        # Test database connection with ping
        ping_result = await db.command("ping")
        
        # Get database stats
        stats = await db.command("dbStats")
        
        # Get collection count
        collections = await db.list_collection_names()
        
        return {
            "status": "healthy",
            "database": "connected",
            "ping_result": ping_result,
            "database_name": stats.get("db"),
            "collections": collections,
            "collections_count": len(collections),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

# ───────────────────────────────────────────────
# Google OAuth routes
@api_router.get("/google/login")
def google_login():
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [GOOGLE_REDIRECT_URI],
            }
        },
        scopes=SCOPES,
    )
    auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline")
    return RedirectResponse(auth_url)

@api_router.get("/google/callback")
async def google_callback(request: Request, current_user: dict = Depends(get_current_user)):
    code = request.query_params.get("code")
    if not code:
        return JSONResponse({"error": "No code provided"}, status_code=400)

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [GOOGLE_REDIRECT_URI],
            }
        },
        scopes=SCOPES,
    )
    flow.redirect_uri = GOOGLE_REDIRECT_URI
    flow.fetch_token(code=code)
    credentials = flow.credentials

    # Save refresh_token to DB for the current user
    await db.users.update_one(
        {"_id": ObjectId(current_user["_id"])},
        {"$set": {"google_refresh_token": credentials.refresh_token}}
    )

    # Fetch Google Calendar events
    service = build("calendar", "v3", credentials=credentials)
    events_result = service.events().list(
        calendarId="primary",
        maxResults=20,
        singleEvents=True,
        orderBy="startTime"
    ).execute()
    events = events_result.get("items", [])

    return {"events": events}

# ───────────────────────────────────────────────
# Auth routes
@api_router.post("/auth/register", response_model=Token)
async def register(user_data: UserRegister):
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_dict = {
        "email": user_data.email,
        "name": user_data.name,
        "password_hash": get_password_hash(user_data.password),
        "created_at": datetime.utcnow()
    }
    result = await db.users.insert_one(user_dict)
    user_id = str(result.inserted_id)
    access_token = create_access_token(data={"sub": user_id})
    return {"access_token": access_token, "token_type": "bearer", "user": {"id": user_id, "email": user_data.email, "name": user_data.name}}

@api_router.post("/auth/login", response_model=Token)
async def login(user_data: UserLogin):
    user = await db.users.find_one({"email": user_data.email})
    if not user or not verify_password(user_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    user_id = str(user["_id"])
    access_token = create_access_token(data={"sub": user_id})
    return {"access_token": access_token, "token_type": "bearer", "user": {"id": user_id, "email": user["email"], "name": user["name"]}}

# ───────────────────────────────────────────────
# Calendar Sources
@api_router.get("/calendar-sources", response_model=List[CalendarSource])
async def get_calendar_sources(current_user: dict = Depends(get_current_user)):
    return [
        CalendarSource(id="google", name="Google Calendar", type="google", color="#4285F4"),
        CalendarSource(id="apple", name="Apple Calendar", type="apple", color="#FF3B30"),
        CalendarSource(id="outlook", name="Outlook Calendar", type="outlook", color="#0078D4")
    ]

# ───────────────────────────────────────────────
# Events
@api_router.get("/events")
async def get_events(current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])

    # Fetch events from local DB
    db_events = await db.events.find({"user_id": user_id}).to_list(100)
    for e in db_events:
        e["id"] = str(e["_id"])
        e["_id"] = str(e["_id"])

    # Fetch Google events if available
    google_events = []
    refresh_token = current_user.get("google_refresh_token")
    if refresh_token:
        from google.oauth2.credentials import Credentials
        creds = Credentials(
            None,
            refresh_token=refresh_token,
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            token_uri="https://oauth2.googleapis.com/token"
        )
        service = build("calendar", "v3", credentials=creds)
        events_result = service.events().list(
            calendarId="primary",
            maxResults=20,
            singleEvents=True,
            orderBy="startTime"
        ).execute()
        google_events = events_result.get("items", [])

    # Fetch Apple events if available
    apple_events = []
    if current_user.get("apple_calendar_connected"):
        try:
            from apple_calendar_service import AppleCalendarService
            credentials = current_user.get("apple_calendar_credentials", {})
            if credentials:
                apple_calendar = AppleCalendarService(
                    apple_id=credentials["apple_id"],
                    app_specific_password=credentials["app_specific_password"],
                    user_id=user_id
                )
                apple_events = await apple_calendar.get_events()
        except Exception as e:
            logger.error(f"Error fetching Apple events: {str(e)}")

    # Fetch Microsoft events if available
    microsoft_events = []
    if current_user.get("microsoft_calendar_connected"):
        try:
            from microsoft_calendar_service import MicrosoftCalendarService
            access_token = current_user.get("microsoft_access_token")
            if access_token:
                from datetime import timedelta
                microsoft_calendar = MicrosoftCalendarService(access_token)
                start_date = datetime.utcnow()
                end_date = datetime.utcnow() + timedelta(days=30)
                microsoft_events = microsoft_calendar.get_events(
                    start_date=start_date,
                    end_date=end_date,
                    max_results=20
                )
        except Exception as e:
            logger.error(f"Error fetching Microsoft events: {str(e)}")

    return {
        "local_events": db_events, 
        "google_events": google_events,
        "apple_events": apple_events,
        "microsoft_events": microsoft_events
    }

@api_router.post("/events")
async def create_event(event: dict, current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    event["user_id"] = user_id

    result = await db.events.insert_one(event)
    event["id"] = str(result.inserted_id)
    event["_id"] = str(result.inserted_id)
    return {"message": "Event created successfully", "event": event}
@api_router.put("/events/{event_id}")
async def update_event(event_id: str, event: EventUpdate, current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])

    existing = await db.events.find_one({"_id": ObjectId(event_id), "user_id": user_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Event not found")

    # Only update fields that are provided
    update_data = {k: v for k, v in event.dict().items() if v is not None}
    
    await db.events.update_one({"_id": ObjectId(event_id)}, {"$set": update_data})
    
    # Return the updated event with proper ObjectId conversion
    updated_event = await db.events.find_one({"_id": ObjectId(event_id)})
    if updated_event:
        # Convert ObjectId to string for JSON serialization
        updated_event["id"] = str(updated_event["_id"])
        updated_event["_id"] = str(updated_event["_id"])
        # Convert any other ObjectId fields to strings
        if "user_id" in updated_event and isinstance(updated_event["user_id"], ObjectId):
            updated_event["user_id"] = str(updated_event["user_id"])
    
    return updated_event


# -------------------------------
# DELETE /api/events/{event_id}
# -------------------------------
@api_router.delete("/events/{event_id}")
async def delete_event(event_id: str, current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    result = await db.events.delete_one({"_id": ObjectId(event_id), "user_id": user_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Event not found")
    return {"message": "Event deleted"}
# ───────────────────────────────────────────────
# Include Routers + Middleware
app.include_router(api_router)

# Apple Calendar routes will be imported at the end to avoid circular imports
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ───────────────────────────────────────────────
# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ───────────────────────────────────────────────
# Import Apple Calendar routes (after all other definitions to avoid circular imports)
from apple_routes import apple_router
app.include_router(apple_router)

# Import Microsoft Calendar routes
from microsoft_routes import microsoft_router
app.include_router(microsoft_router)

# ───────────────────────────────────────────────
# Startup
if __name__ == "__main__":
    import uvicorn
    
    logger.info("Starting backend server on http://127.0.0.1:8000")
    
    # Configure uvicorn for Windows compatibility
    # Disable reload by default to avoid multiprocessing issues
    uvicorn.run(
        "server:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=False,  # Disable reload to avoid multiprocessing issues
        workers=1,     # Use single worker to avoid multiprocessing issues
        loop="asyncio" # Explicitly set event loop
    )
