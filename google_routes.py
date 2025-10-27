from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta

load_dotenv()

router = APIRouter()
redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")

# Optional: Security setup to protect endpoints
security = HTTPBearer()
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30 * 24 * 60  # 30 days

# In-memory state store for demo purposes (use DB in production)
oauth_states = {}

@router.get("/")
async def auth_google():
    """Step 1: Redirect user to Google OAuth login"""
    flow = Flow.from_client_secrets_file(
        "client_secret.json",
        scopes=[
            "https://www.googleapis.com/auth/calendar.readonly",
            "openid",
            "https://www.googleapis.com/auth/userinfo.email"
        ],
        redirect_uri=redirect_uri
    )
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true"
    )
    oauth_states[state] = datetime.utcnow()  # store state
    return RedirectResponse(authorization_url)


@router.get("/callback")
async def google_callback(request: Request):
    """Step 2: Handle Google OAuth callback"""
    state = request.query_params.get("state")
    if state not in oauth_states:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")
    
    flow = Flow.from_client_secrets_file(
        "client_secret.json",
        scopes=[
            "https://www.googleapis.com/auth/calendar.readonly",
            "openid",
            "https://www.googleapis.com/auth/userinfo.email"
        ],
        redirect_uri=redirect_uri,
        state=state
    )
    
    flow.fetch_token(authorization_response=str(request.url))
    credentials = flow.credentials

    # Fetch Google Calendar events
    service = build("calendar", "v3", credentials=credentials)
    events_result = service.events().list(calendarId="primary", maxResults=10).execute()
    events = events_result.get("items", [])

    # Optionally: create JWT to return to your frontend
    token_data = {"sub": "google_user"}
    access_token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)

    return JSONResponse({
        "access_token": access_token,
        "token_type": "bearer",
        "google_events": events
    })
