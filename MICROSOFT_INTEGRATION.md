# Microsoft Outlook Calendar Integration

This guide explains how to set up and use Microsoft Outlook Calendar integration in the unified calendar app.

## Setup Instructions

### 1. Create Microsoft Azure App Registration

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** > **App registrations**
3. Click **New registration**
4. Fill in the details:
   - **Name**: Unified Calendar App
   - **Supported account types**: Accounts in any organizational directory and personal Microsoft accounts
   - **Redirect URI**: 
     - Web: `http://localhost:8000/microsoft/auth/callback`
     - Mobile: Your app's URL scheme
5. Click **Register**

### 2. Configure API Permissions

1. In your app registration, go to **API permissions**
2. Click **Add a permission** > **Microsoft Graph**
3. Select **Delegated permissions**
4. Add the following permissions:
   - `User.Read` - Read user profile
   - `Calendars.Read` - Read user calendars
   - `Calendars.ReadWrite` - Read and write user calendars
   - `offline_access` - Maintain access to resources
5. Click **Add permissions**
6. Click **Grant admin consent** (if you have admin rights)

### 3. Get Client Credentials

1. Go to **Certificates & secrets**
2. Click **New client secret**
3. Add description and set expiration
4. Click **Add**
5. **Copy the secret value immediately** (you won't be able to see it again)

### 4. Get Application (Client) ID

1. From the app registration **Overview** page
2. Copy the **Application (client) ID**

### 5. Get Directory (tenant) ID

1. From the app registration **Overview** page
2. Copy the **Directory (tenant) ID**

## Environment Configuration

Add these variables to your `.env` file in the backend directory:

```env
# Microsoft OAuth Configuration
MICROSOFT_CLIENT_ID=your_client_id_here
MICROSOFT_CLIENT_SECRET=your_client_secret_here
MICROSOFT_TENANT_ID=your_tenant_id_here
MICROSOFT_REDIRECT_URI=http://localhost:8000/microsoft/auth/callback
```

## Installation

1. Install required Python packages:
```bash
pip install msal
```

2. Update requirements.txt:
```bash
pip install -r requirements.txt
```

## API Endpoints

### Authentication

- `GET /api/microsoft/auth/login` - Initiate OAuth login
- `GET /api/microsoft/auth/callback` - Handle OAuth callback
- `GET /api/microsoft/auth/disconnect` - Disconnect Microsoft Calendar

### Calendar Operations

- `GET /api/microsoft/calendar/events` - Get all events
- `POST /api/microsoft/calendar/events` - Create event
- `PUT /api/microsoft/calendar/events/{event_id}` - Update event
- `DELETE /api/microsoft/calendar/events/{event_id}` - Delete event

### Merged Events

- `GET /api/events` - Get all events from all connected calendars (Google, Apple, Microsoft)

## Usage

### Backend

The Microsoft Calendar integration is automatically included when you:
1. Connect your Microsoft account via OAuth
2. Fetch events from the unified endpoint `/api/events`

Microsoft events will be included with the source: "Microsoft"

### Frontend

The frontend can:
1. Show a "Connect Microsoft Calendar" button
2. Display Microsoft events with a blue label
3. Filter events by calendar source
4. Create, update, and delete Microsoft events

## Security Notes

- Client secret should be kept secure and never committed to version control
- Use environment variables for all sensitive credentials
- Refresh tokens are stored securely in MongoDB
- Implement proper token rotation for production

## Troubleshooting

### Common Issues

1. **"Invalid client" error**: Check your CLIENT_ID and CLIENT_SECRET
2. **"Redirect URI mismatch"**: Verify the redirect URI matches exactly
3. **"Insufficient permissions"**: Ensure all required permissions are granted
4. **Token expired**: The system will automatically refresh tokens

### Logs

Check backend logs for detailed error messages:
```bash
tail -f backend/backend_log.txt
```

## Next Steps

1. Install the msal library
2. Set up environment variables
3. Test the authentication flow
4. Integrate with frontend UI

See the frontend integration guide for mobile app setup.
