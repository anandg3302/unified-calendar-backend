"""
Microsoft Calendar Service

This module handles Microsoft Graph API integration for Outlook Calendar.
"""

import requests
import logging
from typing import List, Dict, Optional, Any
from datetime import datetime
import pytz

logger = logging.getLogger(__name__)

class MicrosoftCalendarService:
    """
    Service class for Microsoft Outlook Calendar integration.
    
    This class handles:
    - Fetching calendar events from Microsoft Graph API
    - Creating, updating, and deleting events
    - Managing calendar sync
    """
    
    GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"
    
    def __init__(self, access_token: str):
        """
        Initialize Microsoft Calendar service.
        
        Args:
            access_token (str): Microsoft access token
        """
        self.access_token = access_token
        self.headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
    
    def get_user_info(self) -> Dict[str, Any]:
        """
        Get authenticated user information from Microsoft Graph.
        
        Returns:
            Dict: User information
        """
        try:
            response = requests.get(
                f"{self.GRAPH_API_BASE}/me",
                headers=self.headers
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get user info: {response.status_code} - {response.text}")
                return {}
                
        except Exception as e:
            logger.error(f"Error getting Microsoft user info: {str(e)}")
            return {}
    
    def get_calendars(self) -> List[Dict[str, Any]]:
        """
        Get user's calendars from Outlook.
        
        Returns:
            List[Dict]: List of calendar objects
        """
        try:
            response = requests.get(
                f"{self.GRAPH_API_BASE}/me/calendars",
                headers=self.headers
            )
            
            if response.status_code == 200:
                return response.json().get("value", [])
            else:
                logger.error(f"Failed to get calendars: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            logger.error(f"Error getting Microsoft calendars: {str(e)}")
            return []
    
    def get_events(
        self, 
        calendar_id: str = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        max_results: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Fetch calendar events from Microsoft Outlook.
        
        Args:
            calendar_id (str): Specific calendar ID (None for default calendar)
            start_date (datetime): Start date for events
            end_date (datetime): End date for events
            max_results (int): Maximum number of events to return
            
        Returns:
            List[Dict]: List of event objects with unified format
        """
        try:
            # Determine calendar endpoint
            if calendar_id:
                endpoint = f"{self.GRAPH_API_BASE}/me/calendars/{calendar_id}/events"
            else:
                endpoint = f"{self.GRAPH_API_BASE}/me/events"
            
            # Build query parameters
            params = {}
            if start_date:
                params["startDateTime"] = start_date.isoformat()
            if end_date:
                params["endDateTime"] = end_date.isoformat()
            params["$top"] = str(max_results)
            
            # Fetch events
            response = requests.get(
                endpoint,
                headers=self.headers,
                params=params
            )
            
            if response.status_code == 200:
                events = response.json().get("value", [])
                
                # Transform Microsoft events to unified format
                unified_events = []
                for event in events:
                    unified_event = self._transform_event(event)
                    unified_events.append(unified_event)
                
                logger.info(f"Fetched {len(unified_events)} Microsoft events")
                return unified_events
            else:
                logger.error(f"Failed to get events: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            logger.error(f"Error fetching Microsoft events: {str(e)}")
            return []
    
    def create_event(self, event_data: Dict[str, Any], calendar_id: str = None) -> Dict[str, Any]:
        """
        Create a new event in Microsoft Outlook calendar.
        
        Args:
            event_data (Dict): Event data in unified format
            calendar_id (str): Specific calendar ID (None for default calendar)
            
        Returns:
            Dict: Created event data
        """
        try:
            # Determine calendar endpoint
            if calendar_id:
                endpoint = f"{self.GRAPH_API_BASE}/me/calendars/{calendar_id}/events"
            else:
                endpoint = f"{self.GRAPH_API_BASE}/me/events"
            
            # Transform unified format to Microsoft format
            microsoft_event = self._transform_to_microsoft_format(event_data)
            
            # Create event
            response = requests.post(
                endpoint,
                headers=self.headers,
                json=microsoft_event
            )
            
            if response.status_code == 201:
                created_event = response.json()
                logger.info(f"Created Microsoft event: {created_event.get('subject')}")
                return self._transform_event(created_event)
            else:
                logger.error(f"Failed to create event: {response.status_code} - {response.text}")
                raise Exception(f"Failed to create Microsoft event: {response.text}")
                
        except Exception as e:
            logger.error(f"Error creating Microsoft event: {str(e)}")
            raise
    
    def update_event(self, event_id: str, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update an existing event in Microsoft Outlook calendar.
        
        Args:
            event_id (str): Microsoft event ID
            event_data (Dict): Updated event data
            
        Returns:
            Dict: Updated event data
        """
        try:
            endpoint = f"{self.GRAPH_API_BASE}/me/events/{event_id}"
            
            # Transform unified format to Microsoft format
            microsoft_event = self._transform_to_microsoft_format(event_data)
            
            # Update event
            response = requests.patch(
                endpoint,
                headers=self.headers,
                json=microsoft_event
            )
            
            if response.status_code == 200:
                updated_event = response.json()
                logger.info(f"Updated Microsoft event: {updated_event.get('subject')}")
                return self._transform_event(updated_event)
            else:
                logger.error(f"Failed to update event: {response.status_code} - {response.text}")
                raise Exception(f"Failed to update Microsoft event: {response.text}")
                
        except Exception as e:
            logger.error(f"Error updating Microsoft event: {str(e)}")
            raise
    
    def delete_event(self, event_id: str) -> bool:
        """
        Delete an event from Microsoft Outlook calendar.
        
        Args:
            event_id (str): Microsoft event ID
            
        Returns:
            bool: True if successful
        """
        try:
            endpoint = f"{self.GRAPH_API_BASE}/me/events/{event_id}"
            
            response = requests.delete(
                endpoint,
                headers=self.headers
            )
            
            if response.status_code == 204:
                logger.info(f"Deleted Microsoft event: {event_id}")
                return True
            else:
                logger.error(f"Failed to delete event: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error deleting Microsoft event: {str(e)}")
            return False
    
    def _transform_event(self, microsoft_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform Microsoft event format to unified format.
        
        Args:
            microsoft_event (Dict): Microsoft event data
            
        Returns:
            Dict: Event in unified format
        """
        # Convert Microsoft event to unified format
        unified_event = {
            "id": microsoft_event.get("id"),
            "title": microsoft_event.get("subject", "No Title"),
            "description": microsoft_event.get("body", {}).get("content", ""),
            "start_time": microsoft_event.get("start", {}).get("dateTime", ""),
            "end_time": microsoft_event.get("end", {}).get("dateTime", ""),
            "location": microsoft_event.get("location", {}).get("displayName", ""),
            "calendar_source": "Microsoft",
            "microsoft_event_id": microsoft_event.get("id"),
            "microsoft_calendar_id": microsoft_event.get("calendarId"),
            "created_at": microsoft_event.get("createdDateTime", ""),
            "updated_at": microsoft_event.get("lastModifiedDateTime", ""),
            "is_all_day": microsoft_event.get("isAllDay", False),
            "is_invite": microsoft_event.get("isReminderOn", False),
            "attendees": microsoft_event.get("attendees", [])
        }
        
        return unified_event
    
    def _transform_to_microsoft_format(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform unified event format to Microsoft format.
        
        Args:
            event_data (Dict): Event data in unified format
            
        Returns:
            Dict: Event data in Microsoft format
        """
        microsoft_event = {
            "subject": event_data.get("title", "New Event"),
            "body": {
                "contentType": "HTML",
                "content": event_data.get("description", "")
            },
            "start": {
                "dateTime": event_data.get("start_time"),
                "timeZone": "UTC"
            },
            "end": {
                "dateTime": event_data.get("end_time"),
                "timeZone": "UTC"
            }
        }
        
        # Add location if provided
        if event_data.get("location"):
            microsoft_event["location"] = {
                "displayName": event_data.get("location")
            }
        
        # Add attendees if provided
        if event_data.get("attendees"):
            microsoft_event["attendees"] = event_data.get("attendees")
        
        return microsoft_event
