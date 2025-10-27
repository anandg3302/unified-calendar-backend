"""
Apple Calendar Integration Service

This module provides CalDAV integration for Apple Calendar (iCloud) using the CalDAV protocol.
It handles authentication, CRUD operations, and event synchronization.

Author: AI Assistant
Date: 2024
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from urllib.parse import urljoin
import httpx
import caldav
from caldav import Calendar, Event
from icalendar import Calendar as ICalendar, Event as IEvent
import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from jose import jwt as jose_jwt
import secrets
import string

logger = logging.getLogger(__name__)

class AppleCalendarService:
    """
    Service class for Apple Calendar integration using CalDAV protocol.
    
    This class handles:
    - CalDAV authentication with iCloud
    - CRUD operations for calendar events
    - Event synchronization
    - Token management
    """
    
    def __init__(self, apple_id: str, app_specific_password: str, user_id: str):
        """
        Initialize Apple Calendar service.
        
        Args:
            apple_id (str): User's Apple ID email
            app_specific_password (str): App-specific password for iCloud
            user_id (str): Internal user ID for tracking
        """
        self.apple_id = apple_id
        self.app_specific_password = app_specific_password
        self.user_id = user_id
        self.caldav_url = "https://caldav.icloud.com"
        self.client = None
        self.principal = None
        
    async def connect(self) -> bool:
        """
        Establish connection to Apple Calendar via CalDAV.
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            # Initialize CalDAV client
            self.client = caldav.DAVClient(
                url=self.caldav_url,
                username=self.apple_id,
                password=self.app_specific_password
            )
            
            # Get principal (user's calendar collection)
            self.principal = self.client.principal()
            
            logger.info(f"Successfully connected to Apple Calendar for user {self.user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to Apple Calendar: {str(e)}")
            return False
    
    async def get_calendars(self) -> List[Dict[str, Any]]:
        """
        Retrieve all available calendars for the user.
        
        Returns:
            List[Dict]: List of calendar information
        """
        try:
            if not self.principal:
                await self.connect()
            
            calendars = self.principal.calendars()
            calendar_list = []
            
            for calendar in calendars:
                calendar_info = {
                    'id': calendar.id,
                    'name': calendar.name,
                    'url': calendar.url,
                    'display_name': getattr(calendar, 'display_name', calendar.name),
                    'color': getattr(calendar, 'color', '#007AFF'),
                    'is_active': True
                }
                calendar_list.append(calendar_info)
            
            return calendar_list
            
        except Exception as e:
            logger.error(f"Error fetching Apple calendars: {str(e)}")
            return []
    
    async def get_events(self, calendar_id: str = None, start_date: datetime = None, 
                        end_date: datetime = None) -> List[Dict[str, Any]]:
        """
        Retrieve events from Apple Calendar.
        
        Args:
            calendar_id (str): Specific calendar ID (optional)
            start_date (datetime): Start date for event range
            end_date (datetime): End date for event range
            
        Returns:
            List[Dict]: List of event data
        """
        try:
            if not self.principal:
                await self.connect()
            
            # Set default date range if not provided
            if not start_date:
                start_date = datetime.now() - timedelta(days=30)
            if not end_date:
                end_date = datetime.now() + timedelta(days=365)
            
            events = []
            calendars = self.principal.calendars()
            
            for calendar in calendars:
                if calendar_id and calendar.id != calendar_id:
                    continue
                
                try:
                    # Search for events in date range
                    search_results = calendar.search(
                        start=start_date,
                        end=end_date,
                        event=True,
                        expand=True
                    )
                    
                    for event in search_results:
                        event_data = self._parse_ical_event(event)
                        if event_data:
                            event_data['calendar_source'] = 'apple'
                            event_data['calendar_id'] = calendar.id
                            event_data['calendar_name'] = calendar.name
                            events.append(event_data)
                            
                except Exception as e:
                    logger.warning(f"Error fetching events from calendar {calendar.name}: {str(e)}")
                    continue
            
            return events
            
        except Exception as e:
            logger.error(f"Error fetching Apple Calendar events: {str(e)}")
            return []
    
    async def create_event(self, event_data: Dict[str, Any], calendar_id: str = None) -> Optional[str]:
        """
        Create a new event in Apple Calendar.
        
        Args:
            event_data (Dict): Event information
            calendar_id (str): Target calendar ID
            
        Returns:
            Optional[str]: Event ID if successful, None otherwise
        """
        try:
            if not self.principal:
                await self.connect()
            
            calendars = self.principal.calendars()
            target_calendar = None
            
            # Find target calendar
            if calendar_id:
                for calendar in calendars:
                    if calendar.id == calendar_id:
                        target_calendar = calendar
                        break
            
            if not target_calendar and calendars:
                target_calendar = calendars[0]  # Use first available calendar
            
            if not target_calendar:
                raise Exception("No calendar available for event creation")
            
            # Create iCal event
            ical_event = self._create_ical_event(event_data)
            
            # Save event to calendar
            event = target_calendar.save_event(ical_event)
            
            logger.info(f"Successfully created Apple Calendar event for user {self.user_id}")
            return event.id if hasattr(event, 'id') else str(event.url)
            
        except Exception as e:
            logger.error(f"Error creating Apple Calendar event: {str(e)}")
            return None
    
    async def update_event(self, event_id: str, event_data: Dict[str, Any], 
                          calendar_id: str = None) -> bool:
        """
        Update an existing event in Apple Calendar.
        
        Args:
            event_id (str): Event ID to update
            event_data (Dict): Updated event information
            calendar_id (str): Calendar ID containing the event
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not self.principal:
                await self.connect()
            
            calendars = self.principal.calendars()
            target_calendar = None
            
            # Find target calendar
            if calendar_id:
                for calendar in calendars:
                    if calendar.id == calendar_id:
                        target_calendar = calendar
                        break
            
            if not target_calendar and calendars:
                target_calendar = calendars[0]
            
            if not target_calendar:
                raise Exception("No calendar available for event update")
            
            # Find the event
            events = target_calendar.events()
            target_event = None
            
            for event in events:
                if event.id == event_id or str(event.url).endswith(event_id):
                    target_event = event
                    break
            
            if not target_event:
                raise Exception(f"Event {event_id} not found")
            
            # Create updated iCal event
            ical_event = self._create_ical_event(event_data)
            
            # Update the event
            target_event.data = ical_event
            target_event.save()
            
            logger.info(f"Successfully updated Apple Calendar event {event_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating Apple Calendar event: {str(e)}")
            return False
    
    async def delete_event(self, event_id: str, calendar_id: str = None) -> bool:
        """
        Delete an event from Apple Calendar.
        
        Args:
            event_id (str): Event ID to delete
            calendar_id (str): Calendar ID containing the event
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not self.principal:
                await self.connect()
            
            calendars = self.principal.calendars()
            target_calendar = None
            
            # Find target calendar
            if calendar_id:
                for calendar in calendars:
                    if calendar.id == calendar_id:
                        target_calendar = calendar
                        break
            
            if not target_calendar and calendars:
                target_calendar = calendars[0]
            
            if not target_calendar:
                raise Exception("No calendar available for event deletion")
            
            # Find the event
            events = target_calendar.events()
            target_event = None
            
            for event in events:
                if event.id == event_id or str(event.url).endswith(event_id):
                    target_event = event
                    break
            
            if not target_event:
                raise Exception(f"Event {event_id} not found")
            
            # Delete the event
            target_event.delete()
            
            logger.info(f"Successfully deleted Apple Calendar event {event_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting Apple Calendar event: {str(e)}")
            return False
    
    def _parse_ical_event(self, event: Event) -> Optional[Dict[str, Any]]:
        """
        Parse iCal event data into our standard format.
        
        Args:
            event (Event): CalDAV event object
            
        Returns:
            Optional[Dict]: Parsed event data
        """
        try:
            # Parse iCal data
            ical_data = event.data
            if isinstance(ical_data, bytes):
                ical_data = ical_data.decode('utf-8')
            
            cal = ICalendar.from_ical(ical_data)
            
            for component in cal.walk():
                if component.name == "VEVENT":
                    # Extract event data
                    event_data = {
                        'id': str(component.get('uid', '')),
                        'title': str(component.get('summary', '')),
                        'description': str(component.get('description', '')),
                        'location': str(component.get('location', '')),
                        'start_time': self._parse_datetime(component.get('dtstart')),
                        'end_time': self._parse_datetime(component.get('dtend')),
                        'created_at': self._parse_datetime(component.get('created')),
                        'updated_at': self._parse_datetime(component.get('last-modified')),
                        'is_invite': False,  # Apple Calendar events are not invites by default
                        'invite_status': None,
                        'raw_data': ical_data
                    }
                    
                    return event_data
            
            return None
            
        except Exception as e:
            logger.error(f"Error parsing iCal event: {str(e)}")
            return None
    
    def _create_ical_event(self, event_data: Dict[str, Any]) -> str:
        """
        Create iCal formatted event data.
        
        Args:
            event_data (Dict): Event information
            
        Returns:
            str: iCal formatted event data
        """
        try:
            # Create iCal event
            cal = ICalendar()
            event = IEvent()
            
            # Set event properties
            event.add('uid', event_data.get('id', self._generate_uid()))
            event.add('summary', event_data.get('title', ''))
            event.add('description', event_data.get('description', ''))
            event.add('location', event_data.get('location', ''))
            
            # Set dates
            start_time = event_data.get('start_time')
            end_time = event_data.get('end_time')
            
            if isinstance(start_time, str):
                start_time = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            if isinstance(end_time, str):
                end_time = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            
            event.add('dtstart', start_time)
            event.add('dtend', end_time)
            event.add('dtstamp', datetime.now())
            
            # Add to calendar
            cal.add_component(event)
            
            return cal.to_ical().decode('utf-8')
            
        except Exception as e:
            logger.error(f"Error creating iCal event: {str(e)}")
            raise
    
    def _parse_datetime(self, dt_value) -> Optional[str]:
        """
        Parse datetime value from iCal format.
        
        Args:
            dt_value: iCal datetime value
            
        Returns:
            Optional[str]: ISO formatted datetime string
        """
        try:
            if not dt_value:
                return None
            
            if hasattr(dt_value, 'dt'):
                dt = dt_value.dt
            else:
                dt = dt_value
            
            if isinstance(dt, datetime):
                return dt.isoformat()
            elif isinstance(dt, str):
                return dt
            
            return None
            
        except Exception as e:
            logger.error(f"Error parsing datetime: {str(e)}")
            return None
    
    def _generate_uid(self) -> str:
        """
        Generate a unique identifier for events.
        
        Returns:
            str: Unique identifier
        """
        return f"apple-{self.user_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(8)}"
    
    async def close(self):
        """
        Close the CalDAV connection.
        """
        if self.client:
            # CalDAV client doesn't have explicit close method
            # Connection will be closed when object is garbage collected
            self.client = None
            self.principal = None
