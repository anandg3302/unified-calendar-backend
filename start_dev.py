#!/usr/bin/env python3
"""
Development startup script for the unified calendar backend server.
This script enables reload functionality while handling Windows multiprocessing issues.
"""

import sys
import os
import multiprocessing

# Critical: Fix for Windows multiprocessing issues with MongoDB driver
# This MUST be done before any other imports
if sys.platform == "win32":
    try:
        multiprocessing.set_start_method('spawn', force=True)
    except RuntimeError:
        # Already set, ignore
        pass

if __name__ == "__main__":
    import uvicorn
    
    print("Starting Unified Calendar Backend Server (Development Mode)...")
    print("Server will be available at: http://localhost:8000")
    print("Health check endpoint: http://localhost:8000/api/health")
    print("Database health check: http://localhost:8000/api/health/db")
    print("Auto-reload enabled for development")
    print("Press Ctrl+C to stop the server")
    print("-" * 50)
    
    try:
        # Development mode with reload enabled
        # Use --reload flag equivalent
        uvicorn.run(
            "server:app",  # Import string
            host="0.0.0.0",
            port=8000,
            reload=True,   # Enable reload for development
            workers=1,     # Single worker
            loop="asyncio",
            reload_dirs=["./"]  # Watch current directory for changes
        )
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Server error: {e}")
        sys.exit(1)
