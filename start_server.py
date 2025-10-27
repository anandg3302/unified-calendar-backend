#!/usr/bin/env python3
"""
Startup script for the unified calendar backend server.
This script handles Windows multiprocessing issues with MongoDB driver.
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
    
    print("Starting Unified Calendar Backend Server...")
    print("Server will be available at: http://localhost:8000")
    print("Health check endpoint: http://localhost:8000/api/health")
    print("Database health check: http://localhost:8000/api/health/db")
    print("Press Ctrl+C to stop the server")
    print("-" * 50)
    
    try:
        # Disable reload to avoid multiprocessing issues on Windows
        # Use single worker and no reload for stability
        uvicorn.run(
            "server:app",  # Import string
            host="0.0.0.0",
            port=8000,
            reload=False,  # Disable reload to avoid multiprocessing issues
            workers=1,     # Single worker
            loop="asyncio"
        )
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Server error: {e}")
        sys.exit(1)
