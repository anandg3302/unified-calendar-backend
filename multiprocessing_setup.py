"""
Multiprocessing setup module for Windows compatibility.
This module must be imported before any MongoDB-related imports.
"""

import sys
import multiprocessing

def setup_multiprocessing():
    """Setup multiprocessing for Windows compatibility with MongoDB driver."""
    if sys.platform == "win32":
        try:
            multiprocessing.set_start_method('spawn', force=True)
        except RuntimeError:
            # Already set, ignore
            pass

# Automatically setup when module is imported
setup_multiprocessing()
