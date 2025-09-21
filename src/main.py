#!/usr/bin/env python3
"""
Multinedor!!! - Multipurpose Threat Detection Toolkit
Main entry point for the application.

Usage:
    python main.py          # Launch GUI
    python main.py --cli    # Launch CLI mode (future feature)
    python main.py --help   # Show help information
"""

import sys
import argparse
from pathlib import Path

# Add src directory to Python path for module imports
sys.path.insert(0, str(Path(__file__).parent))

def main():
    """Main application entry point."""
    parser = argparse.ArgumentParser(
        description="Multinedor!!! - Multipurpose Threat Detection Toolkit"
    )
    parser.add_argument(
        '--cli', 
        action='store_true',
        help='Launch CLI mode (future feature)'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='Multinedor!!! v1.0'
    )
    
    args = parser.parse_args()
    
    try:
        if args.cli:
            print("CLI mode is not implemented yet.")
            print("Please run without --cli to use the GUI.")
            sys.exit(1)
        else:
            # Launch GUI
            from gui import MultinenadorGUI
            app = MultinenadorGUI()
            app.run()
            
    except ImportError as e:
        print(f"Import Error: {e}")
        print("Please ensure all required modules are installed.")
        print("Run: pip install -r requirements.txt")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nApplication terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
