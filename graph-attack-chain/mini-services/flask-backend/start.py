"""Flask startup script."""
import sys
import os

# Add user site-packages where pip installed deps
sys.path.insert(0, os.path.expanduser('~/.local/lib/python3.13/site-packages'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app

if __name__ == '__main__':
    from werkzeug.serving import run_simple
    print('Starting Flask on port 5001...')
    run_simple('0.0.0.0', 5001, app, use_reloader=False, use_debugger=False, threaded=True)
