import argparse
import webbrowser
import sys
from pathlib import Path
from flask import Flask, send_from_directory, abort, redirect, url_for

# Package configuration
PACKAGE_NAME = "ctlabs_tools.flashcards"
HTML_FILE    = "flashcards.html"

# Resolve the package directory as a filesystem path
# This works for both editable installs and regular installs (when not zipped)
PACKAGE_DIR = Path(__file__).parent

# Create Flask app - serve static files directly from the package directory
app = Flask(__name__, static_folder=str(PACKAGE_DIR), static_url_path='')

@app.route('/')
@app.route('/index.html')
def serve_flashcards():
    """Redirect root requests to the actual flashcards file"""
    return redirect(url_for('static', filename=HTML_FILE))

@app.errorhandler(404)
def not_found(e):
    return {"error": "Not Found", "message": str(e.description)}, 404

def main():
    parser = argparse.ArgumentParser(description="Run the Flashcards app locally")
    parser.add_argument(
        "-H", "--host", 
        type=str, 
        default="127.0.0.1", 
        help="Host IP to bind to (default: 127.0.0.1)"
    )
    parser.add_argument(
        "-p", "--port", 
        type=int, 
        default=8000, 
        help="Port to bind to (default: 8000)"
    )
    parser.add_argument(
        "--no-browser", 
        action="store_true", 
        help="Do not automatically open the web browser"
    )
    
    args = parser.parse_args()
    
    # Browser URL: use localhost even if binding to 0.0.0.0
    browser_host = "localhost" if args.host == "0.0.0.0" else args.host
    url = f"http://{browser_host}:{args.port}"

    print(f"Serving flashcards at {url}")
    print(f"Listening on {args.host}:{args.port}")
    print(f"Static files served from: {PACKAGE_DIR}")
    print("Press Ctrl+C to stop")
    
    if not args.no_browser:
        webbrowser.open(url)
    
    # Run Flask (debug=False for production safety)
    app.run(host=args.host, port=args.port, debug=False)

if __name__ == "__main__":
    main()
