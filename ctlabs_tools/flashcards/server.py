import argparse
import webbrowser
import sys
from flask import Flask, send_from_directory, abort
from importlib import resources

# Package configuration
PACKAGE_NAME = "ctlabs_tools.flashcards"
HTML_FILE    = "flashcards.html"

# Create Flask app - static files served from the package directory
app = Flask(__name__, static_folder=resources.files(PACKAGE_NAME), static_url_path='')

@app.route('/')
@app.route('/index.html')
def serve_flashcards():
    """Serve the flashcards HTML file"""
    try:
        return send_from_directory(app.static_folder, HTML_FILE)
    except FileNotFoundError:
        abort(404, description=f"Flashcard app file '{HTML_FILE}' not found in package")

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
    print("Press Ctrl+C to stop")
    
    if not args.no_browser:
        webbrowser.open(url)
    
    # Run Flask (debug=False for production safety)
    app.run(host=args.host, port=args.port, debug=False)

if __name__ == "__main__":
    main()