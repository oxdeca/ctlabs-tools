import http.server
import socketserver
import webbrowser
import sys
import argparse
from importlib import resources

# Adjust this to match your package structure
PACKAGE_NAME = "ctlabs_tools.flashcards" 
HTML_FILE    = "flashcards.html"

class FlashcardHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            try:
                # Python 3.9+ API (required for Python 3.13)
                html_content = resources.files(PACKAGE_NAME).joinpath(HTML_FILE).read_bytes()
                
                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(html_content)
            except FileNotFoundError:
                self.send_error(404, "Flashcard app file not found in package")
        else:
            self.send_error(404, "Not Found")

# Custom server to allow address reuse (prevents "Address already in use" errors)
class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

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

    # Determine the URL for the browser
    # If host is 0.0.0.0, browsers usually can't connect to that specific address, so use localhost
    browser_host = "localhost" if args.host == "0.0.0.0" else args.host
    url = f"http://{browser_host}:{args.port}"

    try:
        with ReusableTCPServer((args.host, args.port), FlashcardHandler) as httpd:
            print(f"Serving flashcards at {url}")
            print(f"Listening on {args.host}:{args.port}")
            print("Press Ctrl+C to stop")
            
            if not args.no_browser:
                webbrowser.open(url)
            
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\nShutting down server...")
                sys.exit(0)
    except OSError as e:
        print(f"Error starting server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
