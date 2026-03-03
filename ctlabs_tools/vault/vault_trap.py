#!/usr/bin/env python3

# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/vault_trap.py
# Purpose : web server to receive oidc responses and presenting a copy button
# -----------------------------------------------------------------------------

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8250

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vault OIDC Helper</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f4f6f8; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: #ffffff; padding: 40px; border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.1); text-align: center; max-width: 650px; width: 90%; }
        h2 { color: #1a1a1a; margin-top: 0; }
        p { color: #555; margin-bottom: 24px; font-size: 15px; line-height: 1.5; }
        .input-group { display: flex; gap: 12px; margin-bottom: 16px; }
        input[type="text"] { flex: 1; padding: 12px; border: 1px solid #d1d5db; border-radius: 6px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 13px; color: #333; background-color: #f9fafb; outline: none; }
        input[type="text"]:focus { border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1); }
        button { background-color: #000000; color: white; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 600; transition: background-color 0.2s; }
        button:hover { background-color: #333333; }
        .success-msg { color: #10b981; font-weight: 600; font-size: 14px; opacity: 0; transition: opacity 0.3s ease; }
        .show-msg { opacity: 1; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔒 Authentication Received</h2>
        <p>Google has successfully verified your identity. Click the button below to copy your authorization URL, then paste it back into your SSH terminal.</p>
        
        <div class="input-group">
            <input type="text" id="authUrl" value="{full_url}" readonly>
            <button onclick="copyUrl()" id="copyBtn">Copy URL</button>
        </div>
        <div class="success-msg" id="successMsg">✅ Copied to clipboard! You can close this tab.</div>
    </div>

    <script>
        function copyUrl() {
            var copyText = document.getElementById("authUrl");
            copyText.select();
            copyText.setSelectionRange(0, 99999); // For mobile devices
            
            navigator.clipboard.writeText(copyText.value).then(() => {
                document.getElementById("successMsg").classList.add("show-msg");
                var btn = document.getElementById("copyBtn");
                btn.innerHTML = "Copied!";
                btn.style.backgroundColor = "#10b981";
                
                setTimeout(() => { 
                    document.getElementById("successMsg").classList.remove("show-msg"); 
                    btn.innerHTML = "Copy URL";
                    btn.style.backgroundColor = "#000000";
                }, 3000);
            }).catch(err => {
                console.error('Failed to copy: ', err);
                alert("Failed to copy automatically. Please copy the text manually.");
            });
        }
    </script>
</body>
</html>
"""

class OIDCReceiverHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Only intercept the specific callback path
        if self.path.startswith("/oidc/callback"):
            # Reconstruct the full URL the browser hit
            full_url = f"http://localhost:{PORT}{self.path}"
            
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            
            # Inject the URL into our HTML template
            html_content = HTML_TEMPLATE.replace("{full_url}", full_url)
            self.wfile.write(html_content.encode('utf-8'))
            
            print(f"✅ Intercepted callback! Serving UI to browser...")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        # Keep the terminal output completely clean
        pass

def main():
    server = HTTPServer(('localhost', PORT), OIDCReceiverHandler)
    print("="*60)
    print(f"🚀 Vault OIDC Local Helper is running on http://localhost:{PORT}")
    print("   Leave this running in the background.")
    print("   Press Ctrl+C to stop.")
    print("="*60)
    
    try:
        # Run forever so it's always ready to catch your logins
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down helper...")
    finally:
        server.server_close()
        sys.exit(0)

if __name__ == "__main__":
    main()
