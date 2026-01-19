from http.server import BaseHTTPRequestHandler, HTTPServer

class TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/secret':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"secret info")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"admin, now go to secret")

if __name__ == "__main__":
    server = HTTPServer(('127.0.0.1', 9000), TargetHandler)
    print("[*] Target server with sensitive info listening on 127.0.0.1:9000...")
    server.serve_forever()