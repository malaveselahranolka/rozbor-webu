import io
import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from PIL import Image, ImageDraw, ImageFont

from app import run_analysis


class _TestSite(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self._send(b"<button>New chat</button><script>fetch('/api/models')</script>", "text/html")
        elif self.path == "/api/models":
            self._send(b'{"models":[{"id":"demo"}]}', "application/json")
        else:
            self.send_error(404)

    def _send(self, body, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class CompatibilityTest(unittest.TestCase):
    def test_chromium_captures_live_api(self):
        with ThreadingHTTPServer(("127.0.0.1", 0), _TestSite) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = f"http://127.0.0.1:{server.server_port}"
                report, markdown = run_analysis(url, "", [], False, 0)
                endpoint = next((row for row in report.data["observed"] if row["url"].endswith("/api/models")), None)
                self.assertIsNotNone(endpoint, report.data["sources"])
                self.assertEqual(endpoint["statuses"], [200])
                self.assertIn("models[].id", endpoint["response_fields"])
                self.assertIn("/api/models", markdown)
            finally:
                server.shutdown()
                thread.join()

    @unittest.skipUnless(sys.platform in {"darwin", "win32"}, "OCR uses macOS or Windows.")
    def test_native_ocr_reads_screenshot(self):
        image = Image.new("RGB", (900, 260), "white")
        draw = ImageDraw.Draw(image)
        font = ImageFont.load_default(size=55)
        draw.text((24, 18), "New chat\nUpload files", font=font, fill="black", spacing=10)
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        report, _ = run_analysis("", "", [("screenshot.png", buffer.getvalue())], False, 0)
        text = json.dumps(report.data["ocr"]).lower()
        self.assertIn("new chat", text, report.data["sources"])
        self.assertIn("upload files", text, report.data["sources"])
