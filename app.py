import argparse
import base64
import binascii
import json
import os
import pickle
import secrets
import subprocess
import sys
import threading
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from browser_capture import INTERACTIVE_SECONDS, capture_url, target_url
from inspector import FILE_LIMIT, Report, inspect_input, markdown_report, public_url
from ocr import recognize_image


ROOT = Path(__file__).resolve().parent
MAX_FILES = 6
MAX_TEXT = 500_000
MAX_HTTP_BYTES = (FILE_LIMIT + 2) // 3 * 4 + MAX_TEXT * 6 + 65536
WEB_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}


def _bounded_capture(report, url, seconds):
    # The worker runs this same project's code. The pipe carries a snapshot of
    # the report, so the parent can keep the offline results on a browser error.
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
    try:
        worker = subprocess.run(
            [sys.executable, "-X", "utf8", str(ROOT / "app.py"), "--capture-worker"],
            input=pickle.dumps((report, url, seconds)),
            capture_output=True, timeout=seconds + 65, **options,
        )
        if worker.returncode == 0:
            captured = pickle.loads(worker.stdout)
            if isinstance(captured, Report):
                return captured
    except (OSError, EOFError, pickle.UnpicklingError, subprocess.TimeoutExpired):
        pass
    source = report.source("URL", public_url(target_url(url)))
    report.note("Záznam v prohlížeči nedoběhl. Síťový provoz z této adresy lze dodat v HAR.", source)
    return report


def run_analysis(url, text, files, archive, seconds):
    if not (url or text.strip() or files):
        raise ValueError("Přidej URL, text nebo soubor.")
    if len(text) > MAX_TEXT:
        raise ValueError("Vložený text je nad limitem. Delší text přilož jako soubor.")
    if len(files) > MAX_FILES or sum(len(data) for _, data in files) > FILE_LIMIT:
        raise ValueError("Jedna analýza přijme až 6 souborů o celkové velikosti do 64 MiB.")
    if type(seconds) is not int or seconds not in INTERACTIVE_SECONDS | {0}:
        raise ValueError("Vyber platnou délku ručního záznamu.")
    if seconds and not url:
        raise ValueError("Pro záznam v novém okně zadej webovou adresu.")
    if url:
        target_url(url)
    report = Report(archive)
    if text.strip():
        inspect_input(report, "Vložený text", text.encode("utf-8"), recognize_image)
    for name, data in files:
        inspect_input(report, name, data, recognize_image)
    if url:
        report = _bounded_capture(report, url, seconds)
    report.finish()
    return report, markdown_report(report.data)


def _input_files(value):
    if not isinstance(value, list) or len(value) > MAX_FILES:
        raise ValueError("Jedna analýza přijme až 6 souborů.")
    files = []
    size = 0
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("data"), str):
            raise ValueError("Forma souboru musí obsahovat název a jeho obsah.")
        try:
            data = base64.b64decode(item["data"], validate=True)
        except (ValueError, binascii.Error):
            raise ValueError("Přiložený soubor se nepodařilo načíst.") from None
        size += len(data)
        if size > FILE_LIMIT:
            raise ValueError("Přílohy mají celkem více než 64 MiB.")
        files.append((item["name"], data))
    return files


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), LocalHandler)
        self.host_header = f"127.0.0.1:{self.server_port}"
        self.origin = f"http://{self.host_header}"
        self.token = secrets.token_urlsafe(32)
        self.analysis_lock = threading.Lock()


class LocalHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def _same_local_origin(self):
        return (
            self.headers.get("Host") == self.server.host_header
            and self.headers.get("Sec-Fetch-Site") != "cross-site"
            and self.headers.get("Origin") in {None, self.server.origin}
        )

    def _send(self, status, body, mime):
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def _json(self, status, value):
        self._send(status, json.dumps(value, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def do_GET(self):
        if not self._same_local_origin():
            self._json(403, {"error": "Rozhraní je dostupné z místní adresy aplikace."})
            return
        if self.path not in WEB_FILES:
            self._json(404, {"error": "Stránka nenalezena."})
            return
        name, mime = WEB_FILES[self.path]
        body = (ROOT / "web" / name).read_bytes()
        if self.path == "/":
            body = body.replace(b"__LOCAL_TOKEN__", self.server.token.encode("ascii"))
        self._send(200, body, mime)

    def do_POST(self):
        if not self._same_local_origin() or not secrets.compare_digest(
            self.headers.get("X-Local-Token", "").encode("latin-1"), self.server.token.encode("ascii")
        ):
            self._json(403, {"error": "Otevři stránku z místního okna Rozbor webu."})
            return
        if self.path != "/analyze":
            self._json(404, {"error": "Stránka nenalezena."})
            return
        length = self.headers.get("Content-Length", "")
        if not length.isascii() or not length.isdecimal() or len(length) > 9 or not 0 < int(length) <= MAX_HTTP_BYTES:
            self._json(413, {"error": "Vstup má nepodporovanou velikost."})
            return
        if self.headers.get_content_type() != "application/json":
            self._json(415, {"error": "Vstup musí mít formát JSON."})
            return
        if not self.server.analysis_lock.acquire(blocking=False):
            self._json(409, {"error": "Jedna analýza už běží. Počkej na její výsledek."})
            return
        try:
            self.connection.settimeout(25)
            payload = json.loads(self.rfile.read(int(length)))
            self.connection.settimeout(None)
            if not isinstance(payload, dict):
                raise ValueError("Vstup musí být JSON objekt.")
            url = payload.get("url", "")
            text = payload.get("text", "")
            if not isinstance(url, str) or not isinstance(text, str):
                raise ValueError("Adresa i poznámky musí být text.")
            report, markdown = run_analysis(
                url.strip(), text, _input_files(payload.get("files", [])),
                payload.get("archive") is True, payload.get("seconds", 0),
            )
            result = {"report": report.data, "markdown": markdown}
            if report.archive_files:
                result["archive"] = base64.b64encode(report.zip_bytes(markdown)).decode("ascii")
            self._json(200, result)
        except (json.JSONDecodeError, UnicodeError, TimeoutError, RecursionError):
            self._json(400, {"error": "Vstup se nepodařilo přečíst."})
        except ValueError as error:
            self._json(400, {"error": str(error)})
        except OSError:
            self._json(500, {"error": "Při analýze nastala chyba vstupu, prohlížeče nebo souborového systému."})
        finally:
            self.server.analysis_lock.release()


def serve(open_browser=True):
    with LocalServer() as server:
        print(f"Rozbor webu běží na {server.origin}", flush=True)
        print("Okno příkazové řádky nech otevřené. Ctrl+C aplikaci ukončí.", flush=True)
        if open_browser:
            threading.Thread(target=webbrowser.open, args=(server.origin,), daemon=True).start()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


def run_cli(args):
    files = []
    size = 0
    if len(args.file) > MAX_FILES:
        raise ValueError("Jedna analýza přijme až 6 souborů.")
    for path in args.file:
        if path.stat().st_size + size > FILE_LIMIT:
            raise ValueError("Přílohy mají celkem více než 64 MiB.")
        with path.open("rb") as file:
            data = file.read(FILE_LIMIT - size + 1)
        size += len(data)
        if size > FILE_LIMIT:
            raise ValueError("Přílohy mají celkem více než 64 MiB.")
        files.append((path.name, data))
    if args.window:
        print(f"Chromium otevře nové okno pro ruční záznam do {args.window} sekund.", flush=True)
    report, markdown = run_analysis(args.url, args.text, files, args.archive, args.window)
    output = args.out or Path(datetime.now().strftime("rozbor-%Y%m%d-%H%M%S.zip"))
    with output.open("xb") as file:
        file.write(report.zip_bytes(markdown))
    print(f"Výsledek je v {output.resolve()}")


def main():
    parser = argparse.ArgumentParser(description="Rozbor URL, HAR, screenshotů a klientských souborů.")
    commands = parser.add_subparsers(dest="command")
    web = commands.add_parser("web", help="Otevře místní webové rozhraní.")
    web.add_argument("--no-open", action="store_true", help="Vypíše adresu pro ruční otevření.")
    cli = commands.add_parser("analyze", help="Vytvoří ZIP s reportem z příkazové řádky.")
    cli.add_argument("--url", default="")
    cli.add_argument("--file", type=Path, action="append", default=[], help="Lze zadat vícekrát.")
    cli.add_argument("--text", default="")
    cli.add_argument("--window", type=int, choices=sorted(INTERACTIVE_SECONDS), default=0)
    cli.add_argument("--archive", action="store_true", help="Přibalí doručené JS soubory a zdrojové mapy.")
    cli.add_argument("--out", type=Path, help="Cesta k novému výstupnímu ZIPu.")
    args = parser.parse_args()
    if args.command == "analyze":
        try:
            run_cli(args)
        except (OSError, ValueError) as error:
            sys.exit(str(error))
    else:
        serve(open_browser=not getattr(args, "no_open", False))


if __name__ == "__main__":
    if sys.argv[1:] == ["--capture-worker"]:
        loaded_report, loaded_url, loaded_seconds = pickle.load(sys.stdin.buffer)
        capture_url(loaded_report, loaded_url, loaded_seconds)
        pickle.dump(loaded_report, sys.stdout.buffer)
    else:
        main()
