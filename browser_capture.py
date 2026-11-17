from concurrent.futures import ThreadPoolExecutor
from pathlib import PurePosixPath
from time import monotonic
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from inspector import (
    ARCHIVE_LIMIT, BODY_LIMIT, CODE_LIMIT, is_api, json_value, map_reference, public_url,
    scan_text, visible_text,
)


MAX_REQUESTS = 1500
MAX_MAPS = 8
AUTO_SECONDS = 5
INTERACTIVE_SECONDS = {30, 60, 120}

VISIBLE_LABELS = r"""
() => {
  const nodes = document.querySelectorAll(
    'title,h1,h2,h3,button,a,summary,[role="button"],[role="menuitem"],[role="tab"],input[type="file"]'
  );
  const labels = new Set();
  for (const node of nodes) {
    if (labels.size >= 220) break;
    if (node.tagName !== 'TITLE' && (!node.getClientRects().length ||
        ['hidden', 'collapse'].includes(getComputedStyle(node).visibility))) continue;
    const label = node.getAttribute('aria-label') || node.getAttribute('title') ||
        (node.matches('input[type="file"]') ? 'Upload file' : node.textContent || '');
    const text = label.replace(/\s+/g, ' ').trim();
    if (text && text.length <= 160) labels.add(text);
  }
  return [...labels];
}
"""


def target_url(raw):
    raw = raw.strip()
    if not raw or any(char.isspace() for char in raw) or "\\" in raw or len(raw) > 4096:
        raise ValueError("Zadej jednu platnou webovou adresu.")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        url = urlsplit(raw)
        if url.scheme not in {"http", "https"} or not public_url(raw) or url.username or url.password:
            raise ValueError
    except ValueError:
        raise ValueError("Použij adresu HTTP nebo HTTPS bez přihlašovacích údajů v adrese.") from None
    return raw


def _origin(raw_url):
    parsed = urlsplit(raw_url)
    return parsed.scheme, parsed.hostname, parsed.port or {"http": 80, "https": 443}.get(parsed.scheme)


def linked_map(raw_script_url, reference):
    if not reference or len(reference) > 2048:
        return ""
    try:
        full = urljoin(raw_script_url, reference)
        url = urlsplit(full)
        if url.scheme not in {"https", "http"} or url.username or url.password or _origin(full) != _origin(raw_script_url):
            return ""
    except ValueError:
        return ""
    return urlunsplit(url._replace(fragment=""))


class _KeepOrigin(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def retrieve_map(url):
    request = Request(url, headers={"Accept": "application/json, */*", "Accept-Encoding": "identity"})
    try:
        with build_opener(_KeepOrigin).open(request, timeout=4) as response:
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                return None, "Kódování odpovědi mimo podporovaný rozsah."
            if response.headers.get("Content-Length", "0").isdigit() and int(response.headers.get("Content-Length", "0")) > CODE_LIMIT:
                return None, "Zdrojová mapa je nad limitem 4 MiB."
            body = response.read(CODE_LIMIT + 1)
    except HTTPError as error:
        error.close()
        return None, f"Zdrojová mapa vrátila HTTP {error.code}."
    except (URLError, OSError, ValueError):
        return None, "Deklarovaný odkaz na mapu se nepodařilo načíst."
    if len(body) > CODE_LIMIT:
        return None, "Zdrojová mapa je nad limitem 4 MiB."
    value = json_value(body, CODE_LIMIT)
    if not isinstance(value, dict) or value.get("version") != 3:
        return None, "Odpověď nemá formát zdrojové mapy v3."
    return body, ""


def _launch(chromium, manual, error_class):
    for channel in (None, "chrome", "msedge"):
        try:
            return chromium.launch(channel=channel, headless=not manual, chromium_sandbox=True, timeout=6500)
        except error_class:
            continue
    return None


def _response_bytes(request, response, limit, error_class):
    try:
        length = response.headers.get("content-length", "")
        if length.isdigit() and int(length) > limit:
            return None
        if request.sizes().get("responseBodySize", 0) > limit:
            return None
        body = response.body()
        return body if len(body) <= limit else None
    except error_class:
        return None


def _request_shape(request, error_class):
    try:
        raw = request.post_data
        value = json_value(raw)
        mime = request.headers.get("content-type", "")
    except error_class:
        return None
    if value is not None or not isinstance(raw, str) or len(raw) > BODY_LIMIT:
        return value
    if mime.startswith("application/x-www-form-urlencoded"):
        try:
            return {key: None for key, _ in parse_qsl(raw, keep_blank_values=True, max_num_fields=80)}
        except ValueError:
            return None
    return None


def _network_evidence(report, source, requests, sockets, error_class):
    code_bytes = 0
    missing_scripts = 0
    link_queue = {}
    captured_maps = set()
    for request, event in requests:
        raw_url = request.url
        url = public_url(raw_url)
        if not url:
            continue
        evidence = f"{source['id']} · síť #{event['index']}"
        response = event.get("response")
        resource = request.resource_type
        headers = response.headers if response else {}
        status = response.status if response else None
        mime = headers.get("content-type", "").lower()
        path = urlsplit(url).path
        extension = PurePosixPath(path).suffix.lower()
        is_script = resource == "script" or (extension in {".js", ".mjs"} and "javascript" in mime)
        is_map = extension == ".map"
        endpoint = is_api(url, resource, mime)
        body = None
        if event.get("finished") and response and status:
            if (is_script or is_map) and 200 <= status < 300 and code_bytes < ARCHIVE_LIMIT:
                body = _response_bytes(request, response, min(CODE_LIMIT, ARCHIVE_LIMIT - code_bytes), error_class)
            elif (endpoint and "json" in mime and not any(marker in mime for marker in ("ndjson", "json-seq"))) or resource == "document":
                body = _response_bytes(request, response, BODY_LIMIT, error_class)
        if is_script or is_map:
            if body:
                code_bytes += len(body)
                report.code(url, body, evidence, kind="source map" if is_map else "javascript")
                if is_map:
                    captured_maps.add(url)
            else:
                missing_scripts += 1
        if is_script:
            reference = map_reference(body or b"", headers)
            declared_url = public_url(reference, raw_url)
            if declared_url:
                report.hint("references", "Deklarovaná zdrojová mapa", declared_url, evidence)
            allowed_url = linked_map(raw_url, reference)
            if allowed_url:
                link_queue.setdefault(allowed_url, (declared_url, evidence))
        elif resource == "document" and body and mime.startswith("text/html"):
            scan_text(report, body.decode("utf-8", errors="replace"),
                      {"id": evidence + " · HTML"}, base=raw_url, html=True)
        if resource == "document" and event.get("main_document") and status:
            report.note(f"Navigace · HTTP {status} · {url}", source)
        failure = event.get("failure", "")
        report.observe(raw_url, request.method, status, resource, headers,
                       _request_shape(request, error_class) if endpoint else None,
                       json_value(body) if endpoint else None, evidence, failure)
    seen_websockets = {public_url(request.url) for request, _ in requests if request.resource_type == "websocket"}
    for index, socket_url in enumerate(sockets, 1):
        if public_url(socket_url) not in seen_websockets:
            report.observe(socket_url, "GET", None, "websocket", {}, None, None,
                           f"{source['id']} · událost WebSocket #{index}")
    if missing_scripts:
        report.note(f"Obsah {missing_scripts} JS souborů či map chyběl, nedoběhl nebo překročil limit.", source)
    candidates = [(url, name, evidence) for url, (name, evidence) in link_queue.items() if name not in captured_maps]
    if len(candidates) > MAX_MAPS:
        report.note(f"Z {len(candidates)} deklarovaných map se zpracuje nejvýše {MAX_MAPS} ve stejném originu jako skript.", source)
    return candidates[:MAX_MAPS]


def _rendered_labels(report, context, source, error_class):
    for index, page in enumerate(context.pages[:4], 1):
        try:
            labels = page.evaluate(VISIBLE_LABELS)
        except error_class:
            continue
        page_url = public_url(page.url) or "okno bez webové adresy"
        for number, label in enumerate(labels, 1):
            report.text_features(label, f"{source['id']} · {page_url} · prvek {number}", f"Okno {index}")


def capture_url(report, raw_url, seconds=0):
    url = target_url(raw_url)
    source = report.source("URL", public_url(url))
    try:
        from playwright.sync_api import Error, sync_playwright
    except ImportError:
        report.note("Pro záznam URL nainstaluj Playwright podle README. HAR a zdrojové soubory fungují samostatně.", source)
        return
    if seconds not in INTERACTIVE_SECONDS | {0}:
        raise ValueError("Pro ruční záznam vyber 30, 60 nebo 120 sekund.")
    requests = {}
    sockets = []
    collecting = True
    skipped = 0
    candidates = []

    def start_request(request):
        nonlocal skipped
        if not collecting:
            return
        if len(requests) >= MAX_REQUESTS:
            skipped += 1
            return
        main_document = False
        if request.resource_type == "document":
            try:
                main_document = request.frame.parent_frame is None
            except Error:
                pass
        requests[request] = {"index": len(requests) + 1, "main_document": main_document}

    def on_response(response):
        if collecting and response.request in requests:
            requests[response.request]["response"] = response

    def on_finished(request):
        if collecting and request in requests:
            requests[request]["finished"] = True

    def on_failed(request):
        if collecting and request in requests:
            requests[request]["failure"] = visible_text(request.failure or "Síťová chyba", 100)

    def on_page(page):
        def on_socket(socket):
            if collecting and len(sockets) < 155:
                sockets.append(socket.url)
        page.on("websocket", on_socket)

    try:
        with sync_playwright() as manager:
            browser = _launch(manager.chromium, bool(seconds), Error)
            if not browser:
                report.note("Chromium se nepodařilo spustit. Použij HAR, případně nainstaluj Chromium podle README.", source)
                return
            context = browser.new_context(accept_downloads=False)
            context.set_default_timeout(3500)
            context.on("request", start_request)
            context.on("response", on_response)
            context.on("requestfinished", on_finished)
            context.on("requestfailed", on_failed)
            context.on("page", on_page)
            page = context.new_page()
            report.note(f"Režim · nové okno, ruční záznam do {seconds} s." if seconds else
                        f"Režim · čistá relace, načtení a dalších {AUTO_SECONDS} s.", source)
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=16000)
            except Error:
                report.note("Navigace nedoběhla do DOMContentLoaded. Přehled obsahuje dosud zachycené požadavky.", source)
            deadline = monotonic() + (seconds or AUTO_SECONDS)
            while context.pages and browser.is_connected() and monotonic() < deadline:
                try:
                    context.pages[-1].wait_for_timeout(min(300, max(1, int((deadline - monotonic()) * 1000))))
                except Error:
                    if not browser.is_connected():
                        break
            _rendered_labels(report, context, source, Error)
            collecting = False
            candidates = _network_evidence(report, source, list(requests.items()), sockets, Error)
            if browser.is_connected():
                browser.close()
    except (Error, OSError):
        report.note("Prohlížeč ukončil záznam dříve. Další zachycení stránky umožní import HAR.", source)
        if collecting:
            collecting = False
            _network_evidence(report, source, list(requests.items()), sockets, Error)
    report.note(f"Síťový záznam · {len(requests)} požadavků, {len(sockets)} událostí WebSocket.", source)
    if skipped:
        report.note(f"Limit záznamu vynechal dalších {skipped} požadavků.", source)
    if candidates:
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = executor.map(retrieve_map, (url for url, _, _ in candidates))
            for (_, name, evidence), (body, note) in zip(candidates, results):
                if body:
                    report.code(name, body, f"{evidence} · načtení deklarované mapy", kind="source map")
                else:
                    report.note(f"{name} · {note}", source)
