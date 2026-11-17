import base64
import binascii
import hashlib
import io
import json
import re
import zipfile
from datetime import datetime, timezone
from html import escape
from html.parser import HTMLParser
from pathlib import PurePosixPath
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit


FILE_LIMIT = 64 * 1024 * 1024
CODE_LIMIT = 4 * 1024 * 1024
BODY_LIMIT = 512 * 1024
ENTRY_LIMIT = 3500
ARCHIVE_LIMIT = 36 * 1024 * 1024
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif", ".tiff"}
TEXT_EXTENSIONS = {
    ".txt", ".md", ".csv", ".har", ".json", ".html", ".htm",
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".map", ".css", ".log",
}
HTTP_TOKEN = re.compile(r"[A-Za-z]{3,16}\Z")
FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_ -]{0,62}\Z")
OPERATION = re.compile(r"[_A-Za-z][_0-9A-Za-z]{0,79}\Z")
GRAPHQL_OPERATION = re.compile(r"\b(?:query|mutation|subscription)\s+([_A-Za-z][_0-9A-Za-z]{0,79})\b")
API_PATH = re.compile(
    r"(?i)(?:/api(?:/|$)|/graphql(?:/|$)|/rest/v[0-9]+(?:/|$)|"
    r"/functions/v[0-9]+(?:/|$)|/rpc(?:/|$)|/(?:v\d+(?:beta)?)/(?:chat|messages|models|responses|embeddings)(?:/|$))"
)
URL_IN_TEXT = re.compile(r"""https?://[^\s"'<>\\`]{4,2048}""", re.I)
API_LITERAL = re.compile(
    r"""(?P<quote>["'\x60])(?P<url>(?:https?://[^/\s"'<>\\\x60]{1,250})?"""
    r"""/(?:api(?:/|\b)|graphql(?:/|\b)|rest/v\d+|functions/v\d+|rpc/|"""
    r"""v\d+(?:beta)?/(?:chat|messages|models|responses|embeddings))"""
    r"""[^"'\\\s<>\x60]{0,500})(?P=quote)""",
    re.I,
)
HTTP_CALL = re.compile(
    r"""(?P<call>fetch|axios\.(?:get|post|put|patch|delete|head|options))\s*\(\s*"""
    r"""(?P<quote>["'\x60])(?P<url>https?://[^"'\s\\<>\x60]{1,1000}|/[^/"'\s\\<>\x60][^"'\s\\<>\x60]{0,999})(?P=quote)"""
)
METHOD_OPTION = re.compile(r"""\s*,\s*\{\s*(?:["']?method["']?)\s*:\s*["']([A-Za-z]{3,16})["']""")
SOURCE_MAP = re.compile(rb"(?:/[/*][#@])\s*sourceMappingURL\s*=\s*([^\s'\"<>]{1,2048})")
STATUS_LABELS = {
    401: "HTTP 401 · vyžaduje ověření identity",
    402: "HTTP 402 · Payment Required",
    403: "HTTP 403 · server požadavek odmítl",
    429: "HTTP 429 · server hlásí příliš mnoho požadavků",
}
SERVICE_CODES = {
    "PAYMENT_REQUIRED", "UPGRADE_REQUIRED", "SUBSCRIPTION_REQUIRED", "PLAN_LIMIT_REACHED",
    "INSUFFICIENT_CREDITS", "INSUFFICIENT_QUOTA", "QUOTA_EXCEEDED", "RATE_LIMIT_EXCEEDED",
    "PREMIUM_REQUIRED", "CREDIT_LIMIT_EXCEEDED",
}
STACK_MARKERS = {
    "Next.js": re.compile(r"/_next/|__NEXT_DATA__|__next_f\b"),
    "Nuxt": re.compile(r"/_nuxt/|__NUXT_DATA__|__NUXT__"),
    "SvelteKit": re.compile(r"@sveltejs/kit|/_app/immutable/"),
    "Remix": re.compile(r"__remixContext|@remix-run/"),
    "React": re.compile(r"""react-dom(?:/|@|["'])|\b__REACT_DEVTOOLS_GLOBAL_HOOK__\b"""),
    "Angular": re.compile(r"""ng-version\s*=|@angular/core"""),
    "Vue": re.compile(r"""data-v-app|@vue/runtime-(?:dom|core)"""),
    "Supabase SDK": re.compile(r"@supabase/supabase-js"),
    "Firebase SDK": re.compile(r"@firebase/(?:app|firestore|auth)"),
}
HOST_MARKERS = {
    "supabase.co": "Supabase", "supabase.com": "Supabase",
    "firebaseio.com": "Firebase Realtime Database", "firebasedatabase.app": "Firebase Realtime Database",
    "firestore.googleapis.com": "Cloud Firestore", "identitytoolkit.googleapis.com": "Google Identity Toolkit",
    "api.openai.com": "OpenAI API", "api.anthropic.com": "Anthropic API",
    "generativelanguage.googleapis.com": "Google Gemini API", "openrouter.ai": "OpenRouter",
    "api.stripe.com": "Stripe API", "js.stripe.com": "Stripe.js",
    "vercel.app": "Vercel", "pages.dev": "Cloudflare Pages",
}
FEATURES = {
    "Chat a konverzace": r"\b(?:chat|chats|conversation(?:s)?|konverzac\w*|new chat)\b",
    "Volba modelu": r"\b(?:model selector|select model|choose model|model picker|rychlý model|vybrat model|výběr modelu|models|modely)\b",
    "Nahrání souborů": r"\b(?:upload(?:s)?|attachments?|attach files?|příloh\w*|nahrát soubory?|přidat soubory?)\b",
    "Tvorba obrázků": r"\b(?:generate images?|create images?|image generation|text to image|generovat obráz\w*|vytvořit obráz\w*|tvorba obrázků)\b",
    "Vyhledávání na webu": r"\b(?:web search|browse the web|search the web|vyhledat na webu|hledat na webu|prohledat web)\b",
    "Hlas a přepis": r"\b(?:voice mode|voice chat|transcrib\w*|transcription|hlasový režim|hlasový chat|přepis|diktování)\b",
    "Historie": r"\b(?:chat history|conversation history|historie(?: chatů| konverzací)?)\b",
    "Integrace a konektory": r"\b(?:connectors?|integrations?|konektor\w*|integrace)\b",
    "Předplatné a kredity": r"\b(?:upgrade|subscription|billing|plans|credits|pricing|paywall|předplatn\w*|ceník|kredit\w*)\b",
}
FEATURES = {label: re.compile(pattern, re.I) for label, pattern in FEATURES.items()}


def object_or_empty(value):
    return value if isinstance(value, dict) else {}


def list_or_empty(value):
    return value if isinstance(value, list) else []


def json_value(value, limit=BODY_LIMIT):
    if not isinstance(value, (str, bytes)) or len(value) > limit:
        return None
    try:
        return json.loads(value)
    except (ValueError, RecursionError):
        return None


def visible_text(value, limit=140):
    text = " ".join(value.split())
    text = URL_IN_TEXT.sub(lambda match: public_url(match[0]) or "[odkaz]", text)
    text = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[e-mail]", text)
    text = re.sub(r"\b(?:sk-[\w-]{12,}|eyJ[\w.-]{16,}|Bearer\s+[\w.-]{8,})\b", "[token]", text, flags=re.I)
    return text[:limit]


def source_name(value):
    return visible_text(re.split(r"[/\\]", str(value))[-1], 100) or "vstup"


def safe_path(path):
    parts = []
    for part in path[:2048].split("/")[:36]:
        decoded = unquote(part)
        if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", decoded, re.I):
            part = "{id}"
        elif "@" in decoded or (len(decoded) > 38 and re.fullmatch(r"[\w%.-]+", decoded) and "." not in decoded):
            part = "{hodnota}"
        elif decoded.startswith(("sk-", "eyJ")) and len(decoded) > 16:
            part = "{token}"
        parts.append("".join(char for char in part if char.isprintable())[:220])
    return "/".join(parts) or "/"


def public_url(value, base=None):
    if not isinstance(value, str) or not value or len(value) > 8192:
        return ""
    if value.startswith("/") and not value.startswith("//") and base is None:
        return safe_path(value.split("?", 1)[0].split("#", 1)[0])
    try:
        url = urlsplit(urljoin(base, value) if base else value)
        if url.scheme.lower() not in {"https", "http", "wss", "ws"} or not url.hostname:
            return ""
        host = url.hostname.lower()
        if not re.fullmatch(r"[\w.:%-]+", host):
            return ""
        if ":" in host:
            host = "[" + host + "]"
        port = f":{url.port}" if url.port is not None else ""
    except ValueError:
        return ""
    return f"{url.scheme.lower()}://{host}{port}{safe_path(url.path)}"


def query_fields(url):
    try:
        query = urlsplit(url).query
        pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=80)
    except ValueError:
        return [], []
    return (
        sorted({name for name, _ in pairs if FIELD.fullmatch(name)}),
        [value for name, value in pairs if name == "operationName" and OPERATION.fullmatch(value)],
    )


def fields(value, depth=1):
    if isinstance(value, list):
        return ["[]"]
    if not isinstance(value, dict):
        return []
    result = []
    for key in value:
        if len(result) >= 30:
            break
        if not FIELD.fullmatch(key):
            continue
        result.append(key)
        if depth:
            sample = value[key]
            path = key
            if isinstance(sample, list):
                path += "[]"
                sample = next((item for item in sample[:5] if isinstance(item, dict)), None)
            result.extend(f"{path}.{name}" for name in fields(sample, depth=0) if name != "[]")
    return result[:32]


def graphql_operations(value):
    operations = []
    for item in value[:12] if isinstance(value, list) else [value]:
        item = object_or_empty(item)
        name = item.get("operationName")
        if isinstance(name, str) and OPERATION.fullmatch(name):
            operations.append(name)
        elif isinstance(item.get("query"), str):
            operations.extend(GRAPHQL_OPERATION.findall(item["query"][:18000])[:12])
    return operations


def service_codes(value):
    value = object_or_empty(value)
    errors = [value, object_or_empty(value.get("error")), *list_or_empty(value.get("errors"))[:10]]
    hits = set()
    for error in errors:
        error = object_or_empty(error)
        for node in (error, object_or_empty(error.get("extensions"))):
            for field in ("code", "type", "error"):
                code = node.get(field)
                if isinstance(code, str) and code.upper() in SERVICE_CODES:
                    hits.add(code.upper())
    return sorted(hits)


def headers_from_har(value):
    result = {}
    for item in list_or_empty(value)[:200]:
        item = object_or_empty(item)
        if isinstance(item.get("name"), str) and isinstance(item.get("value"), str):
            result[item["name"].lower()] = item["value"]
    return result


def text_from_har(content, limit):
    text = content.get("text")
    if not isinstance(text, str) or len(text) > limit * 2:
        return None
    if str(content.get("encoding", "")).lower() == "base64":
        try:
            payload = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            return None
        return payload if len(payload) <= limit else None
    payload = text.encode("utf-8", errors="replace")
    return payload if len(payload) <= limit else None


def is_api(url, resource, mime):
    path = urlsplit(url).path.lower()
    if resource in {"script", "stylesheet", "image", "font", "media", "document"}:
        return False
    return (
        resource in {"xhr", "fetch", "eventsource", "websocket"}
        or mime.startswith("text/event-stream")
        or (("json" in mime or API_PATH.search(path)) and not path.endswith((".map", ".js", ".css", ".html")))
    )


def map_reference(data, headers):
    if headers.get("sourcemap") or headers.get("x-sourcemap"):
        return headers.get("sourcemap") or headers["x-sourcemap"]
    matches = list(SOURCE_MAP.finditer(data[-12000:]))
    return matches[-1][1].decode("utf-8", errors="replace") if matches else ""


class Report:
    def __init__(self, archive_code=False):
        self.data = {
            "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "sources": [],
            "observed": [],
            "access": [],
            "features": [],
            "technologies": [],
            "references": [],
            "client_files": [],
            "ocr": [],
            "notes": [],
        }
        self._groups = {}
        self._seen = {}
        self.archive_code = archive_code
        self.archive_files = {}
        self.archive_size = 0
        self.map_scan_bytes = 0

    def source(self, kind, label):
        item = {"id": f"S{len(self.data['sources']) + 1}", "kind": kind, "label": label, "details": []}
        self.data["sources"].append(item)
        return item

    def note(self, message, source=None):
        notes = source["details"] if source else self.data["notes"]
        if message not in notes:
            notes.append(message)

    def hint(self, section, label, detail, evidence):
        key = section, label, detail
        if key not in self._seen:
            if len(self.data[section]) >= (180 if section == "references" else 100):
                self.note(f"Sekce {section} dosáhla limitu počtu položek.")
                return
            self._seen[key] = {"label": label, "detail": detail, "evidence": []}
            self.data[section].append(self._seen[key])
        items = self._seen[key]["evidence"]
        if evidence not in items and len(items) < 8:
            items.append(evidence)

    def text_features(self, label, evidence, kind):
        label = visible_text(label)
        for feature, pattern in FEATURES.items():
            if pattern.search(label):
                self.hint("features", feature, f"{kind} · {label}", evidence)

    def technology(self, url, headers, evidence):
        host = urlsplit(url).hostname or ""
        for suffix, name in HOST_MARKERS.items():
            if host == suffix or host.endswith("." + suffix):
                self.hint("technologies", name, f"Doména {host}", evidence)
        if "cf-ray" in headers or headers.get("server", "").lower() == "cloudflare":
            self.hint("technologies", "Cloudflare", "HTTP hlavička serveru nebo CF-Ray", evidence)
        if "x-vercel-id" in headers:
            self.hint("technologies", "Vercel", "HTTP hlavička X-Vercel-Id", evidence)
        signature = headers.get("x-powered-by", "").strip().lower()
        for framework in ("express", "next.js", "asp.net", "php"):
            if signature == framework or signature.startswith(framework + "/"):
                self.hint("technologies", framework, "HTTP hlavička X-Powered-By", evidence)

    def observe(self, raw_url, method, status, resource, headers, request_body, response_body, evidence, failure=""):
        url = public_url(raw_url)
        if not url:
            return
        mime = headers.get("content-type", "").partition(";")[0].strip().lower()
        status = status if isinstance(status, int) and 100 <= status <= 599 else None
        method = method.upper() if isinstance(method, str) and HTTP_TOKEN.fullmatch(method) else "?"
        self.technology(url, headers, evidence)
        endpoint = is_api(url, resource, mime)
        if resource == "document" or endpoint:
            if status in STATUS_LABELS:
                self.hint("access", STATUS_LABELS[status], f"{method} {url}", evidence)
            if endpoint:
                for code in service_codes(response_body):
                    self.hint("access", f"Kód v odpovědi · {code}", f"{method} {url}", evidence)
        if not endpoint:
            return
        fields_in_url, named_operations = query_fields(raw_url)
        if named_operations or "graphql" in urlsplit(url).path.lower() or "graphql" in mime:
            named_operations.extend(graphql_operations(request_body))
        elif isinstance(request_body, (dict, list)):
            samples = request_body[:12] if isinstance(request_body, list) else [request_body]
            if any(isinstance(item, dict) and ("operationName" in item or isinstance(item.get("query"), str)
                   and GRAPHQL_OPERATION.search(item["query"][:18000])) for item in samples):
                named_operations.extend(graphql_operations(request_body))
        transport = resource or "HTTP"
        if mime.startswith("text/event-stream") or resource == "eventsource":
            transport = "SSE"
        elif mime in {"application/x-ndjson", "application/ndjson", "application/json-seq"}:
            transport = "NDJSON / JSON stream"
        elif resource == "websocket":
            transport = "WebSocket"
        elif named_operations or "graphql" in mime or re.search(r"/graphql(?:/|$)", urlsplit(url).path, re.I):
            transport = "GraphQL"
        key = method, url
        if key not in self._groups:
            if len(self._groups) >= 550:
                self.note("Přehled sítě dosáhl limitu 550 skupin podle metody a URL.")
                return
            self._groups[key] = {
                "method": method, "url": url, "count": 0, "statuses": [], "transports": [],
                "query_fields": [], "request_fields": [], "response_fields": [], "operations": [],
                "failures": [], "evidence": [],
            }
        record = self._groups[key]
        record["count"] += 1
        evidence_text = " · ".join(filter(None, [evidence, str(status) if status else "", transport]))
        for field, items in {
            "statuses": [status] if status else [], "transports": [transport],
            "query_fields": fields_in_url, "request_fields": fields(request_body),
            "response_fields": fields(response_body), "operations": named_operations,
            "failures": [failure] if failure else [], "evidence": [evidence_text],
        }.items():
            cap = 8 if field == "evidence" else 32
            record[field] = list(dict.fromkeys(record[field] + items))[:cap]
        self.text_features(urlsplit(url).path.replace("-", " ").replace("_", " "), evidence, "Cesta požadavku")

    def code(self, label, body, evidence, base=None, kind="javascript"):
        if len(self.data["client_files"]) >= 110:
            self.note("Přehled klientských souborů dosáhl limitu 110 položek.")
            return
        digest = hashlib.sha256(body).hexdigest()
        entry = {"name": label, "kind": kind, "bytes": len(body), "sha256": digest, "evidence": evidence}
        self.data["client_files"].append(entry)
        if self.archive_code and self.archive_size + len(body) <= ARCHIVE_LIMIT:
            filename = re.sub(r"[^a-zA-Z0-9._-]", "_", source_name(urlsplit(label).path))[:90].strip(".")
            filename = filename or ("source.map" if kind == "source map" else "script.js")
            archive_path = f"client/{len(self.data['client_files']):03d}-{filename}"
            self.archive_files[archive_path] = body
            self.archive_size += len(body)
            entry["archive_path"] = archive_path
        elif self.archive_code:
            self.note("Archiv klientských souborů dosáhl limitu 36 MiB.")
        if kind == "source map":
            self.source_map(body, evidence, base, label)
        else:
            scan_code(self, body.decode("utf-8", errors="replace"), f"{evidence} · {label}", base)

    def source_map(self, body, evidence, base, label):
        value = object_or_empty(json_value(body, CODE_LIMIT))
        sources = list_or_empty(value.get("sources"))
        contents = list_or_empty(value.get("sourcesContent"))
        if value.get("version") != 3 or not sources:
            return
        self.hint("references", "Zdrojová mapa", f"{label} · {len(sources)} cest, {sum(isinstance(x, str) for x in contents)} vložených zdrojů", evidence)
        for index, (name, content) in enumerate(zip(sources, contents), 1):
            if not isinstance(content, str) or not content or len(content) > CODE_LIMIT:
                continue
            if self.map_scan_bytes + len(content) > ARCHIVE_LIMIT or index > 160:
                self.note("Analýza vložených částí zdrojových map dosáhla limitu.")
                break
            self.map_scan_bytes += len(content)
            scan_code(self, content, f"{evidence} · {label} · zdroj {index} ({source_name(name)})", base)

    def finish(self):
        self.data["observed"] = sorted(self._groups.values(), key=lambda item: (item["url"], item["method"]))
        if not self.data["observed"]:
            self.note("Pro zachycení API při konkrétní akci přidej HAR z daného scénáře nebo použij záznam v novém okně.")
        if self.data["references"]:
            self.note("Odkazy a metody nalezené v kódu nebo dokumentaci popisují kandidáty. Síťový záznam potvrzuje, které požadavky proběhly.")

    def zip_bytes(self, markdown):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=5) as archive:
            archive.writestr("report.md", markdown)
            archive.writestr("report.json", json.dumps(self.data, ensure_ascii=False, indent=2))
            for filename, body in self.archive_files.items():
                archive.writestr(filename, body)
        return output.getvalue()


def scan_code(report, text, evidence, base=None):
    text = text[:CODE_LIMIT]
    for name, pattern in STACK_MARKERS.items():
        match = pattern.search(text)
        if match:
            line = text.count("\n", 0, match.start()) + 1
            report.hint("technologies", name, f"Znak v kódu · {match.group()}", f"{evidence}:{line}")
    hits = set()
    for pattern, label in [(HTTP_CALL, "Volání v kódu"), (API_LITERAL, "Odkaz v kódu")]:
        for match in pattern.finditer(text):
            if len(hits) >= 70:
                break
            raw = match["url"]
            url = public_url(raw, base)
            if not url:
                continue
            method = ""
            if label == "Volání v kódu":
                call = match["call"]
                option = METHOD_OPTION.match(text, match.end())
                method = call.partition(".")[2].upper() or (option[1].upper() if option else "fetch")
            key = (url, method)
            if key in hits or (label == "Odkaz v kódu" and any(path == url for path, _ in hits)):
                continue
            hits.add(key)
            line = text.count("\n", 0, match.start()) + 1
            column = match.start() - text.rfind("\n", 0, match.start())
            report.hint("references", label, " ".join(filter(None, [method, url])), f"{evidence}:{line}:{column}")
            report.technology(url, {}, f"{evidence}:{line}:{column}")


class VisibleHTML(HTMLParser):
    def __init__(self, report, evidence, base):
        super().__init__(convert_charrefs=True)
        self.report, self.evidence, self.base = report, evidence, base
        self.collectors = []
        self.labels = 0

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if tag in {"title", "h1", "h2", "h3", "button", "a", "summary", "script"} and len(self.collectors) < 12:
            self.collectors.append((tag, self.getpos()[0], []))
        label = attributes.get("aria-label")
        if isinstance(label, str) and tag in {"a", "button", "input", "select"}:
            self.report.text_features(label, f"{self.evidence}:{self.getpos()[0]}", "HTML")

    def handle_data(self, data):
        for _, _, parts in self.collectors:
            if len(parts) < 200:
                parts.append(data)

    def handle_endtag(self, tag):
        for index in range(len(self.collectors) - 1, -1, -1):
            opened, line, parts = self.collectors[index]
            if opened != tag:
                continue
            del self.collectors[index:]
            if tag == "script":
                scan_code(self.report, "".join(parts), f"{self.evidence} · inline <script> řádek {line}", self.base)
            elif self.labels < 250:
                self.report.text_features(" ".join(parts), f"{self.evidence}:{line}", "HTML")
                self.labels += 1
            break


def scan_text(report, text, source, base=None, html=False):
    evidence = source["id"]
    if html:
        parser = VisibleHTML(report, evidence, base)
        parser.feed(text)
        parser.close()
    else:
        for number, line in enumerate(text.splitlines()[:300], 1):
            if len(line) <= 280:
                report.text_features(line, f"{evidence}:{number}", "Dodaný text")
    scan_code(report, text, evidence, base)
    if not html:
        for index, match in enumerate(URL_IN_TEXT.finditer(text), 1):
            if index > 80:
                break
            url = public_url(match[0].rstrip(".,);]"))
            if url:
                line = text.count("\n", 0, match.start()) + 1
                report.hint("references", "Odkaz ve vstupu", url, f"{evidence}:{line}")


def parse_openapi(report, value, source):
    paths = object_or_empty(value.get("paths"))
    servers = list_or_empty(value.get("servers"))
    base = object_or_empty(servers[0]).get("url") if servers else None
    if not isinstance(base, str) or "{" in base or not public_url(base).startswith(("https://", "http://")):
        base = None
    evidence = source["id"]
    for path in list(paths)[:180]:
        url = public_url(base.rstrip("/") + path if base and path.startswith("/") else path)
        if not url or not path.startswith("/"):
            continue
        for method in object_or_empty(paths[path]):
            if method.lower() in {"get", "put", "post", "delete", "options", "head", "patch", "trace"}:
                report.hint("references", "Dokumentované volání", f"{method.upper()} {url}", f"{evidence} · paths")
    report.note(f"OpenAPI/Swagger · {len(paths)} zdokumentovaných cest.", source)


def parse_har(report, entries, source):
    document_ids = list(dict.fromkeys(
        item.get("pageref") for item in entries[:ENTRY_LIMIT] if isinstance(item, dict)
        and isinstance(item.get("pageref"), str) and item.get("_resourceType") == "document"
    ))
    if document_ids:
        report.note(f"Dokumenty v HAR · {len(document_ids)} stránek podle pageref.", source)
    report.note(f"Zpracované položky HAR · {min(len(entries), ENTRY_LIMIT)} z {len(entries)}.", source)
    missing = 0
    for number, item in enumerate(entries[:ENTRY_LIMIT], 1):
        item = object_or_empty(item)
        request = object_or_empty(item.get("request"))
        response = object_or_empty(item.get("response"))
        content = object_or_empty(response.get("content"))
        raw_url = request.get("url")
        url = public_url(raw_url)
        if not url.startswith(("http://", "https://", "ws://", "wss://")):
            continue
        headers = headers_from_har(response.get("headers"))
        if not headers.get("content-type") and isinstance(content.get("mimeType"), str):
            headers["content-type"] = content["mimeType"]
        mime = headers.get("content-type", "").lower()
        resource = item.get("_resourceType", "")
        resource = resource.lower() if isinstance(resource, str) else ""
        if url.startswith(("ws://", "wss://")):
            resource = "websocket"
        evidence = f"{source['id']} · HAR #{number}"
        post = object_or_empty(request.get("postData"))
        request_body = json_value(post.get("text"))
        if request_body is None:
            request_body = {
                param["name"]: None for param in list_or_empty(post.get("params"))[:80]
                if isinstance(param, dict) and isinstance(param.get("name"), str)
            }
        if mime.startswith("text/html"):
            resource = resource or "document"
        is_js = resource == "script" or ("javascript" in mime and resource not in {"xhr", "fetch"})
        path = urlsplit(url).path
        is_map = path.endswith(".map")
        body = text_from_har(content, CODE_LIMIT if is_js or is_map else BODY_LIMIT)
        if is_js or is_map:
            if body is not None:
                report.code(url, body, evidence, kind="source map" if is_map else "javascript")
                if is_js:
                    reference = public_url(map_reference(body, headers), raw_url)
                    if reference:
                        report.hint("references", "Deklarovaná zdrojová mapa", reference, evidence)
            else:
                missing += 1
        report.observe(raw_url, request.get("method"), response.get("status"), resource, headers,
                       request_body, json_value(body), evidence)
    if missing:
        report.note(f"Tělo vynecháno nebo nad limitem u {missing} položek s JavaScriptem či mapou.", source)


def inspect_input(report, filename, data, read_image):
    filename = source_name(filename)
    suffix = PurePosixPath(filename).suffix.lower()
    if suffix in IMAGE_EXTENSIONS:
        source = report.source("screenshot", filename)
        lines, note = read_image(data, suffix)
        report.note(note, source)
        for index, line in enumerate(lines[:100], 1):
            evidence = f"{source['id']} · OCR řádek {index}"
            report.data["ocr"].append({"text": visible_text(line, 220), "evidence": evidence})
            report.text_features(line, evidence, "OCR")
            for match in URL_IN_TEXT.finditer(line):
                url = public_url(match[0].rstrip(".,);]"))
                if url:
                    report.hint("references", "Odkaz ze screenshotu", url, evidence)
        return
    source = report.source("soubor" if suffix else "text", filename)
    if suffix and suffix not in TEXT_EXTENSIONS:
        report.note("Podporované vstupy zahrnují HAR, běžné screenshoty, text a zdrojové soubory.", source)
        return
    text = data.decode("utf-8-sig", errors="replace")
    if suffix in {".har", ".json", ".map", ""}:
        value = object_or_empty(json_value(text, FILE_LIMIT))
        log = object_or_empty(value.get("log"))
        if isinstance(log.get("entries"), list):
            source["kind"] = "HAR"
            parse_har(report, log["entries"], source)
            return
        if suffix == ".har":
            report.note("Chybí JSON pole log.entries. Vyexportuj HAR z panelu Síť v prohlížeči.", source)
            return
        if ("openapi" in value or "swagger" in value) and isinstance(value.get("paths"), dict):
            source["kind"] = "OpenAPI"
            parse_openapi(report, value, source)
            return
        if suffix == ".map":
            if len(data) <= CODE_LIMIT:
                report.code(filename, data, source["id"], kind="source map")
            else:
                report.note("Zdrojová mapa překročila limit 4 MiB.", source)
            return
    if suffix in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"} and len(data) <= CODE_LIMIT:
        report.code(filename, data, source["id"])
    else:
        scan_text(report, text[:CODE_LIMIT], source, html=suffix in {".html", ".htm"})
        if len(text) > CODE_LIMIT:
            report.note("Analýza textu skončila na limitu velikosti zdrojového souboru.", source)


def _markdown(text):
    return escape(str(text).replace("\n", " ").replace("\r", " "), quote=False).translate(
        str.maketrans({char: "\\" + char for char in "\\|*_[\x60]#"})
    )


def markdown_report(data):
    lines = ["# Rozbor webu", "", f"Vytvořeno {data['generated_at']}", "", "## Pokrytí", ""]
    for source in data["sources"]:
        lines.append(f"- **{source['id']} · {_markdown(source['kind'])}** · {_markdown(source['label'])}")
        lines.extend(f"  - {_markdown(note)}" for note in source["details"])
    lines.extend(["", "## Pozorovaná síťová volání", ""])
    if not data["observed"]:
        lines.append("V dodaných podkladech nejsou zachycená API volání.")
    else:
        for row in data["observed"]:
            status = ", ".join(map(str, row["statuses"])) or "bez doloženého HTTP stavu"
            lines.append(f"- **{_markdown(row['method'])} {_markdown(row['url'])}** · {row['count']}× · {status}")
            for key, title in [
                ("transports", "Přenos"), ("operations", "Operace"), ("query_fields", "Parametry URL"),
                ("request_fields", "Pole požadavku"), ("response_fields", "Pole odpovědi"),
                ("failures", "Síťová hlášení"), ("evidence", "Důkaz"),
            ]:
                if row[key]:
                    values = ", ".join(_markdown(item) for item in row[key])
                    lines.append(f"  - {title} · {values}")
    sections = {
        "access": "Stavy přístupu a účtování",
        "features": "Stopy funkcí",
        "technologies": "Technologické stopy",
        "references": "Odkazy v kódu, dokumentaci a dalších vstupech",
    }
    for key, title in sections.items():
        if data[key]:
            lines.extend(["", f"## {title}", ""])
            for item in data[key]:
                evidence = " · ".join(_markdown(value) for value in item["evidence"])
                lines.append(f"- **{_markdown(item['label'])}** · {_markdown(item['detail'])} · {evidence}")
    if data["client_files"]:
        lines.extend(["", "## Klientské soubory", ""])
        for item in data["client_files"]:
            lines.append(f"- {_markdown(item['name'])} · {item['bytes']} B · {_markdown(item['evidence'])}")
            if item.get("archive_path"):
                lines.append(f"  - Archiv · {_markdown(item['archive_path'])}")
    if data["ocr"]:
        lines.extend(["", "## Text ze screenshotů", ""])
        lines.extend(f"- {_markdown(row['evidence'])} · {_markdown(row['text'])}" for row in data["ocr"])
    lines.extend(["", "## Rozsah závěrů", "",
                  "Serverový kód, konfigurace databáze a kroky za přístupovým omezením vyžadují odpovídající přístup nebo dodané podklady."])
    if data["notes"]:
        lines.extend(["", *[f"- {_markdown(note)}" for note in data["notes"]]])
    return "\n".join(lines) + "\n"
