# The queue as a web page: one HTML file and three JSON routes, served on this machine only.

import json
import secrets
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from core.incidents import CLASSIFICATIONS
from core.store import StoreError
from meerkat import records

PAGE = Path(__file__).parent / "page.html"
HOST = "127.0.0.1"
BODY_LIMIT = 4096
TOKEN_HEADER = "X-Meerkat-Token"


def serve(runs_dir: Path, port: int) -> None:
    server = make_server(runs_dir, port)
    print(f"meerkat is on http://{HOST}:{server.server_port}  (Ctrl+C stops it)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def make_server(runs_dir: Path, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((HOST, port), _Handler)
    server.runs_dir = runs_dir
    server.lock = threading.Lock()
    server.token = secrets.token_urlsafe(32)
    server.scored = (None, None)
    return server


def _version(runs_dir: Path) -> tuple:
    files = (path for path in runs_dir.rglob("*") if path.is_file())
    return tuple(sorted((str(path), path.stat().st_mtime_ns, path.stat().st_size)
                        for path in files))


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        url = urlsplit(self.path)
        if not self._local():
            self._json(HTTPStatus.FORBIDDEN, {"error": "this page answers on this machine only"})
        elif url.path == "/":
            self._page()
        elif not self._trusted():
            self._json(HTTPStatus.FORBIDDEN, {"error": "missing or wrong token"})
        elif url.path == "/api/queue":
            self._answer(self._queue)
        elif url.path == "/api/incident":
            wanted = parse_qs(url.query).get("id", [""])[0]
            self._answer(lambda: records.incident(self.server.runs_dir, self._scores(), wanted))
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "no such page"})

    def do_POST(self) -> None:
        if not self._local() or not self._trusted():
            self._json(HTTPStatus.FORBIDDEN, {"error": "missing or wrong token"})
        elif urlsplit(self.path).path != "/api/classify":
            self._json(HTTPStatus.NOT_FOUND, {"error": "no such page"})
        else:
            self._classify()

    # a page on another site can reach this port, but it cannot send this host name or read the token
    def _local(self) -> bool:
        port = self.server.server_port
        return self.headers.get("Host") in (f"{HOST}:{port}", f"localhost:{port}")

    def _trusted(self) -> bool:
        given = self.headers.get(TOKEN_HEADER, "")
        return secrets.compare_digest(given.encode(), self.server.token.encode())

    # scoring reads every run, so it is kept until a file under the runs folder changes
    def _scores(self):
        version = _version(self.server.runs_dir)
        if self.server.scored[0] != version:
            self.server.scored = (version, records.scored(self.server.runs_dir))
        return self.server.scored[1]

    def _queue(self) -> dict:
        runs_dir = self.server.runs_dir
        return records.queue(runs_dir, self._scores(), records.settings(runs_dir))

    def _classify(self) -> None:
        try:
            size = int(self.headers.get("Content-Length", ""))
        except ValueError:
            size = -1
        if not 0 <= size <= BODY_LIMIT:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "the request body has no valid length"})
            return
        try:
            body = json.loads(self.rfile.read(size))
            incident, classification = body["incident"], body["classification"]
            comment = body.get("comment", "")
            whole = body.get("group", False)
        except (ValueError, KeyError, TypeError, AttributeError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "expected incident and classification"})
            return
        if (not isinstance(incident, str) or not isinstance(comment, str)
                or not isinstance(whole, bool) or classification not in CLASSIFICATIONS):
            self._json(HTTPStatus.BAD_REQUEST,
                       {"error": f"classification is one of {', '.join(CLASSIFICATIONS)}"})
            return
        self._answer(lambda: self._record(incident, classification, comment, whole))

    def _record(self, incident: str, classification: str, comment: str, whole: bool) -> dict:
        runs_dir, scores = self.server.runs_dir, self._scores()
        classified = records.with_group(runs_dir, scores, incident) if whole else [incident]
        records.classify(runs_dir, scores, [(one, classification) for one in classified],
                         comment)
        return {"incident": incident, "classification": classification,
                "classified": len(classified)}

    def _answer(self, build) -> None:
        try:
            with self.server.lock:
                built = build()
            self._json(HTTPStatus.OK, built)
        except StoreError as error:
            self._json(HTTPStatus.NOT_FOUND, {"error": str(error)})

    def _page(self) -> None:
        nonce = secrets.token_urlsafe(16)
        page = PAGE.read_text(encoding="utf-8")
        page = page.replace("__NONCE__", nonce).replace("__TOKEN__", self.server.token)
        self._send(HTTPStatus.OK, "text/html; charset=utf-8", page.encode(), {
            "Content-Security-Policy":
                f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                "connect-src 'self'; base-uri 'none'; form-action 'none'; "
                "frame-ancestors 'none'"})

    def _json(self, status: HTTPStatus, value: dict) -> None:
        self._send(status, "application/json", json.dumps(value).encode(), {})

    def _send(self, status: HTTPStatus, kind: str, body: bytes, headers: dict) -> None:
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        pass
