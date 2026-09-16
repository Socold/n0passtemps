"""A recording HTTP server on loopback, shared by the test modules.

Every test talks to a real socket so that what is asserted is what urllib puts
on the wire (the request target before any decoding, the headers as sent), not
what a mock was told to expect. Nothing leaves the machine.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union

# A proxy configured in the environment must not capture loopback traffic.
os.environ["no_proxy"] = "*"
os.environ["NO_PROXY"] = "*"

Reply = Tuple[int, Mapping[str, str], bytes]


@dataclass
class Recorded:
    method: str
    target: str
    headers: Dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


def json_reply(
    status: int, document: Any, headers: Optional[Mapping[str, str]] = None
) -> Reply:
    merged = {"Content-Type": "application/json; charset=utf-8"}
    merged.update(headers or {})
    return status, merged, json.dumps(document).encode("utf-8")


def problem_reply(
    status: int,
    slug: str,
    title: str = "refused",
    headers: Optional[Mapping[str, str]] = None,
    **members: Any,
) -> Reply:
    document = {
        "type": "urn:n0passtemps:error:" + slug,
        "title": title,
        "status": status,
    }
    document.update(members)
    merged = {"Content-Type": "application/problem+json; charset=utf-8"}
    merged.update(headers or {})
    return status, merged, json.dumps(document).encode("utf-8")


class RecordingServer:
    """Serves whatever ``reply`` says and remembers every request it saw."""

    def __init__(self) -> None:
        self.requests: List[Recorded] = []
        self.reply: Union[Reply, Callable[[Recorded], Reply]] = json_reply(200, {})
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def _serve(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                recorded = Recorded(
                    method=self.command,
                    target=self.path,
                    headers={k.lower(): v for k, v in self.headers.items()},
                    body=self.rfile.read(length) if length else b"",
                )
                owner.requests.append(recorded)
                reply = owner.reply(recorded) if callable(owner.reply) else owner.reply
                status, headers, body = reply
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    # The client gave up first, which the timeout test wants.
                    pass

            do_GET = do_POST = do_PUT = do_DELETE = _serve

            def log_message(self, format: str, *args: Any) -> None:
                pass

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._httpd.daemon_threads = True
        self.port = self._httpd.server_address[1]
        self.url = "http://127.0.0.1:" + str(self.port)
        # The short poll keeps shutdown() from costing half a second per test.
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        self._thread.start()

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


def closed_port() -> int:
    """Return a loopback port that nothing is listening on."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port
