"""실행: python app.py → http://127.0.0.1:8000 (Python 3.10 이상)

외부 라이브러리 없이 브라우저 화면, 실습 API, 진단 API를 함께 제공합니다.
http.server는 이 로컬 교육 환경용입니다. 인터넷 공개 서비스용 서버가 아닙니다.
"""
import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import lab
from lessons import LESSONS
from scanner import ScanError, scan

STATIC = Path(__file__).parent / "static"
SCAN_LOCK = threading.Lock()
ASSETS = {"/": ("index.html", "text/html"), "/style.css": ("style.css", "text/css"),
          "/app.js": ("app.js", "text/javascript"), "/lab.js": ("lab.js", "text/javascript")}


class Handler(BaseHTTPRequestHandler):
    server_version = "SWWeekLab"
    sys_version = ""

    def log_message(self, *_):
        # 입력 URL, 검색어, 실습 세션을 콘솔에 남기지 않습니다.
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(8)

    def send(self, status, body, content_type="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("X-SW-Lab", "2025-v1")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def local_request(self):
        port = self.server.server_port
        allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
        # DNS rebinding이나 다른 웹사이트에서 로컬 API를 사용하는 것을 제한합니다.
        if self.headers.get("Host") not in allowed:
            self.send(403, {"message": "로컬 주소로 접속해 주세요."})
            return False
        origin = self.headers.get("Origin")
        if origin and origin not in {"http://" + host for host in allowed}:
            self.send(403, {"message": "다른 사이트에서 보낸 요청은 허용하지 않습니다."})
            return False
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            self.send(403, {"message": "실습 화면에서 직접 실행해 주세요."})
            return False
        return True

    def do_GET(self):
        if not self.local_request():
            return
        parsed = urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path in ASSETS:
            name, mime = ASSETS[path]
            self.send(200, (STATIC / name).read_bytes(), mime)
            return
        if path == "/api/config":
            self.send(200, {"base": f"http://127.0.0.1:{self.server.server_port}", "lessons": LESSONS})
            return
        parts = path.strip("/").split("/")
        if len(parts) >= 2 and parts[0] == "lab" and parts[1] in ("vulnerable", "fixed"):
            if len(parts) == 2:
                self.send(200, (STATIC / "lab.html").read_bytes(), "text/html")
                return
            if len(parts) == 3:
                params = parse_qs(parsed.query, keep_blank_values=True)
                version, action = parts[1], parts[2]
                if action == "posts":
                    status, data = lab.read_post(version, params.get("id", ["1"])[0], self.headers.get("X-Lab-Session", ""))
                elif action == "error":
                    status, data = lab.error_page(version, params.get("trigger", ["0"])[0] == "1")
                elif action == "search":
                    status, data = lab.search_products(version, params.get("q", [""])[0])
                else:
                    self.send(404, {"message": "실습 기능을 찾을 수 없습니다."})
                    return
                self.send(status, data)
                return
        self.send(404, {"message": "페이지를 찾을 수 없습니다."})

    def do_POST(self):
        if not self.local_request():
            return
        if self.path != "/api/scan":
            self.send(404, {"message": "API를 찾을 수 없습니다."})
            return
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            self.send(415, {"message": "JSON 형식으로 요청해 주세요."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                raise ValueError()
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict) or payload.get("authorized") is not True:
                self.send(400, {"message": "직접 실행한 실습 환경임을 확인해 주세요."})
                return
        except (ValueError, UnicodeError, TimeoutError):
            self.send(400, {"message": "요청 형식이 올바르지 않습니다."})
            return
        if not SCAN_LOCK.acquire(blocking=False):
            self.send(429, {"message": "진단 중입니다. 완료 후 다시 시도해 주세요."})
            return
        try:
            result = scan(payload.get("url", ""), self.server.server_port, payload.get("compare") is True)
            self.send(200, result)
        except ScanError as error:
            self.send(400, {"message": str(error)})
        except Exception:
            self.send(500, {"message": "진단을 완료하지 못했습니다. 서버를 재시작해 주세요."})
        finally:
            SCAN_LOCK.release()


def create_server(port=8000):
    # 실습용 취약 API가 다른 컴퓨터에 노출되지 않도록 loopback에만 바인딩합니다.
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main():
    parser = argparse.ArgumentParser(description="SW WEEK 웹 보안 실습 대시보드")
    parser.add_argument("--port", type=int, default=8000, help="사용할 포트 (기본 8000)")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("포트는 1~65535 범위로 입력해 주세요.")
    try:
        server = create_server(args.port)
    except OSError as error:
        print(f"서버 실행 실패: {error}\n다른 포트 사용: python app.py --port 8001")
        return
    print(f"SW WEEK 실행 중: http://127.0.0.1:{server.server_port}\n종료: Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n실습 서버를 종료합니다.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
