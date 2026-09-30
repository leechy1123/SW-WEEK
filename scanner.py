"""등록된 로컬 실습 URL만 진단합니다. 외부 사이트에는 요청하지 않습니다.

흐름: URL 검증 → 실제 HTTP 요청 → 응답 비교 → 근거와 설명 반환.
정상 기능이 고장났거나 예상하지 못한 응답이면 '미확인'이며 통과가 아닙니다.
"""
import http.client
import json
from datetime import datetime, timezone
from urllib.parse import urlencode, urlsplit
from lessons import LESSONS

TRUE_INPUT = "' OR 1=1 -- "
FALSE_INPUT = "' OR 1=2 -- "


class ScanError(ValueError):
    pass


def validate_target(raw, port):
    if not isinstance(raw, str) or len(raw) > 2048 or any(ord(c) < 32 for c in raw):
        raise ScanError("올바른 실습 URL을 입력해 주세요.")
    try:
        parsed = urlsplit(raw.strip())
        if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
                or parsed.port != port or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment):
            raise ValueError()
        path = parsed.path.rstrip("/")
        if path not in ("/lab/vulnerable", "/lab/fixed"):
            raise ValueError()
    except ValueError:
        raise ScanError(f"이 앱의 실습 URL만 사용할 수 있습니다: http://127.0.0.1:{port}/lab/vulnerable") from None
    return path.rsplit("/", 1)[1]


def request_case(port, version, path, label, session="demo-alice"):
    """호스트를 사용자 입력에서 가져오지 않고 숫자 loopback 주소에만 연결합니다."""
    route = f"/lab/{version}/{path}"
    headers = {"Accept": "application/json"}
    if session:
        headers["X-Lab-Session"] = session
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request("GET", route, headers=headers)
        response = connection.getresponse()
        body = response.read(65537)
        if len(body) > 65536 or response.getheader("X-SW-Lab") != "2025-v1":
            raise ScanError("실습 응답을 확인할 수 없습니다. 서버 상태를 확인해 주세요.")
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict):
            raise ScanError("실습 응답의 형식이 올바르지 않습니다.")
        return {"label": label, "path": route, "status": response.status, "body": data}
    except (OSError, http.client.HTTPException, UnicodeError, json.JSONDecodeError) as error:
        raise ScanError("실습 서버 응답에 실패했습니다. 서버가 실행 중인지 확인해 주세요.") from error
    finally:
        connection.close()


def evaluate(category, cases):
    """내용과 상태를 함께 검사합니다. 단순 200/403만으로 판정하지 않습니다."""
    first, second = cases[:2]
    if category == "A01":
        anonymous = cases[2]
        own_post = first["body"].get("post")
        other_post = second["body"].get("post")
        own_ok = first["status"] == 200 and isinstance(own_post, dict) and own_post.get("owner") == "alice"
        anon_ok = anonymous["status"] == 401 and "post" not in anonymous["body"]
        leaked = second["status"] == 200 and isinstance(other_post, dict) and other_post.get("owner") == "bob"
        blocked = second["status"] == 403 and "post" not in second["body"]
        if leaked:
            return "vulnerable", "앨리스의 세션으로 밥의 비공개 글이 반환되었습니다. 소유자 확인이 빠져 있습니다.", own_ok and anon_ok
        if own_ok and anon_ok and blocked:
            return "pass", "본인 글은 200, 다른 사람 글은 403, 비로그인 요청은 401로 처리됩니다.", True
    if category == "A02":
        normal_ok = first["status"] == 200 and "message" in first["body"]
        debug = second["body"].get("debug", "")
        if second["status"] == 500 and "Traceback" in str(debug) and "ZeroDivisionError" in str(debug):
            return "vulnerable", "오류 응답에 내부 파일 경로와 호출 내역이 노출되었습니다.", normal_ok
        if normal_ok and second["status"] == 500 and "debug" not in second["body"] and "message" in second["body"]:
            return "pass", "정상 요청은 유지되고 오류 요청에는 일반 안내만 표시됩니다. 500 자체는 취약점이 아닙니다.", True
    if category == "A05":
        false_case = cases[2]
        normal_ok = first["status"] == 200 and first["body"].get("products") == [{"id": 1, "name": "노트"}]
        all_ok = all(case["status"] == 200 and isinstance(case["body"].get("products"), list) for case in cases)
        if all_ok:
            true_count = len(second["body"]["products"])
            false_count = len(false_case["body"]["products"])
            if normal_ok and true_count == 3 and false_count == 0:
                return "vulnerable", "참 조건은 3개, 거짓 조건은 0개를 반환합니다. 검색어가 SQL 조건으로 실행되었습니다.", True
            if normal_ok and true_count == 0 and false_count == 0:
                return "pass", "두 테스트 입력을 명령이 아닌 검색어로 처리했습니다. 정상 ‘노트’ 검색은 1개로 유지됩니다.", True
    return "unknown", "예상한 정상 응답과 테스트 응답을 모두 확인하지 못했습니다. 코드와 서버 상태를 확인하세요.", False


def scan_version(port, version):
    get = lambda path, label, session="demo-alice": request_case(port, version, path, label, session)
    cases = {
        "A01": [get("posts?id=1", "본인 글 · 앨리스"), get("posts?id=2", "다른 사람 글 · 밥"), get("posts?id=1", "비로그인 요청", "")],
        "A02": [get("error", "정상 페이지"), get("error?trigger=1", "오류 발생 요청")],
        "A05": [get("search?" + urlencode({"q": "노트"}), "정상 검색 · 노트"),
                get("search?" + urlencode({"q": TRUE_INPUT}), "참 조건 · 1=1"),
                get("search?" + urlencode({"q": FALSE_INPUT}), "거짓 조건 · 1=2")],
    }
    findings = []
    for lesson in LESSONS:
        state, reason, normal_ok = evaluate(lesson["id"], cases[lesson["id"]])
        findings.append({**lesson, "state": state, "reason": reason, "normal_ok": normal_ok, "evidence": cases[lesson["id"]]})
    return {"version": version, "url": f"http://127.0.0.1:{port}/lab/{version}", "checks": findings, "request_count": 8}


def scan(raw, port, compare=False):
    version = validate_target(raw, port)
    if compare:
        before = scan_version(port, "vulnerable")
        after = scan_version(port, "fixed")
        return {"kind": "compare", "before": before, "after": after, "request_count": 16,
                "time": datetime.now(timezone.utc).isoformat()}
    return {"kind": "single", **scan_version(port, version), "time": datetime.now(timezone.utc).isoformat()}
