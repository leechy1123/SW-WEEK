"""실습용 웹 기능. 실제 개인정보 대신 메모리 안의 가상 데이터만 사용합니다.

처음 읽을 파일: read_post → error_page → search_products 순서로 읽어보세요.
vulnerable은 의도적으로 잘못된 예제, fixed는 같은 기능의 수정 예제입니다.
"""
import sqlite3
import traceback
from contextlib import closing

# 학습 과제: False를 하나씩 True로 바꾸고 서버를 재시작한 뒤 다시 진단하세요.
# fixed 버전은 이 값과 관계없이 항상 수정된 로직을 사용합니다.
REPAIR_ACCESS = False
REPAIR_DEBUG = False
REPAIR_SQL = False

# 실제 로그인 대신 서버가 확인하는 고정된 실습 세션입니다. 운영 서비스에 쓰지 마세요.
TEST_SESSIONS = {"demo-alice": "alice", "demo-bob": "bob"}
POSTS = {
    "1": {"id": "1", "owner": "alice", "title": "앨리스의 비공개 메모", "body": "주말에 파이썬 공부하기"},
    "2": {"id": "2", "owner": "bob", "title": "밥의 비공개 메모", "body": "이 내용은 밥에게만 보여야 합니다."},
}


def read_post(version, post_id, session):
    """A01: 로그인 확인에 더해 '이 글의 주인인가?'를 확인해야 합니다."""
    current_user = TEST_SESSIONS.get(session)
    if current_user is None:
        return 401, {"message": "로그인이 필요합니다."}
    post = POSTS.get(post_id)
    if post is None:
        return 404, {"message": "게시글을 찾을 수 없습니다."}

    # 수정 전에는 이 권한 검사가 실행되지 않아 다른 사람의 글도 보입니다.
    if version == "fixed" or REPAIR_ACCESS:
        if post["owner"] != current_user:
            return 403, {"message": "이 게시글을 볼 권한이 없습니다."}
    return 200, {"post": post}


def error_page(version, trigger):
    """A02: 상세 오류는 사용자 화면 대신 접근이 제한된 서버 로그에 남깁니다."""
    if not trigger:
        return 200, {"message": "서비스가 정상적으로 응답합니다."}
    try:
        # 오류 화면을 관찰하기 위해 일부러 만드는 작은 예제입니다.
        1 / 0
    except ZeroDivisionError:
        if version == "fixed" or REPAIR_DEBUG:
            # 운영에서는 logging.exception으로 보호된 서버 로그에 기록하세요.
            return 500, {"message": "처리 중 문제가 발생했습니다. 잠시 후 다시 시도해 주세요."}
        return 500, {"message": "개발용 상세 오류", "debug": traceback.format_exc()}


def search_products(version, keyword):
    """A05: 문자열 연결과 매개변수 바인딩의 차이를 SQLite로 실행합니다."""
    if len(keyword) > 100:
        return 400, {"message": "검색어는 100자 이내로 입력해 주세요."}
    # 요청마다 새 DB를 만듭니다. 파일, 실제 계정, 개인정보는 사용하지 않습니다.
    with closing(sqlite3.connect(":memory:")) as db:
        db.execute("CREATE TABLE products (id INTEGER, name TEXT)")
        db.executemany("INSERT INTO products VALUES (?, ?)", [(1, "노트"), (2, "연필"), (3, "지우개")])
        try:
            if version == "fixed" or REPAIR_SQL:
                # ?는 데이터가 들어갈 자리입니다. 입력을 SQL 명령과 분리합니다.
                rows = db.execute("SELECT id, name FROM products WHERE name = ?", (keyword,)).fetchall()
            else:
                # 취약한 예제: 따옴표를 포함한 입력이 SQL의 구조를 바꿀 수 있습니다.
                query = "SELECT id, name FROM products WHERE name = '" + keyword + "'"
                rows = db.execute(query).fetchall()
        except sqlite3.Error:
            return 400, {"message": "검색 입력을 처리하지 못했습니다."}
    return 200, {"products": [{"id": row[0], "name": row[1]} for row in rows]}
