import os, json, uuid, hashlib, hmac, sqlite3
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from fastapi import (
    FastAPI, WebSocket, WebSocketDisconnect,
    HTTPException, Depends, status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

app = FastAPI(title="Wren Chat API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

SECRET  = os.environ.get("SECRET_KEY", "wren-chat-secret-change-me")
DB_PATH = os.environ.get("DB_PATH", "wren_chat.db")

# ── SQLite setup ──────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            TEXT PRIMARY KEY,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tokens (
            token   TEXT PRIMARY KEY,
            user_id TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS chats (
            id         TEXT PRIMARY KEY,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS chat_members (
            chat_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            PRIMARY KEY (chat_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS messages (
            id         TEXT PRIMARY KEY,
            chat_id    TEXT NOT NULL,
            sender_id  TEXT NOT NULL,
            content    TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()

init_db()

# ── In-memory token cache ─────────────────────────────────────────────────────
TOKENS: Dict[str, str] = {}

def _load_tokens():
    conn = get_db()
    for row in conn.execute("SELECT token, user_id FROM tokens"):
        TOKENS[row["token"]] = row["user_id"]
    conn.close()

_load_tokens()

# ── WebSocket manager ─────────────────────────────────────────────────────────
class Manager:
    def __init__(self):
        self.connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, user_id: str, ws: WebSocket):
        await ws.accept()
        self.connections.setdefault(user_id, set()).add(ws)

    def disconnect(self, user_id: str, ws: WebSocket):
        if user_id in self.connections:
            self.connections[user_id].discard(ws)

    async def send_to(self, user_id: str, payload: dict):
        dead = set()
        for ws in self.connections.get(user_id, set()):
            try:
                await ws.send_text(json.dumps(payload))
            except Exception:
                dead.add(ws)
        for ws in dead:
            self.connections[user_id].discard(ws)

manager = Manager()

# ── Helpers ───────────────────────────────────────────────────────────────────
def _hash(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def _make_token(user_id: str) -> str:
    raw = f"{user_id}:{uuid.uuid4()}"
    tok = hmac.new(SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()
    TOKENS[tok] = user_id
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO tokens (token, user_id) VALUES (?, ?)", (tok, user_id))
    conn.commit()
    conn.close()
    return tok

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    uid = TOKENS.get(token)
    if not uid:
        # fallback: check DB (e.g. after process restart with existing token)
        conn = get_db()
        row = conn.execute("SELECT user_id FROM tokens WHERE token=?", (token,)).fetchone()
        conn.close()
        if row:
            uid = row["user_id"]
            TOKENS[token] = uid
    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token")
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return dict(user)

# ── Auth ──────────────────────────────────────────────────────────────────────
class RegisterBody(BaseModel):
    username: str
    password: str
    email:    Optional[str] = None

@app.post("/api/auth/register", status_code=201)
def register(body: RegisterBody):
    uname = body.username.strip()
    if not uname or not body.password:
        raise HTTPException(400, "username and password required")
    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE username=?", (uname,)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(409, "Username already taken")
    uid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
        (uid, uname, _hash(body.password))
    )
    conn.commit()
    conn.close()
    token = _make_token(uid)
    return {"access_token": token, "token_type": "bearer", "user_id": uid, "username": uname}

@app.post("/api/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (form.username,)).fetchone()
    conn.close()
    if not user:
        raise HTTPException(401, "User not found")
    if user["password_hash"] != _hash(form.password):
        raise HTTPException(401, "Wrong password")
    token = _make_token(user["id"])
    return {"access_token": token, "token_type": "bearer", "user_id": user["id"], "username": user["username"]}

@app.get("/api/users/me")
def me(user=Depends(get_current_user)):
    return {"id": user["id"], "username": user["username"]}

# ── User search (NEW) ─────────────────────────────────────────────────────────
@app.get("/api/users/search")
def search_users(q: str = "", username: str = "", query: str = "", user=Depends(get_current_user)):
    term = (q or username or query).strip()
    if not term:
        raise HTTPException(400, "Provide a search term")
    conn = get_db()
    # Exact match first, then prefix match
    rows = conn.execute(
        "SELECT id, username FROM users WHERE LOWER(username) = LOWER(?)", (term,)
    ).fetchall()
    if not rows:
        rows = conn.execute(
            "SELECT id, username FROM users WHERE LOWER(username) LIKE LOWER(?)", (f"{term}%",)
        ).fetchall()
    conn.close()
    return [{"id": r["id"], "username": r["username"]} for r in rows]

@app.get("/api/users/by-username/{username}")
def get_user_by_username(username: str, user=Depends(get_current_user)):
    conn = get_db()
    row = conn.execute(
        "SELECT id, username FROM users WHERE LOWER(username) = LOWER(?)", (username,)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "User not found")
    return {"id": row["id"], "username": row["username"]}

# ── Chats ─────────────────────────────────────────────────────────────────────
class DMBody(BaseModel):
    user_id: str

@app.post("/api/chats/dm", status_code=201)
def create_or_get_dm(body: DMBody, me=Depends(get_current_user)):
    conn = get_db()
    target = conn.execute("SELECT id FROM users WHERE id=?", (body.user_id,)).fetchone()
    if not target:
        conn.close()
        raise HTTPException(404, "Target user not found")
    members = sorted([me["id"], body.user_id])
    # Check if DM already exists
    existing = conn.execute("""
        SELECT c.id FROM chats c
        JOIN chat_members m1 ON m1.chat_id = c.id AND m1.user_id = ?
        JOIN chat_members m2 ON m2.chat_id = c.id AND m2.user_id = ?
        WHERE (SELECT COUNT(*) FROM chat_members WHERE chat_id = c.id) = 2
        LIMIT 1
    """, (members[0], members[1])).fetchone()
    if existing:
        cid = existing["id"]
        member_rows = conn.execute("SELECT user_id FROM chat_members WHERE chat_id=?", (cid,)).fetchall()
        conn.close()
        return {"id": cid, "members": [r["user_id"] for r in member_rows]}
    cid = str(uuid.uuid4())
    now = _now()
    conn.execute("INSERT INTO chats (id, created_at) VALUES (?, ?)", (cid, now))
    for uid in members:
        conn.execute("INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)", (cid, uid))
    conn.commit()
    conn.close()
    return {"id": cid, "members": members, "created_at": now}

@app.get("/api/chats")
def list_chats(user=Depends(get_current_user)):
    conn = get_db()
    chat_rows = conn.execute("""
        SELECT c.id, c.created_at FROM chats c
        JOIN chat_members cm ON cm.chat_id = c.id
        WHERE cm.user_id = ?
    """, (user["id"],)).fetchall()
    result = []
    for chat in chat_rows:
        cid = chat["id"]
        members = conn.execute("""
            SELECT u.id, u.username FROM users u
            JOIN chat_members cm ON cm.user_id = u.id
            WHERE cm.chat_id = ?
        """, (cid,)).fetchall()
        last_msg = conn.execute("""
            SELECT content, created_at FROM messages
            WHERE chat_id = ? ORDER BY created_at DESC LIMIT 1
        """, (cid,)).fetchone()
        result.append({
            "id": cid,
            "created_at": chat["created_at"],
            "participants": [{"id": m["id"], "username": m["username"]} for m in members],
            "last_message": {"content": last_msg["content"], "created_at": last_msg["created_at"]} if last_msg else None,
        })
    conn.close()
    return result

@app.get("/api/chats/{chat_id}/messages")
def get_messages(chat_id: str, user=Depends(get_current_user)):
    conn = get_db()
    member = conn.execute(
        "SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?", (chat_id, user["id"])
    ).fetchone()
    if not member:
        conn.close()
        raise HTTPException(403, "Not a member")
    msgs = conn.execute(
        "SELECT * FROM messages WHERE chat_id=? ORDER BY created_at ASC", (chat_id,)
    ).fetchall()
    conn.close()
    return [dict(m) for m in msgs]

class MsgBody(BaseModel):
    content: str

@app.post("/api/chats/{chat_id}/messages", status_code=201)
async def send_message(chat_id: str, body: MsgBody, user=Depends(get_current_user)):
    conn = get_db()
    member = conn.execute(
        "SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?", (chat_id, user["id"])
    ).fetchone()
    if not member:
        conn.close()
        raise HTTPException(403, "Not a member")
    msg = {
        "id":         str(uuid.uuid4()),
        "chat_id":    chat_id,
        "sender_id":  user["id"],
        "content":    body.content,
        "created_at": _now(),
    }
    conn.execute(
        "INSERT INTO messages (id, chat_id, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?)",
        (msg["id"], msg["chat_id"], msg["sender_id"], msg["content"], msg["created_at"])
    )
    conn.commit()
    conn.close()
    members = get_db().execute("SELECT user_id FROM chat_members WHERE chat_id=?", (chat_id,)).fetchall()
    payload = {"event": "new_message", "message": msg}
    for row in members:
        await manager.send_to(row["user_id"], payload)
    return msg

# ── WebSocket ─────────────────────────────────────────────────────────────────
@app.websocket("/ws/{user_id}")
async def websocket_endpoint(ws: WebSocket, user_id: str, token: str = ""):
    if token and TOKENS.get(token) != user_id:
        await ws.close(code=4001)
        return
    await manager.connect(user_id, ws)
    try:
        while True:
            raw  = await ws.receive_text()
            data = json.loads(raw)
            event = data.get("event")
            if event == "typing":
                chat_id   = data.get("chat_id")
                is_typing = data.get("is_typing", False)
                if chat_id:
                    members = get_db().execute(
                        "SELECT user_id FROM chat_members WHERE chat_id=?", (chat_id,)
                    ).fetchall()
                    for row in members:
                        if row["user_id"] != user_id:
                            await manager.send_to(row["user_id"], {
                                "event":     "typing",
                                "user_id":   user_id,
                                "chat_id":   chat_id,
                                "is_typing": is_typing,
                            })
            elif event == "join":
                await ws.send_text(json.dumps({"event": "joined", "chat_id": data.get("chat_id")}))
    except WebSocketDisconnect:
        manager.disconnect(user_id, ws)

@app.get("/")
def health():
    conn = get_db()
    users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    chats = conn.execute("SELECT COUNT(*) FROM chats").fetchone()[0]
    conn.close()
    return {"status": "ok", "users": users, "chats": chats}
