import os, json, uuid, hashlib, hmac
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

SECRET = os.environ.get("SECRET_KEY", "wren-chat-secret-change-me")

USERS:    Dict[str, dict] = {}
UNAMES:   Dict[str, str]  = {}
TOKENS:   Dict[str, str]  = {}
CHATS:    Dict[str, dict] = {}
MESSAGES: Dict[str, list] = {}

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

def _hash(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def _make_token(user_id: str) -> str:
    raw = f"{user_id}:{uuid.uuid4()}"
    tok = hmac.new(SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()
    TOKENS[tok] = user_id
    return tok

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    uid = TOKENS.get(token)
    if not uid or uid not in USERS:
        raise HTTPException(status_code=401, detail="Invalid token")
    return USERS[uid]

class RegisterBody(BaseModel):
    username: str
    password: str
    email:    Optional[str] = None

@app.post("/api/auth/register", status_code=201)
def register(body: RegisterBody):
    uname = body.username.strip()
    if not uname or not body.password:
        raise HTTPException(400, "username and password required")
    if uname in UNAMES:
        raise HTTPException(409, "Username already taken")
    uid = str(uuid.uuid4())
    USERS[uid] = {"id": uid, "username": uname, "password_hash": _hash(body.password)}
    UNAMES[uname] = uid
    token = _make_token(uid)
    return {"access_token": token, "token_type": "bearer", "user_id": uid, "username": uname}

@app.post("/api/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    uid = UNAMES.get(form.username)
    if not uid:
        raise HTTPException(401, "User not found")
    user = USERS[uid]
    if user["password_hash"] != _hash(form.password):
        raise HTTPException(401, "Wrong password")
    token = _make_token(uid)
    return {"access_token": token, "token_type": "bearer", "user_id": uid, "username": form.username}

@app.get("/api/users/me")
def me(user=Depends(get_current_user)):
    return {"id": user["id"], "username": user["username"]}

class DMBody(BaseModel):
    user_id: str

@app.post("/api/chats/dm", status_code=201)
def create_or_get_dm(body: DMBody, me=Depends(get_current_user)):
    if body.user_id not in USERS:
        raise HTTPException(404, "Target user not found")
    members = tuple(sorted([me["id"], body.user_id]))
    for chat in CHATS.values():
        if tuple(sorted(chat["members"])) == members:
            return chat
    cid  = str(uuid.uuid4())
    chat = {"id": cid, "members": list(members), "created_at": _now()}
    CHATS[cid]    = chat
    MESSAGES[cid] = []
    return chat

@app.get("/api/chats/{chat_id}/messages")
def get_messages(chat_id: str, user=Depends(get_current_user)):
    if chat_id not in CHATS:
        raise HTTPException(404, "Chat not found")
    if user["id"] not in CHATS[chat_id]["members"]:
        raise HTTPException(403, "Not a member")
    return MESSAGES.get(chat_id, [])

class MsgBody(BaseModel):
    content: str

@app.post("/api/chats/{chat_id}/messages", status_code=201)
async def send_message(chat_id: str, body: MsgBody, user=Depends(get_current_user)):
    if chat_id not in CHATS:
        raise HTTPException(404, "Chat not found")
    if user["id"] not in CHATS[chat_id]["members"]:
        raise HTTPException(403, "Not a member")
    msg = {
        "id":        str(uuid.uuid4()),
        "chat_id":   chat_id,
        "sender_id": user["id"],
        "content":   body.content,
        "created_at": _now(),
    }
    MESSAGES[chat_id].append(msg)
    payload = {"event": "new_message", "message": msg}
    for uid in CHATS[chat_id]["members"]:
        await manager.send_to(uid, payload)
    return msg

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
                if chat_id and chat_id in CHATS:
                    for uid in CHATS[chat_id]["members"]:
                        if uid != user_id:
                            await manager.send_to(uid, {
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
    return {"status": "ok", "users": len(USERS), "chats": len(CHATS)}