import hashlib
import hmac
import os
import secrets
import sqlite3
import uuid

import jwt
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()
db = sqlite3.connect("users.db", check_same_thread=False)
db.execute(
    "CREATE TABLE IF NOT EXISTS users (id TEXT, email TEXT UNIQUE, password_hash TEXT, name TEXT)"
)
db.commit()
os.chmod("users.db", 0o600)


class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str


class LoginRequest(BaseModel):
    email: str
    password: str


def password_hash(password: str, salt: bytes | None = None) -> str:
    selected_salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), selected_salt, 210_000)
    return f"{selected_salt.hex()}:{digest.hex()}"


def password_matches(password: str, encoded: str) -> bool:
    salt_hex, expected = encoded.split(":", 1)
    actual = password_hash(password, bytes.fromhex(salt_hex)).split(":", 1)[1]
    return hmac.compare_digest(actual, expected)


@app.post("/register")
def register(body: RegisterRequest):
    user_id = str(uuid.uuid4())
    try:
        db.execute(
            "INSERT INTO users VALUES (?, ?, ?, ?)",
            (user_id, body.email, password_hash(body.password), body.name),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return JSONResponse(status_code=400, content={"message": "Email already in use or invalid data"})
    return JSONResponse(
        status_code=201,
        content={"message": "Registration successful", "userId": user_id},
    )


@app.post("/login")
def login(body: LoginRequest):
    row = db.execute(
        "SELECT id, email, password_hash FROM users WHERE email = ?", (body.email,)
    ).fetchone()
    if row is None or not password_matches(body.password, row[2]):
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    token = jwt.encode(
        {"sub": row[0], "email": row[1], "jti": secrets.token_hex(16)},
        os.environ["JWT_SECRET"],
        algorithm="HS256",
    )
    return {"token": token, "message": "Login successful"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
