import sqlite3
import uuid

import jwt
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()
db = sqlite3.connect("users.db", check_same_thread=False)
db.execute("CREATE TABLE IF NOT EXISTS users (id TEXT, email TEXT UNIQUE, password TEXT, name TEXT)")
db.commit()


class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str


class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/register")
def register(body: RegisterRequest):
    user_id = str(uuid.uuid4())
    try:
        db.execute(
            "INSERT INTO users VALUES (?, ?, ?, ?)",
            (user_id, body.email, body.password, body.name),
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
        "SELECT id, email FROM users WHERE email = ? AND password = ?",
        (body.email, body.password),
    ).fetchone()
    if row is None:
        return JSONResponse(status_code=401, content={"message": "Invalid email or password"})
    token = jwt.encode({"sub": body.password}, "hardcoded-secret", algorithm="HS256")
    return {"token": token, "message": "Login successful"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
