from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import psycopg2
import os
import hashlib
from datetime import datetime
from typing import Optional

app = FastAPI()

DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

def hash_password(password: str) -> str:
    """Хеширование пароля через SHA-256"""
    if not password:
        return ""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Таблица логов входа
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_logs (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            client_ip TEXT,
            login_time TEXT NOT NULL
        );
    """)
    
    # Таблица пользователей
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            client_ip TEXT,
            created_at TEXT NOT NULL
        );
    """)
    
    # Базовый аккаунт администратора (если его ещё нет)
    admin_login = "admin"
    admin_pass_hash = hash_password("admin123")  # Укажи нужный пароль
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO users (username, role, password_hash, client_ip, created_at)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (username) DO NOTHING;
    """, (admin_login, "Инструктор / Преподаватель", admin_pass_hash, "127.0.0.1", current_time))

    conn.commit()
    cursor.close()
    conn.close()
    print("[POSTGRES INFO] База данных проверена, таблицы и аккаунт админа готовы!")

if DATABASE_URL:
    init_db()


class LoginData(BaseModel):
    username: str
    password: str
    client_ip: Optional[str] = "127.0.0.1"


class RegisterData(BaseModel):
    username: str
    password: str
    role: str
    client_ip: Optional[str] = "127.0.0.1"


@app.get("/")
def read_root():
    return {"status": "Server is running", "db": "PostgreSQL (Neon) connected"}


@app.post("/api/login")
def login_user(data: LoginData):
    """Строгая авторизация пользователя"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Поиск пользователя по логину
    cursor.execute("SELECT username, role, password_hash FROM users WHERE username = %s;", (data.username,))
    user = cursor.fetchone()
    
    if not user:
        cursor.close()
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Пользователь с таким логином не найден!"
        )
    
    db_username, db_role, db_pass_hash = user
    
    # Проверка пароля
    if db_pass_hash != hash_password(data.password):
        cursor.close()
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный пароль!"
        )
    
    # Фиксация входа в логи
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO user_logs (username, role, client_ip, login_time) VALUES (%s, %s, %s, %s)",
        (db_username, db_role, data.client_ip, current_time)
    )
    conn.commit()
    cursor.close()
    conn.close()

    return {
        "status": "success",
        "username": db_username,
        "role": db_role
    }


@app.post("/api/register")
def register_user(data: RegisterData):
    """Регистрация нового пользователя"""
    if not data.username.strip() or not data.password.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Логин и пароль не могут быть пустыми!"
        )

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pass_hash = hash_password(data.password)

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO users (username, role, password_hash, client_ip, created_at)
            VALUES (%s, %s, %s, %s, %s);
        """, (data.username, data.role, pass_hash, data.client_ip, current_time))

        conn.commit()
        return {"status": "success", "message": "Пользователь успешно зарегистрирован!"}
    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь с таким логином уже существует!"
        )
    except Exception as e:
        conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
    finally:
        cursor.close()
        conn.close()


@app.get("/api/users")
def get_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role, client_ip FROM users ORDER BY id ASC;")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    return [
        {"id": r[0], "username": r[1], "role": r[2], "password": "••••••••", "client_ip": r[3]}
        for r in rows
    ]


@app.get("/api/logs")
def get_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role, client_ip, login_time FROM user_logs ORDER BY id DESC;")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    return [
        {"id": r[0], "username": r[1], "role": r[2], "client_ip": r[3], "timestamp": r[4]}
        for r in rows
    ]