import os
import hashlib
import jwt
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import psycopg2

app = FastAPI()

DATABASE_URL = os.environ.get("DATABASE_URL")

# --- НАСТРОЙКИ JWT И БЕЗОПАСНОСТИ ---
SECRET_KEY = os.environ.get("JWT_SECRET", "ELOU_AVT_SECRET_KEY_2026")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 12

security = HTTPBearer()


def create_access_token(data: dict) -> str:
    """Генерация JWT-токена со сроком жизни 12 часов."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Проверка и расшифровка JWT-токена."""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Срок действия сессии истёк. Пожалуйста, войдите снова."
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Недействительный токен авторизации."
        )


def require_admin_role(user: dict = Depends(get_current_user)) -> dict:
    """Проверка, что текущий пользователь — Администратор или Инструктор."""
    user_role = str(user.get("role", "")).lower()
    allowed_roles = ["admin", "администратор", "инструктор / преподаватель"]
    
    if user_role not in allowed_roles and str(user.get("sub", "")).lower() != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав для выполнения данной операции!"
        )
    return user


# --- РАБОТА С БАЗОЙ ДАННЫХ ---
def get_db_connection():
    return psycopg2.connect(DATABASE_URL)


def hash_password(password: str) -> str:
    if not password:
        return ""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def init_db():
    """Автоматическая инициализация таблиц PostgreSQL при старте."""
    if not DATABASE_URL:
        print("[WARN] DATABASE_URL не задан, пропускаем init_db()")
        return

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 1. Таблица входов
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_logs (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                client_ip TEXT,
                login_time TEXT NOT NULL
            );
        """)
        
        # 2. Таблица пользователей
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL,
                password_hash TEXT,
                client_ip TEXT,
                created_at TEXT NOT NULL
            );
        """)
        
        # 3. Таблица действий и аварий ПАЗ
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_action_logs (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
        """)

        # Аккаунт админа по умолчанию
        admin_login = "admin"
        admin_pass_hash = hash_password("admin123")
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            INSERT INTO users (username, role, password_hash, client_ip, created_at)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (username) DO UPDATE 
            SET password_hash = EXCLUDED.password_hash;
        """, (admin_login, "Инструктор / Преподаватель", admin_pass_hash, "127.0.0.1", current_time))

        conn.commit()
        cursor.close()
        conn.close()
        print("[POSTGRES INFO] Все таблицы базы данных успешно инициализированы!")
    except Exception as e:
        print(f"[DB ERROR] Ошибка при инициализации БД: {e}")


# 🚀 АВТОМАТИЧЕСКИЙ ЗАПУСК СОЗДАНИЯ ТАБЛИЦ
init_db()


# --- Pydantic МОДЕЛИ ---
class LoginData(BaseModel):
    username: str
    password: str
    client_ip: Optional[str] = "127.0.0.1"


class RegisterData(BaseModel):
    username: str
    password: str
    role: str
    client_ip: Optional[str] = "127.0.0.1"


class ActionLogData(BaseModel):
    username: str
    role: str
    action: str
    details: str


# --- МАРШРУТЫ API ---
@app.get("/")
def read_root():
    return {"status": "Server is running", "db": "PostgreSQL (Neon) connected"}


@app.post("/api/login")
def login_user(data: LoginData):
    """Авторизация пользователя"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT username, role, password_hash FROM users WHERE username = %s;", (data.username,))
    user = cursor.fetchone()
    
    if not user or user[2] != hash_password(data.password):
        cursor.close()
        conn.close()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Неверный логин или пароль!")
    
    db_username, db_role, _ = user
    
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO user_logs (username, role, client_ip, login_time) VALUES (%s, %s, %s, %s)",
        (db_username, db_role, data.client_ip, current_time)
    )
    conn.commit()
    cursor.close()
    conn.close()

    token = create_access_token({"sub": db_username, "role": db_role})
    return {"status": "success", "access_token": token, "username": db_username, "role": db_role}


@app.post("/api/register")
def register_user(data: RegisterData):
    """Регистрация нового пользователя"""
    if not data.username.strip() or not data.password.strip():
        raise HTTPException(status_code=400, detail="Логин и пароль не могут быть пустыми!")

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
        raise HTTPException(status_code=400, detail="Пользователь уже существует!")
    finally:
        cursor.close()
        conn.close()


@app.get("/api/users")
def get_users(current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role, client_ip FROM users ORDER BY id ASC;")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    return [{"id": r[0], "username": r[1], "role": r[2], "password": "••••••••", "client_ip": r[3]} for r in rows]


# 🚀 ЕДИНСТВЕННЫЙ И ПРАВИЛЬНЫЙ ЭНДПОИНТ ПРИЕМА ЛОГОВ (POST)
@app.post("/api/logs")
def create_action_log(data: ActionLogData):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute("""
            INSERT INTO system_action_logs (username, role, action, details, timestamp)
            VALUES (%s, %s, %s, %s, %s);
        """, (data.username, data.role, data.action, data.details, current_time))
        
        conn.commit()
        cursor.close()
        conn.close()
        return {"status": "success"}
    except Exception as e:
        print(f"[DB ERROR] Ошибка записи лога: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# 🚀 ЕДИНСТВЕННЫЙ И ПРАВИЛЬНЫЙ ЭНДПОИНТ ВЫДАЧИ ЛОГОВ (GET)
@app.get("/api/logs")
def get_action_logs(current_user: dict = Depends(get_current_user)):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, username, role, action, details, timestamp 
            FROM system_action_logs 
            ORDER BY id DESC LIMIT 200;
        """)
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        return [
            {
                "id": r[0], 
                "username": r[1], 
                "role": r[2], 
                "action": r[3], 
                "details": r[4], 
                "timestamp": r[5]
            }
            for r in rows
        ]
    except Exception as e:
        print(f"[DB ERROR] Ошибка чтения логов: {e}")
        return []


@app.delete("/api/users/{user_id}")
def delete_user(user_id: int, current_admin: dict = Depends(require_admin_role)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = %s AND username != 'admin';", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return {"status": "success"}


@app.delete("/api/users/clear/all")
def clear_all_users(current_admin: dict = Depends(require_admin_role)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE username != 'admin';")
    conn.commit()
    cursor.close()
    conn.close()
    return {"status": "success"}