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
SECRET_KEY = os.environ.get("JWT_SECRET", "ELOU_AVT_SECRET_KEY_2026")  # Секретный ключ подписи
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
    """Проверка и расшифровка JWT-токена из заголовка Authorization."""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload  # Возвращает dict: {"sub": "username", "role": "role", "exp": ...}
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
    """Хеширование пароля через SHA-256"""
    if not password:
        return ""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


# 1. В функции init_db() создаем полноценную таблицу для действий и аварий:
# 1. В init_db() добавляем авто-создание новой таблицы с логированием:
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Таблица входов
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_logs (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            client_ip TEXT,
            login_time TEXT NOT NULL
        );
    """)
    
    # Таблица действий операторов и аварий ПАЗ
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
    
    conn.commit()
    cursor.close()
    conn.close()
    print("[POSTGRES INFO] Все таблицы базы данных проверены и готовы к работе!")


# 2. Pydantic-модель для входящих логов
class ActionLogData(BaseModel):
    username: str
    role: str
    action: str
    details: str


# 3. Прием логов от оператора (POST /api/logs)
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


# 4. Отдача логов клиенту (GET /api/logs)
@app.get("/api/logs")
def get_action_logs(current_user: dict = Depends(get_current_user)):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Запрашиваем действия и аварии
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
        # Запасной вариант: если таблицы нет, возвращаем пустой список вместо ошибки 500!
        return []


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


# --- МАРШРУТЫ API ---
@app.get("/")
def read_root():
    return {"status": "Server is running", "db": "PostgreSQL (Neon) connected"}


@app.post("/api/login")
def login_user(data: LoginData):
    """Строгая авторизация пользователя с генерацией JWT-токена"""
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

    # Создаём JWT-токен
    token = create_access_token({"sub": db_username, "role": db_role})

    return {
        "status": "success",
        "access_token": token,
        "token_type": "bearer",
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
def get_users(current_user: dict = Depends(get_current_user)):
    """Получение списка всех пользователей (доступно только зарегистрированным)"""
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
def get_logs(current_user: dict = Depends(get_current_user)):
    """Получение логов (доступно только авторизованным)"""
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


# 1. Удаление конкретного пользователя по ID (Защищено: ТОЛЬКО ДЛЯ АДМИНА)
@app.delete("/api/users/{user_id}")
def delete_user(user_id: int, current_admin: dict = Depends(require_admin_role)):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT username FROM users WHERE id = %s;", (user_id,))
        user = cursor.fetchone()
        
        if user and user[0] == "admin":
            cursor.close()
            conn.close()
            return {"status": "error", "message": "Нельзя удалить главного администратора!"}
            
        cursor.execute("DELETE FROM users WHERE id = %s;", (user_id,))
        conn.commit()
        cursor.close()
        conn.close()
        
        return {"status": "success", "message": "Пользователь удален"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# 2. Очистка всех пользователей (Защищено: ТОЛЬКО ДЛЯ АДМИНА)
@app.delete("/api/users/clear/all")
def clear_all_users(current_admin: dict = Depends(require_admin_role)):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM users WHERE username != 'admin';")
        conn.commit()
        cursor.close()
        conn.close()
        
        return {"status": "success", "message": "Все пользователи (кроме admin) удалены"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))