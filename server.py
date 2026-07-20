from fastapi import FastAPI
from pydantic import BaseModel
import psycopg2
import os
from datetime import datetime
from typing import Optional

app = FastAPI()

# Получаем ссылку на базу данных Neon из настроек облака Render
DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db_connection():
    """Функция для быстрого подключения к облачной PostgreSQL"""
    return psycopg2.connect(DATABASE_URL)

def init_db():
    """Функция, которая создает необходимые таблицы в облачной базе данных, если их нет"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Таблица логов входа
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_logs (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            password TEXT,
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
            password TEXT,
            client_ip TEXT,
            created_at TEXT NOT NULL
        );
    """)
    
    conn.commit()
    cursor.close()
    conn.close()
    print("[POSTGRES INFO] База данных проверена, таблицы user_logs и users готовы!")

# Запускаем создание/проверку таблиц в облаке при старте сервера
if DATABASE_URL:
    init_db()
else:
    print("[ERROR] Переменная окружения DATABASE_URL не найдена!")


class LoginData(BaseModel):
    username: str
    role: str
    password: str = ""
    client_ip: Optional[str] = "Не указан"


class RegisterData(BaseModel):
    username: str
    role: str
    password: str = ""
    client_ip: Optional[str] = "Не указан"


@app.get("/")
def read_root():
    return {"status": "Server is running", "db": "PostgreSQL (Neon) connected"}


@app.post("/api/login")
def login_user(data: LoginData):
    """Запись факта входа в логи"""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "INSERT INTO user_logs (username, role, password, client_ip, login_time) VALUES (%s, %s, %s, %s, %s)",
        (data.username, data.role, data.password, data.client_ip, current_time)
    )
    conn.commit()
    cursor.close()
    conn.close()

    print(f"\n[SERVER LOG] Получен вход от {data.username} ({data.role})")
    return {"status": "success", "saved_to_logs": True}


@app.post("/api/register")
def register_user(data: RegisterData):
    """Сохранение нового пользователя в таблицу users (если его еще нет)"""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Вставляем пользователя, если логина ещё нет в базе (ON CONFLICT DO NOTHING / UPDATE)
        cursor.execute("""
            INSERT INTO users (username, role, password, client_ip, created_at) 
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (username) DO UPDATE 
            SET role = EXCLUDED.role, client_ip = EXCLUDED.client_ip;
        """, (data.username, data.role, data.password, data.client_ip, current_time))
        
        conn.commit()
        print(f"[NEON DB LOG] Пользователь {data.username} сохранен/обновлен в таблице users!")
        return {"status": "success", "saved_to_users": True}
    except Exception as e:
        conn.rollback()
        print(f"[ERROR DB] Ошибка сохранения пользователя: {e}")
        return {"status": "error", "message": str(e)}
    finally:
        cursor.close()
        conn.close()


@app.get("/api/users")
def get_users():
    """Эндпоинт для выгрузки всех пользователей в Excel"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, username, role, password, client_ip FROM users ORDER BY id ASC;")
    rows = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    users = []
    for r in rows:
        users.append({
            "id": r[0],
            "username": r[1],
            "role": r[2],
            "password": r[3],
            "client_ip": r[4]
        })
    return users


@app.get("/api/logs")
def get_logs():
    """Эндпоинт для выгрузки всех логов в Excel"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, username, role, client_ip, login_time FROM user_logs ORDER BY id DESC;")
    rows = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    logs = []
    for r in rows:
        logs.append({
            "id": r[0],
            "username": r[1],
            "role": r[2],
            "client_ip": r[3],
            "timestamp": r[4]
        })
    return logs