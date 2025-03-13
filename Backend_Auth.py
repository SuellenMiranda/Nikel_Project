from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import jwt
import os
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
SECRET_KEY = os.getenv("SECRET_KEY", "seu_segredo_secreto")

def get_db_connection():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

# Criar tabela de usuários se não existir
with get_db_connection() as conn:
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password TEXT)''')
    conn.commit()

# Rota de registro
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password").encode("utf-8")
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
    
    try:
        with get_db_connection() as conn:
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
        return jsonify({"message": "Usuário registrado com sucesso"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Usuário já existe"}), 400

# Rota de login
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password").encode("utf-8")
    
    with get_db_connection() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    
    if not user or not bcrypt.checkpw(password, user["password"]):
        return jsonify({"error": "Credenciais inválidas"}), 400
    
    token = jwt.encode({"id": user["id"], "username": user["username"]}, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token})

# Rota protegida de exemplo
@app.route("/protected", methods=["GET"])
def protected():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "Token não fornecido"}), 401
    
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({"message": "Acesso autorizado", "user": decoded})
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
