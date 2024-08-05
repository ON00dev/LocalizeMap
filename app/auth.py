import hashlib
import json
import os
import hmac
import hashlib
import base64
from datetime import datetime

# Função para criptografar a senha
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Função para verificar as credenciais do usuário
def check_credentials(username, password):
    hashed_password = hash_password(password)
    try:
        with open('data/data/users.json', 'r') as f:
            users = json.load(f)
            return users.get(username, {}).get("password") == hashed_password
    except FileNotFoundError:
        return False

# Função para registrar um novo usuário
def register_user(username, password, email):
    hashed_password = hash_password(password)
    try:
        with open('data/data/users.json', 'r') as f:
            users = json.load(f)
    except FileNotFoundError:
        users = {}

    if username in users:
        return False  # Usuário já existe

    users[username] = {
        "password": hashed_password,
        "email": email
    }
    with open('data/data/users.json', 'w') as f:
        json.dump(users, f, indent=4)
    return True

# Função para redefinir a senha
def reset_password(username, new_password, _):
    hashed_new_password = hash_password(new_password)
    try:
        with open('data/data/users.json', 'r') as f:
            users = json.load(f)
        if username in users:
            users[username]["password"] = hashed_new_password
            with open('data/data/users.json', 'w') as f:
                json.dump(users, f, indent=4)
            return True
        else:
            return False
    except FileNotFoundError:
        return False

# Função para obter o papel do usuário
def get_user_role(username):
    try:
        with open('data/data/users.json', 'r') as f:
            users = json.load(f)
        return users.get(username, {}).get("role", "user")
    except FileNotFoundError:
        return "user"

# Função para gerar um token de redefinição de senha
def generate_reset_token(username):
    secret_key = os.urandom(16)
    timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    message = f'{username}:{timestamp}'
    token = hmac.new(secret_key, message.encode(), hashlib.sha256).digest()
    token_b64 = base64.urlsafe_b64encode(token).decode()
    return token_b64, secret_key

# Função para verificar o token de redefinição de senha
def verify_reset_token(token, username, secret_key):
    try:
        decoded_token = base64.urlsafe_b64decode(token.encode())
        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        message = f'{username}:{timestamp}'
        expected_token = hmac.new(secret_key, message.encode(), hashlib.sha256).digest()
        return hmac.compare_digest(expected_token, decoded_token)
    except Exception as e:
        return False

# Função para enviar o e-mail de redefinição de senha
def send_reset_email(email, token):
    # Aqui você implementaria a lógica para enviar o e-mail
    print(f"Enviando e-mail para {email} com o token {token}")

# Função para obter o e-mail do usuário
def get_user_email(username):
    try:
        with open('data/data/users.json', 'r') as f:
            users = json.load(f)
        return users.get(username, {}).get("email", None)
    except FileNotFoundError:
        return None
