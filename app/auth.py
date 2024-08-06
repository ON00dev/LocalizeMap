import hashlib
import json
import os

# Função para criptografar a senha usando SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Função para verificar as credenciais do usuário
def check_credentials(username, password):
    hashed_password = hash_password(password)
    # Construindo o caminho absoluto para o arquivo users.json
    users_file_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'data', 'users.json')
    try:
        with open(users_file_path, 'r') as f:
            users = json.load(f)
            user_data = users.get(username)
            if user_data and user_data.get("password") == hashed_password:
                return True
    except FileNotFoundError:
        print(f"Arquivo users.json não encontrado no caminho especificado: {users_file_path}")
    except json.JSONDecodeError:
        print(f"Erro ao ler o arquivo users.json. Verifique se o JSON está formatado corretamente no caminho: {users_file_path}")
    return False

# Função para registrar um novo usuário
def register_user(username, password, email):
    hashed_password = hash_password(password)
    users_file_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'data', 'users.json')
    try:
        with open(users_file_path, 'r') as f:
            users = json.load(f)
    except FileNotFoundError:
        users = {}

    if username in users:
        return False  # Usuário já existe

    users[username] = {
        "password": hashed_password,
        "email": email,
        "role": "user"
    }
    with open(users_file_path, 'w') as f:
        json.dump(users, f, indent=4)
    return True

# Função para redefinir a senha
def reset_password(username, new_password):
    hashed_new_password = hash_password(new_password)
    users_file_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'data', 'users.json')
    try:
        with open(users_file_path, 'r') as f:
            users = json.load(f)
        if username in users:
            users[username]["password"] = hashed_new_password
            with open(users_file_path, 'w') as f:
                json.dump(users, f, indent=4)
            return True
    except FileNotFoundError:
        print("Arquivo users.json não encontrado.")
    return False

# Função para obter o papel do usuário
def get_user_role(username):
    users_file_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'data', 'users.json')
    try:
        with open(users_file_path, 'r') as f:
            users = json.load(f)
        return users.get(username, {}).get("role", "user")
    except FileNotFoundError:
        return "user"

# Função para gerar um token de redefinição de senha (simulado)
def generate_reset_token(username):
    return "simulated_token_for_" + username, b'simulated_secret_key'

# Função para verificar o token de redefinição de senha (simulado)
def verify_reset_token(token, username, secret_key):
    return token == "simulated_token_for_" + username and secret_key == b'simulated_secret_key'

# Função para enviar o e-mail de redefinição de senha (simulado)
def send_reset_email(email, token):
    print(f"Simulando envio de e-mail para {email} com o token {token}")

# Função para obter o e-mail do usuário
def get_user_email(username):
    users_file_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'data', 'users.json')
    try:
        with open(users_file_path, 'r') as f:
            users = json.load(f)
        return users.get(username, {}).get("email", None)
    except FileNotFoundError:
        return None
