import hashlib
import json
from notification import notify_admin_new_user
import random
import smtplib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def check_credentials(username, password):
    hashed_password = hash_password(password)
    try:
        with open('data/users.json', 'r') as f:
            users = json.load(f)
            return users.get(username, {}).get("password") == hashed_password
    except FileNotFoundError:
        return False


def register_user(username, password, security_answer, role="user"):
    hashed_password = hash_password(password)
    hashed_answer = hash_password(security_answer)
    try:
        with open('data/users.json', 'r') as f:
            users = json.load(f)
    except FileNotFoundError:
        users = {}

    if username in users:
        return False

    users[username] = {
        "password": hashed_password,
        "security_answer": hashed_answer,
        "role": role
    }
    with open('data/users.json', 'w') as f:
        json.dump(users, f, indent=4)

    # Notificar o administrador sobre o novo usuário
    notify_admin_new_user(username)
    return True


def reset_password(username, new_password, security_answer):
    hashed_answer = hash_password(security_answer)
    hashed_new_password = hash_password(new_password)
    try:
        with open('data/users.json', 'r') as f:
            users = json.load(f)
        if users.get(username, {}).get("security_answer") == hashed_answer:
            users[username]["password"] = hashed_new_password
            with open('data/users.json', 'w') as f:
                json.dump(users, f, indent=4)
            return True
        else:
            return False
    except FileNotFoundError:
        return False


def get_user_role(username):
    try:
        with open('data/users.json', 'r') as f:
            users = json.load(f)
        return users.get(username, {}).get("role", "user")
    except FileNotFoundError:
        return "user"

# Função para gerar código de verificação 2FA
def generate_2fa_code():
    return random.randint(100000, 999999)


# Função para enviar o código de verificação por e-mail
def send_2fa_code(email, code):
    with open('data/config.json', 'r') as f:
        config = json.load(f)

    smtp_server = config['smtp_server']
    smtp_port = config['smtp_port']
    smtp_user = config['smtp_user']
    smtp_password = config['smtp_password']

    msg = f"Seu código de verificação é {code}"

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.sendmail(smtp_user, email, msg)
        server.quit()
        print("Código de verificação enviado.")
    except Exception as e:
        print(f"Erro ao enviar o código de verificação: {e}")
