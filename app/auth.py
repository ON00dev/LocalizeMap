import os
import hmac
import hashlib
import base64
import json
import smtplib
from datetime import datetime


# Função para gerar um token seguro
def generate_reset_token(username):
    secret_key = os.urandom(16)
    timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    message = f'{username}:{timestamp}'
    token = hmac.new(secret_key, message.encode(), hashlib.sha256).digest()
    token_b64 = base64.urlsafe_b64encode(token).decode()
    return token_b64, secret_key


# Função para verificar o token seguro
def verify_reset_token(token, username, secret_key):
    try:
        decoded_token = base64.urlsafe_b64decode(token.encode())
        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        message = f'{username}:{timestamp}'
        expected_token = hmac.new(secret_key, message.encode(), hashlib.sha256).digest()
        return hmac.compare_digest(expected_token, decoded_token)
    except Exception as e:
        return False


# Função para enviar o link de redefinição de senha
def send_reset_email(email, token):
    with open('data/data/config.json', 'r') as f:
        config = json.load(f)

    smtp_server = config['smtp_server']
    smtp_port = config['smtp_port']
    smtp_user = config['smtp_user']
    smtp_password = config['smtp_password']

    reset_link = f"https://example.com/reset_password?token={token}"
    msg = f"Para redefinir sua senha, clique no link a seguir: {reset_link}"

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.sendmail(smtp_user, email, msg)
        server.quit()
        print("E-mail de redefinição de senha enviado.")
    except Exception as e:
        print(f"Erro ao enviar o e-mail de redefinição de senha: {e}")


# Função para obter o e-mail do usuário (Exemplo simplificado)
def get_user_email(username):
    try:
        with open('data/data/users.json', 'r') as f:
            users = json.load(f)
        return users.get(username, {}).get("email", None)
    except FileNotFoundError:
        return None
