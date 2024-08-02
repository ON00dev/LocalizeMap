import smtplib
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def send_email(subject, message, to_email):
    with open('data/config.json', 'r') as f:
        config = json.load(f)

    smtp_server = config['smtp_server']
    smtp_port = config['smtp_port']
    smtp_user = config['smtp_user']
    smtp_password = config['smtp_password']

    msg = MIMEMultipart()
    msg['From'] = smtp_user
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(message, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.send_message(msg)
        server.quit()
        print("E-mail enviado com sucesso.")
    except Exception as e:
        print(f"Erro ao enviar e-mail: {e}")


def notify_admin_new_user(username):
    with open('data/config.json', 'r') as f:
        config = json.load(f)
    admin_email = config['admin_email']
    subject = "Novo Registro de Usuário"
    message = f"Um novo usuário se registrou: {username}"
    send_email(subject, message, admin_email)


def notify_admin_error(error_message):
    with open('data/config.json', 'r') as f:
        config = json.load(f)
    admin_email = config['admin_email']
    subject = "Erro Crítico no Sistema"
    message = f"Ocorreu um erro crítico: {error_message}"
    send_email(subject, message, admin_email)
