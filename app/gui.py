from PyQt6.QtWidgets import (
    QMainWindow, QPushButton, QVBoxLayout, QWidget, QLineEdit, QLabel,
    QComboBox, QMessageBox, QDialog, QTextEdit, QDateEdit, QCheckBox, QFileDialog
)
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import Qt, QDate
import pandas as pd
import logging
import gettext
import os
from auth import check_credentials, register_user, reset_password, get_user_role, generate_reset_token, verify_reset_token, send_reset_email, get_user_email
from data_handler import save_to_json, save_to_excel, save_to_csv
from map_api import fetch_store_data
from map_view import generate_map
from notification import notify_admin_error

# Configurar a tradução com base na configuração do usuário
def set_language(language_code):
    locales_dir = os.path.join(os.path.dirname(__file__), '../locales')
    gettext.bindtextdomain('messages', locales_dir)
    gettext.textdomain('messages')
    language = gettext.translation('messages', localedir=locales_dir, languages=[language_code])
    language.install()
    return language.gettext

# Inicializar com idioma padrão
_ = set_language('pt_BR')

class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(_("Login"))
        self.setGeometry(100, 100, 300, 200)
        self.init_ui()

    def init_ui(self):
        self.layout = QVBoxLayout()
        self.username_label = QLabel(_("Usuário:"))
        self.username_input = QLineEdit(self)
        self.password_label = QLabel(_("Senha:"))
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_button = QPushButton(_("Login"))
        self.login_button.clicked.connect(self.login)
        self.reset_password_button = QPushButton(_("Esqueceu a senha?"))
        self.reset_password_button.clicked.connect(self.show_reset_password)

        self.layout.addWidget(self.username_label)
        self.layout.addWidget(self.username_input)
        self.layout.addWidget(self.password_label)
        self.layout.addWidget(self.password_input)
        self.layout.addWidget(self.login_button)
        self.layout.addWidget(self.reset_password_button)

        self.setLayout(self.layout)

    def login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        if check_credentials(username, password):
            QMessageBox.information(self, _("Sucesso"), _("Login realizado com sucesso."))
            self.accept()
        else:
            QMessageBox.warning(self, _("Erro"), _("Nome de usuário ou senha incorretos."))

    def show_reset_password(self):
        recovery_dialog = PasswordRecoveryDialog()
        recovery_dialog.exec()

class PasswordRecoveryDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(_("Recuperar Senha"))
        self.setGeometry(100, 100, 300, 200)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.email_label = QLabel(_("Digite seu e-mail:"))
        self.email_input = QLineEdit(self)
        self.send_button = QPushButton(_("Enviar E-mail de Redefinição"))
        self.send_button.clicked.connect(self.send_recovery_email)

        layout.addWidget(self.email_label)
        layout.addWidget(self.email_input)
        layout.addWidget(self.send_button)

        self.setLayout(layout)

    def send_recovery_email(self):
        email = self.email_input.text().strip()
        if email:
            username = self.get_username_by_email(email)
            if username:
                token, secret_key = generate_reset_token(username)
                send_reset_email(email, token)
                QMessageBox.information(self, _("Sucesso"), _("E-mail de redefinição de senha enviado."))
                self.accept()
            else:
                QMessageBox.warning(self, _("Erro"), _("E-mail não encontrado."))
        else:
            QMessageBox.warning(self, _("Erro"), _("Por favor, insira um e-mail válido."))

    def get_username_by_email(self, email):
        # Exemplo simplificado para obter o nome de usuário pelo e-mail
        try:
            with open('data/users.json', 'r') as f:
                users = json.load(f)
            for username, details in users.items():
                if details.get("email") == email:
                    return username
        except FileNotFoundError:
            return None
        return None

class ResetPasswordDialog(QDialog):
    def __init__(self, token, username, secret_key):
        super().__init__()
        self.token = token
        self.username = username
        self.secret_key = secret_key
        self.setWindowTitle(_("Redefinir Senha"))
        self.setGeometry(100, 100, 300, 200)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.new_password_label = QLabel(_("Nova Senha:"))
        self.new_password_input = QLineEdit(self)
        self.new_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.reset_button = QPushButton(_("Redefinir Senha"))
        self.reset_button.clicked.connect(self.reset_password)

        layout.addWidget(self.new_password_label)
        layout.addWidget(self.new_password_input)
        layout.addWidget(self.reset_button)

        self.setLayout(layout)

    def reset_password(self):
        new_password = self.new_password_input.text().strip()
        if verify_reset_token(self.token, self.username, self.secret_key):
            if reset_password(self.username, new_password, None):  # A função reset_password precisa ser ajustada
                QMessageBox.information(self, _("Sucesso"), _("Senha redefinida com sucesso."))
                self.accept()
            else:
                QMessageBox.warning(self, _("Erro"), _("Erro ao redefinir a senha."))
        else:
            QMessageBox.warning(self, _("Erro"), _("Token inválido ou expirado."))

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(_("Loja Finder"))
        self.setGeometry(100, 100, 600, 400)
        self.setWindowIcon(QIcon('assets/icons/pin_mapa.png'))

        self.layout = QVBoxLayout()
        self.init_ui()

        container = QWidget()
        container.setLayout(self.layout)
        self.setCentralWidget(container)

        self.show_login()
        self.start_auto_update()

    def init_ui(self):
        # Outros elementos da GUI...

        self.recover_password_button = QPushButton(_("Recuperar Senha"))
        self.recover_password_button.clicked.connect(self.show_password_recovery_dialog)
        self.layout.addWidget(self.recover_password_button)

    def show_password_recovery_dialog(self):
        recovery_dialog = PasswordRecoveryDialog()
        recovery_dialog.exec()

    def show_login(self):
        login_dialog = LoginDialog()
        if login_dialog.exec() != QDialog.DialogCode.Accepted:
            self.close()
        else:
            self.username = login_dialog.username_input.text().strip()
            self.role = get_user_role(self.username)
            self.init_ui()  # Re-renderizar a interface para considerar permissões

    def start_auto_update(self):
        # Configuração do agendamento automático...
        pass
