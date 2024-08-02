from PyQt6.QtWidgets import (
    QMainWindow, QPushButton, QVBoxLayout, QWidget, QLineEdit, QLabel,
    QComboBox, QMessageBox, QDialog, QTextEdit, QDateEdit, QCheckBox, QFileDialog
)
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import Qt, QDate
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtCore import QUrl
import pandas as pd
import logging
import gettext
import os
from auth import check_credentials, register_user, reset_password, get_user_role, generate_2fa_code, send_2fa_code
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
        self.expected_2fa_code = None

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
            # Gerar código de verificação 2FA
            self.expected_2fa_code = generate_2fa_code()
            user_email = get_user_email(username)  # Implementar a função get_user_email
            send_2fa_code(user_email, self.expected_2fa_code)

            # Mostrar diálogo de 2FA
            two_factor_dialog = TwoFactorAuthDialog(user_email, self.expected_2fa_code)
            if two_factor_dialog.exec() == QDialog.DialogCode.Accepted:
                QMessageBox.information(self, _("Sucesso"), _("Login realizado com sucesso."))
                self.accept()
            else:
                QMessageBox.warning(self, _("Erro"), _("Verificação de dois fatores falhou."))
        else:
            QMessageBox.warning(self, _("Erro"), _("Nome de usuário ou senha incorretos."))

    def show_reset_password(self):
        reset_password_dialog = ResetPasswordDialog()
        reset_password_dialog.exec()


class TwoFactorAuthDialog(QDialog):
    def __init__(self, email, expected_code):
        super().__init__()
        self.setWindowTitle(_("Verificação de Dois Fatores"))
        self.setGeometry(100, 100, 300, 200)
        self.email = email
        self.expected_code = expected_code
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.label = QLabel(_("Insira o código enviado para o seu e-mail:"))
        self.code_input = QLineEdit(self)
        self.verify_button = QPushButton(_("Verificar"))
        self.verify_button.clicked.connect(self.verify_code)

        layout.addWidget(self.label)
        layout.addWidget(self.code_input)
        layout.addWidget(self.verify_button)

        self.setLayout(layout)

    def verify_code(self):
        code_entered = self.code_input.text().strip()
        if code_entered == str(self.expected_code):
            QMessageBox.information(self, _("Sucesso"), _("Verificação de dois fatores concluída."))
            self.accept()
        else:
            QMessageBox.warning(self, _("Erro"), _("Código incorreto. Por favor, tente novamente."))


class ResetPasswordDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(_("Recuperar Senha"))
        self.setGeometry(100, 100, 300, 200)
        self.init_ui()

    def init_ui(self):
        self.layout = QVBoxLayout()
        self.username_label = QLabel(_("Usuário:"))
        self.username_input = QLineEdit(self)
        self.security_answer_label = QLabel(_("Resposta de Segurança:"))
        self.security_answer_input = QLineEdit(self)
        self.new_password_label = QLabel(_("Nova Senha:"))
        self.new_password_input = QLineEdit(self)
        self.new_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.reset_button = QPushButton(_("Redefinir Senha"))
        self.reset_button.clicked.connect(self.reset_password)

        self.layout.addWidget(self.username_label)
        self.layout.addWidget(self.username_input)
        self.layout.addWidget(self.security_answer_label)
        self.layout.addWidget(self.security_answer_input)
        self.layout.addWidget(self.new_password_label)
        self.layout.addWidget(self.new_password_input)
        self.layout.addWidget(self.reset_button)

        self.setLayout(self.layout)

    def reset_password(self):
        username = self.username_input.text().strip()
        security_answer = self.security_answer_input.text().strip()
        new_password = self.new_password_input.text().strip()
        if reset_password(username, new_password, security_answer):
            QMessageBox.information(self, _("Sucesso"), _("Senha redefinida com sucesso."))
            self.accept()
        else:
            QMessageBox.warning(self, _("Erro"), _("Usuário ou resposta de segurança incorretos."))


class HelpDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(_("Ajuda"))
        self.setGeometry(100, 100, 400, 300)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        help_text = QTextEdit()
        help_text.setReadOnly(True)
        help_text.setPlainText(self.get_help_text())
        layout.addWidget(help_text)
        self.setLayout(layout)

    def get_help_text(self):
        return _(
            "Bem-vindo ao sistema Loja Finder.\n\n"
            "Aqui estão algumas dicas para usar o sistema:\n"
            "1. Para buscar lojas, preencha a cidade e o estado, "
            "e opcionalmente o tipo de loja. Clique em 'Buscar Lojas'.\n"
            "2. Você pode salvar os resultados em formato Excel ou CSV clicando em 'Salvar'.\n"
            "3. Para visualizar as lojas no mapa, clique em 'Mostrar Mapa'.\n"
            "4. Use a seção 'Configurações' para ajustar suas preferências.\n"
            "5. Se precisar redefinir sua senha, clique em 'Esqueceu a senha?'.\n\n"
            "Para mais informações, entre em contato com o suporte."
        )

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

class ReportDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(_("Gerar Relatório"))
        self.setGeometry(100, 100, 400, 300)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.date_from_label = QLabel(_("Data de Início:"))
        self.date_from = QDateEdit(self)
        self.date_from.setCalendarPopup(True)
        self.date_from.setDate(QDate.currentDate().addMonths(-1))
        layout.addWidget(self.date_from_label)
        layout.addWidget(self.date_from)

        self.date_to_label = QLabel(_("Data de Fim:"))
        self.date_to = QDateEdit(self)
        self.date_to.setCalendarPopup(True)
        self.date_to.setDate(QDate.currentDate())
        layout.addWidget(self.date_to_label)
        layout.addWidget(self.date_to)

        self.filter_store_type_label = QLabel(_("Filtrar por Tipo de Loja:"))
        self.filter_store_type = QLineEdit(self)
        layout.addWidget(self.filter_store_type_label)
        layout.addWidget(self.filter_store_type)

        self.include_contacts_checkbox = QCheckBox(_("Incluir Contatos"))
        layout.addWidget(self.include_contacts_checkbox)

        self.generate_button = QPushButton(_("Gerar Relatório"))
        self.generate_button.clicked.connect(self.generate_report)
        layout.addWidget(self.generate_button)

        self.setLayout(layout)

    def generate_report(self):
        # Obter critérios de filtro
        date_from = self.date_from.date().toPyDate()
        date_to = self.date_to.date().toPyDate()
        store_type = self.filter_store_type.text().strip()
        include_contacts = self.include_contacts_checkbox.isChecked()

        # Carregar dados
        try:
            data = pd.read_json('data/stores.json')

            # Aplicar filtros
            if not data.empty:
                data['date'] = pd.to_datetime(data['date'], errors='coerce')
                data = data[(data['date'] >= date_from) & (data['date'] <= date_to)]

                if store_type:
                    data = data[data['type'].str.contains(store_type, case=False, na=False)]

                if not include_contacts:
                    data = data.drop(columns=['phone', 'email'], errors='ignore')

                # Salvar relatório
                report_file_path, _ = QFileDialog.getSaveFileName(self, _("Salvar Relatório"), "",
                                                                  "Excel Files (*.xlsx);;CSV Files (*.csv)")
                if report_file_path:
                    if report_file_path.endswith('.xlsx'):
                        data.to_excel(report_file_path, index=False)
                    elif report_file_path.endswith('.csv'):
                        data.to_csv(report_file_path, index=False)
                    QMessageBox.information(self, _("Sucesso"), _("Relatório gerado com sucesso."))
                else:
                    QMessageBox.warning(self, _("Erro"), _("Por favor, forneça um caminho de arquivo válido."))

        except Exception as e:
            logging.error(f"Erro ao gerar relatório: {e}")
            QMessageBox.warning(self, _("Erro"), _("Não foi possível gerar o relatório."))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(_("Loja Finder"))
        self.setGeometry(100, 100, 600, 400)
        self.setWindowIcon(QIcon('assets/icons/app_icon.png'))

        self.layout = QVBoxLayout()
        self.init_ui()

        container = QWidget()
        container.setLayout(self.layout)
        self.setCentralWidget(container)

        self.show_login()
        self.start_auto_update()

    def init_ui(self):
        self.city_label = QLabel(_("Cidade:"))
        self.city_input = QLineEdit(self)
        self.city_input.setPlaceholderText(_("Digite a cidade"))
        self.layout.addWidget(self.city_label)
        self.layout.addWidget(self.city_input)

        self.state_label = QLabel(_("Estado:"))
        self.state_input = QLineEdit(self)
        self.state_input.setPlaceholderText(_("Digite o estado"))
        self.layout.addWidget(self.state_label)
        self.layout.addWidget(self.state_input)

        self.type_label = QLabel(_("Tipo de Loja:"))
        self.type_input = QLineEdit(self)
        self.type_input.setPlaceholderText(_("Ex: supermercado, livraria"))
        self.layout.addWidget(self.type_label)
        self.layout.addWidget(self.type_input)

        self.fetch_button = QPushButton(_("Buscar Lojas"))
        self.fetch_button.setIcon(QIcon('assets/icons/search_icon.png'))
        self.fetch_button.clicked.connect(self.fetch_stores)
        self.layout.addWidget(self.fetch_button)

        self.save_button = QPushButton(_("Salvar em Excel ou CSV"))
        self.save_button.setIcon(QIcon('assets/icons/save_icon.png'))
        self.save_button.clicked.connect(self.save_data)
        self.layout.addWidget(self.save_button)

        self.map_button = QPushButton(_("Mostrar Mapa"))
        self.map_button.setIcon(QIcon('assets/icons/map_icon.png'))
        self.map_button.clicked.connect(self.show_map)
        self.layout.addWidget(self.map_button)

        self.help_button = QPushButton(_("Ajuda"))
        self.help_button.setIcon(QIcon('assets/icons/help_icon.png'))
        self.help_button.clicked.connect(self.show_help)
        self.layout.addWidget(self.help_button)

        self.report_button = QPushButton(_("Gerar Relatório"))
        self.report_button.setIcon(QIcon('assets/icons/report_icon.png'))
        self.report_button.clicked.connect(self.show_report_dialog)
        self.layout.addWidget(self.report_button)

        if hasattr(self, 'role') and self.role == "admin":
            self.admin_button = QPushButton(_("Administração"))
            self.admin_button.setIcon(QIcon('assets/icons/admin_icon.png'))
            self.admin_button.clicked.connect(self.admin_panel)
            self.layout.addWidget(self.admin_button)

        self.logout_button = QPushButton(_("Logout"))
        self.logout_button.setIcon(QIcon('assets/icons/logout_icon.png'))
        self.logout_button.clicked.connect(self.logout)
        self.layout.addWidget(self.logout_button)

        self.language_selector = QComboBox()
        self.language_selector.addItems(["pt_BR", "en_US", "fr_FR"])
        self.language_selector.currentTextChanged.connect(self.change_language)
        self.layout.addWidget(self.language_selector)

        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(self.status_label)

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

    def fetch_stores(self):
        city = self.city_input.text().strip()
        state = self.state_input.text().strip()
        store_type = self.type_input.text().strip()

        if not city or not state:
            QMessageBox.warning(self, _("Erro de Validação"), _("Por favor, insira uma cidade e um estado válidos."))
            return

        logging.info(f"Iniciando busca por {store_type} em {city}, {state}")
        self.status_label.setText(_("Buscando lojas..."))
        try:
            data = fetch_store_data(city, state, store_type)
            if data:
                save_to_json(data)
                self.status_label.setText(_("Dados buscados e salvos com sucesso."))
                logging.info("Dados buscados e salvos com sucesso.")
            else:
                raise ValueError("Nenhum dado encontrado")
        except Exception as e:
            QMessageBox.warning(self, _("Erro na Busca"),
                                _("Não foi possível buscar dados para a cidade e estado fornecidos."))
            self.status_label.setText(_("Erro ao buscar dados."))
            logging.error(f"Erro ao buscar dados: {e}")
            notify_admin_error(str(e))

    def save_data(self):
        options = "Excel Files (*.xlsx);;CSV Files (*.csv)"
        file_path, selected_filter = QFileDialog.getSaveFileName(self, _("Salvar Arquivo"), "", options)
        if file_path:
            try:
                if "Excel" in selected_filter:
                    save_to_excel(file_path)
                    self.status_label.setText(_("Dados salvos em Excel com sucesso."))
                elif "CSV" in selected_filter:
                    save_to_csv(file_path)
                    self.status_label.setText(_("Dados salvos em CSV com sucesso."))
                logging.info(f"Dados salvos em {file_path}")
            except Exception as e:
                logging.error(f"Erro ao salvar dados: {e}")
                QMessageBox.warning(self, _("Erro ao Salvar"), _("Não foi possível salvar os dados."))
        else:
            self.status_label.setText(_("Salvamento cancelado."))

    def show_map(self):
        try:
            map_path = generate_map()
            map_view = QWebEngineView()
            map_view.setWindowTitle(_("Mapa das Lojas"))
            map_view.setGeometry(100, 100, 800, 600)
            map_view.load(QUrl.fromLocalFile(map_path))
            map_view.show()
            logging.info("Mapa exibido com sucesso.")
        except Exception as e:
            logging.error(f"Erro ao gerar o mapa: {e}")
            QMessageBox.warning(self, _("Erro ao Mostrar Mapa"), _("Não foi possível gerar o mapa."))

    def show_help(self):
        help_dialog = HelpDialog()
        help_dialog.exec()

    def show_report_dialog(self):
        report_dialog = ReportDialog()
        report_dialog.exec()

    def show_login(self):
        login_dialog = LoginDialog()
        if login_dialog.exec() != QDialog.DialogCode.Accepted:
            self.close()
        else:
            self.username = login_dialog.username_input.text().strip()
            self.role = get_user_role(self.username)
            self.init_ui()  # Re-renderizar a interface para considerar permissões

    def change_language(self, language_code):
        global _
        _ = set_language(language_code)
        self.init_ui()  # Recarregar a interface com o novo idioma

    def admin_panel(self):
        QMessageBox.information(self, _("Administração"), _("Bem-vindo ao painel de administração."))

    def logout(self):
        self.username = None
        self.role = "user"
        QMessageBox.information(self, _("Logout"), _("Você foi desconectado."))
        self.show_login()

    def start_auto_update(self):
        # Configuração do agendamento automático...
        pass
