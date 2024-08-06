import logging
import sys
import os
from PyQt6.QtWidgets import QApplication, QDialog
from gui import LoginDialog, MainWindow

def setup_logging():
    log_dir = os.path.join(os.path.dirname(__file__), '../data/data')
    os.makedirs(log_dir, exist_ok=True)  # Cria o diretório se não existir
    log_file = os.path.join(log_dir, 'app.log')

    logging.basicConfig(
        filename=log_file,
        level=logging.DEBUG,  # Define o nível de log para DEBUG
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def main():
    app = QApplication(sys.argv)
    logging.info("Aplicação iniciada")

    # Cria a janela de login e mostra
    login_dialog = LoginDialog()
    if login_dialog.exec() == QDialog.DialogCode.Accepted:
        # Login bem-sucedido, mostrar a janela principal
        main_window = MainWindow()
        main_window.show()
        sys.exit(app.exec())
    else:
        # Login falhou ou foi cancelado, encerrar a aplicação
        sys.exit(0)

if __name__ == "__main__":
    setup_logging()
    try:
        main()
    except Exception as e:
        logging.error(f"Erro crítico na aplicação: {e}")
