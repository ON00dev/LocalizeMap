import logging
from gui import MainWindow
from PyQt6.QtWidgets import QApplication
import sys


def setup_logging():
    # Configuração do logging com nível de log e formato detalhado
    logging.basicConfig(
        filename='data/app.log',
        level=logging.DEBUG,  # Captura todos os níveis de log
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


if __name__ == "__main__":
    setup_logging()
    logging.info("Aplicação iniciada")

    try:
        app = QApplication(sys.argv)
        main_window = MainWindow()
        main_window.show()
        sys.exit(app.exec())
    except Exception as e:
        logging.error(f"Erro crítico na aplicação: {e}")
