import os
import gettext

# Configurar a tradução com base na configuração do usuário
def set_default_language(language_code="pt_BR"):
    locales_dir = os.path.join(os.path.dirname(__file__), '../locales')
    gettext.bindtextdomain('messages', locales_dir)
    gettext.textdomain('messages')
    language = gettext.translation('messages', localedir=locales_dir, languages=[language_code])
    language.install()
    return language.gettext

# Configura o idioma padrão ao importar o pacote
_ = set_default_language()