import time
import random
import requests
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup

def get_proxies():
    url = 'https://www.sslproxies.org/'
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    proxies = []
    for row in soup.find(id='proxylisttable').find_all('tr')[1:]:
        tds = row.find_all('td')
        if len(tds) > 1:
            ip = tds[0].text
            port = tds[1].text
            proxies.append(f'{ip}:{port}')
    return proxies

def buscar_lojas_google_maps(cidade, query):
    proxies = get_proxies()
    random.shuffle(proxies)
    
    # Configuração inicial do WebDriver
    chrome_options = Options()
    driver_path = '/path/to/chromedriver'  # Atualize com o caminho para o seu ChromeDriver
    
    lojas = []
    for proxy in proxies:
        try:
            chrome_options.add_argument(f'--proxy-server={proxy}')
            driver = webdriver.Chrome(driver_path, options=chrome_options)
            driver.get('https://www.google.com/maps')
            time.sleep(random.uniform(3, 5))  # Esperar a página carregar

            # Procurar pela cidade e tipo de loja
            search_box = driver.find_element_by_css_selector("input[aria-label='Search Google Maps']")
            search_box.send_keys(f"{query} in {cidade}")
            search_box.send_keys(Keys.RETURN)
            time.sleep(random.uniform(5, 7))  # Esperar os resultados carregarem

            # Obter HTML da página de resultados
            page_source = driver.page_source
            soup = BeautifulSoup(page_source, 'html.parser')

            # Extrair informações sobre as lojas
            for result in soup.select('.section-result-content'):
                nome = result.select_one('.section-result-title span').text if result.select_one('.section-result-title span') else 'N/A'
                endereco = result.select_one('.section-result-location').text if result.select_one('.section-result-location') else 'N/A'
                lojas.append({'nome': nome, 'endereco': endereco})
            
            driver.quit()
            # Se obteve resultados suficientes, pode sair do loop
            if len(lojas) > 10:  # Ajuste conforme necessário
                break
        except Exception as e:
            print(f"Erro com proxy {proxy}: {e}")
            driver.quit()
    
    return lojas

cidade = "Volta Redonda, RJ, Brazil"
query = "construction|building supplies|drywall|gesso"
lojas = buscar_lojas_google_maps(cidade, query)

for loja in lojas:
    print(f"Nome: {loja['nome']}, Endereço: {loja['endereco']}")

