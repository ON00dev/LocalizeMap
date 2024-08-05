import requests
import json
import logging

def fetch_store_data(city: str, state: str, store_type: str = ""):
    with open('data/data/config.json', 'r') as f:
        config = json.load(f)

    logging.info(f"Buscando lojas em {city}, {state}, tipo: {store_type}")

    url = f"https://places.ls.hereapi.com/places/v1/discover/explore"
    params = {
        'q': store_type if store_type else 'shop',
        'at': f'{city},{state}',
        'apiKey': config['here_app_id'],
        'app_code': config['here_app_code']
    }
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        data = response.json()
        stores = [
            {
                "name": place["title"],
                "phone": place.get("contacts", {}).get("phone", [{}])[0].get("value", ""),
                "address": place.get("vicinity", ""),
                "email": place.get("contacts", {}).get("email", [{}])[0].get("value", "")
            }
            for place in data["results"]["items"]
        ]
        logging.info(f"{len(stores)} lojas encontradas")
        return stores
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro na requisição: {e}")
        return []
