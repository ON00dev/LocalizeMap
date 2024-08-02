import schedule
import time
from map_api import fetch_store_data
from data_handler import save_to_json

def update_store_data(city: str, state: str, store_type: str = ""):
    print("Atualizando dados de lojas...")
    data = fetch_store_data(city, state, store_type)
    if data:
        save_to_json(data)
        print("Dados atualizados com sucesso.")
    else:
        print("Falha ao atualizar dados.")

def start_scheduler(city: str, state: str, store_type: str, interval_minutes: int):
    schedule.every(interval_minutes).minutes.do(update_store_data, city, state, store_type)
    while True:
        schedule.run_pending()
        time.sleep(1)
