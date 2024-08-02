import folium
import json


def generate_map(file_path='data/stores.json'):
    # Carregar dados das lojas
    with open(file_path, 'r') as f:
        data = json.load(f)

    # Definir o ponto de início do mapa
    if data:
        first_store = data[0]
        lat, lon = 0, 0  # Substituir por coordenadas reais se disponíveis
    else:
        lat, lon = -23.5505, -46.6333  # Padrão: São Paulo, SP

    # Criar mapa
    m = folium.Map(location=[lat, lon], zoom_start=12)

    # Adicionar marcadores para cada loja
    for store in data:
        store_name = store.get('name', 'Loja')
        store_address = store.get('address', 'Endereço desconhecido')
        folium.Marker(
            location=[lat, lon],  # Substituir por coordenadas reais
            popup=f"<b>{store_name}</b><br>{store_address}",
            icon=folium.Icon(icon="info-sign")
        ).add_to(m)

    # Salvar mapa como HTML
    map_path = 'data/map.html'
    m.save(map_path)
    return map_path
