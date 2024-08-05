import json
import pandas as pd

def save_to_json(data, file_path='data/data/stores.json'):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

def save_to_excel(file_path='data/data/results.xlsx'):
    with open('data/data/stores.json', 'r') as f:
        data = json.load(f)
    df = pd.DataFrame(data)
    df.to_excel(file_path, index=False)

def save_to_csv(file_path='data/data/results.csv'):
    with open('data/data/stores.json', 'r') as f:
        data = json.load(f)
    df = pd.DataFrame(data)
    df.to_csv(file_path, index=False)
