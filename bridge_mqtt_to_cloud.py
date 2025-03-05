import sys
import json
import time
import threading
import requests
from requests.auth import HTTPBasicAuth
import paho.mqtt.client as mqtt
import logging

api_key = ''
refresh_key = ''
token = ''
client_id = ''
uuid = ''

config_file_path = sys.argv[1]

print(config_file_path)

# Konfiguration laden
config_file = open(config_file_path)
config_json = config_file.read()
parsed_json = json.loads(config_json)

#MQTT
mqtt_info       = parsed_json["MQTT"]
MQTT_BROKER     = (mqtt_info["mqtt_broker"])
MQTT_PORT       = (mqtt_info["mqtt_port"])
MQTT_TOPIC      = (mqtt_info["mqtt_topic"])
MQTT_USERNAME   = (mqtt_info["mqtt_username"])
MQTT_PASSWORD   = (mqtt_info["mqtt_password"])

print('##################')
print('#MQTT')
print('MQTT_Broker: '   + str(MQTT_BROKER))
print('MQTT_Port:'      + str(MQTT_PORT))
print('MQTT_Topic: '    + str(MQTT_TOPIC))
print('MQTT_Username: ' + str(MQTT_USERNAME))
print('MQTT_Password: ' + str(MQTT_PASSWORD))

#REST API
rest_info       = parsed_json["REST_API"]
base_url_auth   = (rest_info["base_url_auth"])
base_url_data   = (rest_info["base_url_data"])
username        = (rest_info["username"])
password        = (rest_info["password"])

print('##################')
print('#REST API')
print('Base_URL: ' + str(base_url_auth))
print('Base_URL: ' + str(base_url_data))
print('Username: OK')
print('Password: OK')

#ConnectionData
con_info = parsed_json["ConData"]
update_interval = (con_info["update_interval"])

print('##################')
print('#ConnectionData')
print('Update_Interval: ' + str(update_interval))

# Konfiguration des Loggings
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def on_connect(client, userdata, flags, rc):
    logging.info(f"MQTT - Connected - Success")
    logging.info(f"MQTT - Connected with result code {rc}")
    client.subscribe(MQTT_TOPIC)

def on_message(client, userdata, msg):
    logging.info(f"MQTT - Message received on topic {msg.topic}")
    try:
        json_data_raw = msg.payload.decode('utf-8')
        json_data = json.loads(json_data_raw)

        send_json_data(json_data)
    except json.JSONDecodeError:
        logging.error("MQTT - Error decoding JSON")

# Acces Token Abruf
def get_token():
    global token

    logging.info(f"API - Get Token: ")
    
    headers = {
        'accept': '*/*',
        'Content-Type': 'application/json',
    }
    data = {
        'userName': username,
        'password': password
    }
    
    url = base_url_auth  + f"/api/v1/users/login"

    response = requests.post(url, headers=headers, json=data, verify=True)
    logging.info(f"API - Connected with result code " + str(response.status_code))

    if 200 <= response.status_code <= 299:
        token = response.json().get('access_token')
        logging.info(f"API - Get Token - Success ")
    else:
        logging.info(f"API - Request failed with result: {response.status_code}")
        logging.info(f"API - Failure text: {response.text}")
        return None

def get_client_id():
    global client_id

    logging.info("API - Get Client ID")

    try:
        with open("/proc/cpuinfo", "r") as f:
            for line in f:
                if line.startswith("Serial"):
                    client_id = line.split(":")[1].strip()
                    break
        logging.info("API - Get Client ID - Success")
    except Exception as e:
        print("Error getting the Client ID (CPU ID):", e)

def get_uuid():
    global uuid

    logging.info("API - Get Client UUID")
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'accept': '*/*',
    }

    url = base_url_auth + "/api/v1/devices?clientIdDeviceName=" + client_id
    
    logging.info("API - Get Client UUID URL = " + url)
    
    response = requests.get(url, headers=headers, verify=True)
    response_json = response.json()

    if 200 <= response.status_code <= 299:
        logging.info(f"API - Get Client UUID - Success")
        uuid = response_json["data"][0]["id"]
    elif response.status_code == 401:  # Unauthorized
        logging.info("API - Token invalid, refreshing...")
        get_token()
        response = requests.post(url, headers=headers, verify=True)  # Erneut senden
        response_json = response.json()
        uuid = response_json["data"][0]["id"]
    else:
        logging.info(f"API - Get Client UUID Failed with status {response.status_code}, response: {response.text}")

# Api-Key Abruf
def get_api_key(token):
    global api_key
    global refresh_key

    logging.info("API - Get API Key")
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'accept': '*/*',
    }
    data =  {
        'name': f'{uuid}',
        'validDuration': 'OneMonth'
    }

    url = base_url_auth + f"/api/v1/devices/" + uuid + "/keys"
    logging.info(f"API - URl: " + url)

    response = requests.post(url, headers=headers, json=data, verify=True)

    if 200 <= response.status_code <= 299:
        logging.info(f"API - Get API Key - Success")
        api_key = response.json().get('apiKey')
        refresh_key = response.json().get('refreshKey')
    else:
        logging.info(f"API - Request failed with result: {response.status_code}")
        logging.info(f"API - Failure text: {response.text}")

# API-Key Refresh
def refresh_api_key():
    global api_key
    global refresh_key
    
    logging.info("API - Refresh API Key")

    headers = {
        'Content-Type': 'application/json',
        'accept': '*/*',
    }
    data = {
            'refreshKey': refresh_key,
            'apiKey': api_key}

    url = base_url_auth + "/api/v1/devices/keys/refresh"
    
    logging.info("API - Refreshing API Key...")
    response = requests.post(url, headers=headers, json=data, verify=True)
    
    if 200 <= response.status_code <= 299:
        api_key = response.json().get('new_api_key')
        logging.info("API - API Key refreshed successfully.")
    else:
        logging.error(f"API - Failed to refresh API Key: {response.status_code}, {response.text}")

# Data send
def send_json_data(data):
    logging.info("API - Send Data - Start")

    headers = {
        'X-API-KEY': api_key,
        'Content-Type': 'application/json',
        'accept': '*/*',
    }

    url = base_url_data + "/api/v2/livedata"
    logging.info("API - Send Data - LiveData_URL: " + url)

    try:
        response = requests.post(url, headers=headers, json=data, verify=True)
    except ConnectionError:
        logging.info("API - Send Data - Connection Error")
    else:
        if 200 <= response.status_code <= 299:
            logging.info(f"API - Send Data - Success")
        elif response.status_code == 401:
            logging.info(f"API - Send Data - Failed with status {response.status_code}, response: {response.text}")

            refresh_api_key()
            headers["X-API-KEY"] = api_key

            response = requests.post(url, headers=headers, json=data, verify=True)  # Erneut senden
        elif response.status_code == 404:
            logging.info(f"API - Send Data - Connection Problem")
            logging.info(f"API - Send Data - Failed with status {response.status_code}, response: {response.text}")
        else:
            logging.info(f"API - Send Data - Failed with status {response.status_code}, response: {response.text}")
    finally:
        logging.info("API - Send Data - Stop")

if __name__ == "__main__":
    # client id holen
    get_client_id()

    # token holen
    get_token()

    # uuid holen
    get_uuid()

    # api key holen
    get_api_key(token)
    
    # Include a 'data_updated' flag in userdata
    client = mqtt.Client(userdata={'latest_json': None, 'data_updated': False})
    if MQTT_USERNAME and MQTT_PASSWORD:
        client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
        
    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(MQTT_BROKER, MQTT_PORT, update_interval)

    try:
        # mqtt client im loop laufen lassen
        client.loop_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down client...")
        client.disconnect()
