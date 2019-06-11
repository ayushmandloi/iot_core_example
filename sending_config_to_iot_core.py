import base64
import datetime
import ssl
import time
import jwt
import paho.mqtt.client as mqtt
import re
import random

from google.oauth2 import service_account
from googleapiclient import discovery
from googleapiclient.errors import HttpError


ssl_private_key_filepath = 'rsa_private.pem'
algorithm = 'RS256' # Either RS256 or ES256
root_cert_filepath = 'roots.pem'
project_id = 'iottest-230219'
gcp_location = 'us-central1'
registry_id = 'tour-registry'
device_id = 'test-dev'
mqtt_bridge_hostname = 'mqtt.googleapis.com'
mqtt_bridge_port = 8883


cur_time = datetime.datetime.utcnow()


def create_jwt():
    token = {
        'iat': cur_time,
        'exp': cur_time + datetime.timedelta(minutes=60),
        'aud': project_id
    }

    with open(ssl_private_key_filepath, 'r') as f:
        private_key = f.read()

    return jwt.encode(token, private_key, algorithm)

_CLIENT_ID = 'projects/{}/locations/{}/registries/{}/devices/{}'.format(project_id, gcp_location, registry_id, device_id)
_MQTT_TELEMETRY_TOPIC = '/devices/{}/events'.format(device_id)
_MQTT_CONFIG_TOPIC = '/devices/{}/config'.format(device_id)
_MQTT_COMMANDS_TOPIC = '/devices/{}/commands/#'.format(device_id)

client = mqtt.Client(client_id=_CLIENT_ID)
# authorization is handled purely with JWT, no user/pass, so username can be whatever
client.username_pw_set(
    username='unused',
    password=create_jwt())

regExp = re.compile('1')

def on_message(unused_client, unused_userdata, message):
    payload = str(message.payload)
    print('Received message \'{}\' on topic \'{}\''.format(payload, message.topic))



def error_str(rc):
    return '{}: {}'.format(rc, mqtt.error_string(rc))


def on_connect(unusued_client, unused_userdata, unused_flags, rc):
    print('on_connect', error_str(rc))


def on_publish(unused_client, unused_userdata, unused_mid):
    print('on_publish')


def on_disconnect(unused_client, unused_userdata, rc):
    """Paho callback for when a device disconnects."""
    print('on_disconnect', error_str(rc))

    # Since a disconnect occurred, the next loop iteration will wait with
    # exponential backoff.
    global should_backoff
    should_backoff = True



def get_client(service_account_json):
    """Returns an authorized API client by discovering the IoT API and creating
    a service object using the service account credentials JSON."""
    api_scopes = ['https://www.googleapis.com/auth/cloud-platform']
    api_version = 'v1'
    discovery_api = 'https://cloudiot.googleapis.com/$discovery/rest'
    service_name = 'cloudiotcore'

    credentials = service_account.Credentials.from_service_account_file(
        service_account_json)
    scoped_credentials = credentials.with_scopes(api_scopes)

    discovery_url = '{}?version={}'.format(
        discovery_api, api_version)

    return discovery.build(
        service_name,
        api_version,
        discoveryServiceUrl=discovery_url,
        credentials=scoped_credentials)


print('Set device configuration')
#client = get_client(project_id, gcp_location, registry_id, device_id, ssl_private_key_filepath,
#                     algorithm, root_cert_filepath, mqtt_bridge_hostname, mqtt_bridge_port)

client = get_client('service.json')
device_path = 'projects/{}/locations/{}/registries/{}/devices/{}'.format(
    project_id, gcp_location, registry_id, device_id)

config = "hello test 7"
config_body = {
    'versionToUpdate': 6,
    'binaryData': base64.urlsafe_b64encode(
        config.encode('utf-8')).decode('ascii')
}

client.projects(
).locations().registries(
).devices().modifyCloudToDeviceConfig(
    name=device_path, body=config_body).execute()
print("done")

