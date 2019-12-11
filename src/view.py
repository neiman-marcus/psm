import base64
import boto3
import logging
import json
from flatten_json import unflatten
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    
    logger.info('Incoming event!')
    logger.info(f'Event:\n{event}')

    try:
        app_id, stage = parse_event(event)

        naked_params = get_params(app_id, stage)

        params = parse_params(app_id, stage, naked_params)

        response = {
            'statusCode': 200,
            'body': params,
            'headers': {
                'Content-Type': 'application/json'
            }
        }

        return response

    except:

        response = {
            'statusCode': 500,
            'body': 'Err: Internal server error.',
            'headers': {
                'Content-Type': 'text/plain'
            }
        }

        return response

def parse_event(event):

    app_id = event['queryStringParameters']['appId']
    logger.info(f'AppId: {app_id}')

    stage = event['queryStringParameters']['stage']
    logger.info(f'Stage: {stage}')

    return app_id, stage

def get_params(app_id, stage):

    ssm = get_client('ssm')
    
    response = ssm.get_parameters_by_path(
        Path=f'/{app_id}/{stage}/',
        Recursive=True,
        WithDecryption=True,
    )

    logger.info('Got params!')

    naked_params = response['Parameters']

    return naked_params

def get_client(service):
    region = os.environ['REGION']
    client = boto3.client(service, region_name=region)

    return client

def parse_params(app_id, stage, naked_params):

    flat_params = {}

    for param in naked_params:

        if 'SecureString' in param.values():
            param['Value'] = encrypt(param['Value'])

        key = param['Name']
        key = key.replace(f'/{app_id}/{stage}/', '')
        value = param['Value']

        try:
            value = int(value)
        except:
            logger.info('Value is not an int.')

        new_param = {key: value}
        flat_params = {**flat_params, **new_param}
    
    logger.info('Flat params parsed!')
    
    unflat_params = unflatten(flat_params, '.')
    logger.info(f'Params: {unflat_params}')

    params = json.dumps(unflat_params)

    return params

def encrypt(secret):

    key = os.environ['KMS_KEY_ALIAS']
    logger.info(f'KMS Key: {key}')

    kms = get_client('kms')
    kms_response = kms.encrypt(KeyId=key, Plaintext=secret.encode())
    logger.info(f'KMS Response:\n{kms_response}')

    blob = base64.b64encode(kms_response['CiphertextBlob'])
    logger.info(f'Blob: {blob}')

    cipher = 'cipher:' + blob.decode()

    return cipher