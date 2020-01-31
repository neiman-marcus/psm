import base64
import boto3
import logging
import json
from flatten_json import flatten
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    
    logger.info('Incoming event!')
    logger.info(f'Event:\n{event}')

    try:
        path, flat_data, tags = parse_event(event)

        ssm = get_client('ssm')

        for key,value in flat_data.items():
            put_param(path, key, value, ssm)

            if len(tags) != 0:
                tag_param(path, key, tags, ssm)

        response = {
            'statusCode': 200,
            'body': 'Processed.',
            'headers': {
                'Content-Type': 'text/plain'
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

    app_id = event["queryStringParameters"]['appId']
    logger.info(f'AppId: {app_id}')

    stage = event["queryStringParameters"]['stage']
    logger.info(f'Stage: {stage}')

    if 'x-path-override' in event['headers']:
        path = event['headers']['x-path-override']
    else:
        path = f'/{app_id}/{stage}/'
    logger.info(f'Path Override: {path}')

    data = json.loads(event['body'])
    logger.info(f'Data:\n{data}')

    flat_data = flatten(data, '.')
    logger.info(f'Flat data:\n{flat_data}')

    tags = {}
    
    for key,value in flat_data.items():
        if key.startswith('metadata.tags.'):
            key = key[14:]
            new_tag = {key: value}
            tags = {**tags, **new_tag}
    
    logger.info(f'Tags found: {tags}')
    
    if not os.environ['METADATA_AS_PARAM']:
        for key in list(flat_data.keys()):
            if key.startswith('metadata.'):
                del flat_data[key]
    
    for key,value in flat_data.items():
        if isinstance(value,int):
            flat_data[key] = str(value)

    
    logger.info(f'Updated Data:\n{flat_data}')

    return path, flat_data, tags

def put_param(path, key, value, ssm):

    logger.info(f'Key: {key}, Value: {value}')

    if isinstance(value,str) and value.startswith('cipher:') is True:
        value = decrypt(value)
        param_type = 'SecureString'
    else:
        param_type = 'String'

    logger.info(f'Param Type: {param_type}')

    compare = compare_param(path, key, value, param_type)

    if compare is True:
        put = ssm.put_parameter(
            Name=f'{path}{key}',
            Value=value,
            Type=param_type,
            Overwrite=True
        )
    
        logger.info(f'Put Response:\n{put}')
    
        response = True
    else:
        logger.info('Parameter is current.')
        response = False

    return response

def get_client(service):
    region = os.environ['REGION']
    service = boto3.client(service, region_name=region)

    return service

def decrypt(value):

    key = os.environ['KMS_KEY_ALIAS']
    logger.info(f'KMS Key: {key}')

    trim_value = value[7:]
    bytes_value = base64.b64decode(trim_value)

    kms = get_client('kms')
    kms_response = kms.decrypt(CiphertextBlob=bytes_value)
    logger.info('Secret decrypted!')

    bytes_decrypted_value = kms_response['Plaintext']
    value = bytes_decrypted_value.decode('utf-8')

    return value

def compare_param(path, key, value, param_type):

    ssm = get_client('ssm')
    
    try:
        get = ssm.get_parameter(
            Name=f'{path}{key}',
            WithDecryption=True
        )

        existing_value = get['Parameter']['Value']
        existing_type = get['Parameter']['Type']

        if existing_value != value or existing_type != param_type:
            compare = True
        else:
            compare = False
    except:
        compare = True

    return compare

def tag_param(path, key, tags, ssm):

    logger.info('Adding Tags')

    psm_param = {'ManagedBy': 'psm'}
    tags = {**tags, **psm_param}
    
    for tag_key,tag_value in tags.items():

        tag = ssm.add_tags_to_resource(
            ResourceType='Parameter',
            ResourceId=f'{path}{key}',
            Tags=[
                {
                    'Key': tag_key,
                    'Value': tag_value
                },
            ]
        )
    
        logger.info(f'Tag Response:\n{tag}')

    return tag
