import base64
import logging
import json
import os
import boto3
from botocore.exceptions import ClientError
from flatten_json import flatten


logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):

    logger.info('** Incoming event!')
    logger.info(f'Event:\n{event}')

    try:

        # init
        path = get_path(event)
        keyValueDict = {}

        data = json.loads(event['body'])

        logger.info('** Parsing json data **')
        if 'x-kv-block-parser' in event['headers'] and event['headers']['x-kv-block-parser'] == 'true':
            logger.info('** x-kv-block-parser header found **')
            keyValueDict = parse_event_kv_block(data)

        else:
            keyValueDict = parse_event(data)

        logger.info('** Finding tags **')
        # tags = get_tags(data)

        logger.info("** Updating SSM Parameters **")
        for key, value in keyValueDict.items():
            put_param(path, key, value)

            # if len(tags) != 0:
            #     tag_param(path, key, tags)

        response = {
            'statusCode': 200,
            'body': 'Processed.',
            'headers': {
                'Content-Type': 'text/plain'
            }
        }

        return response

    except:
        if 'key' in locals():
            response = {
                'statusCode': 500,
                'body': 'Err: Internal server error while work with: ' + key,
                'headers': {
                    'Content-Type': 'text/plain'
                }
            }
        else:
            response = {
                'statusCode': 500,
                'body': 'Err: Internal server error.',
                'headers': {
                    'Content-Type': 'text/plain'
                }
            }
        return response


def parse_event_kv_block(data):

    logger.info('** Parsing json as key and multi-line json block value **')
    logger.info(f'Data:\n{data}')

    # init
    keyValueDict = {}

    for key in data:
        keyValueDict.update({key: data[key]})

    return keyValueDict


def parse_event(data):

    logger.info('** Parsing json using default parser **')
    logger.info(f'Data:\n{data}')

    flat_data = flatten(data, '.')
    logger.info(f'Flat data:\n{flat_data}')

    if not os.environ['METADATA_AS_PARAM']:
        for key in list(flat_data.keys()):
            if key.startswith('metadata.'):
                del flat_data[key]

    for key, value in flat_data.items():
        if isinstance(value, int):
            flat_data[key] = str(value)

    logger.info(f'Updated Data:\n{flat_data}')

    return flat_data


def get_path(event):

    app_id = event["queryStringParameters"]['appId']
    logger.info(f'** AppId: {app_id}')

    stage = event["queryStringParameters"]['stage']
    logger.info(f'** Stage: {stage}')

    path = f'/{app_id}/{stage}/'

    if 'x-path-override' in event['headers']:
        path = event['headers']['x-path-override']

    logger.info(f'** Path: {path}')
    return path


def put_param(path, key, value):
    """
    Update SSM parameter, only if it differ from the current one.
    """

    logger.info(f'** Key: {key}, Value: {value}')
    # ssm = get_client('ssm')

    if isinstance(value, str) and value.startswith('cipher:') is True:
        value = decrypt(value)
        param_type = 'SecureString'
    else:
        param_type = 'String'

    logger.info(f'** Param Type: {param_type}')
    isKvDifferent = compare_param(path, key, value, param_type)

    if isKvDifferent is True:
        logger.info('** Parameter is different.')
        # try:
        #     put = ssm.put_parameter(
        #         Name=f'{path}{key}',
        #         Value=f'{value}',
        #         Type=param_type,
        #         Overwrite=True
        #     )
        # except ClientError as e:
        #     logger.error(f'Unexpected ClientError: {e}')

        # logger.info(f'Put Response:\n{put}')
        response = True
    else:
        logger.info('** Parameter is current.')
        response = False

    return response


def get_client(service):
    region = os.environ['REGION']
    service = boto3.client(service, region_name=region)

    return service


def decrypt(value):

    key = os.environ['KMS_KEY_ALIAS']
    logger.info(f'** KMS Key: {key}')

    trim_value = value[7:]
    bytes_value = base64.b64decode(trim_value)

    try:
        kms = get_client('kms')
        kms_response = kms.decrypt(CiphertextBlob=bytes_value)
    except ClientError as e:
        logger.critical('Error while decoding by KMS: %s', e)
        value = e
        raise
    else:
        logger.info('** Secret decrypted!')
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
            isDifferent = True
        else:
            isDifferent = False

    except ssm.exceptions.ParameterNotFound:
        logger.info(f'{path}{key} not found in ssm')
        isDifferent = True
        pass  # Dont stop the execution

    except ClientError as e:
        logger.error(f'Unexpected ClientError: {e}')
        isDifferent = True

    return isDifferent
