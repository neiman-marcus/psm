import base64
import logging
import os
import uuid
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):

    logger.info('Incoming event!')

    try:

        secret = get_secret(event)

        if secret is None:

            response = {
                'statusCode': 400,
                'body': 'Err: No secret supplied with POST method.',
                'headers': {
                    'Content-Type': 'text/plain'
                }
            }

            logger.info('Err: No secret supplied with POST method.')

            return response

        cipher = encrypt(secret)

        logger.info(cipher)

        response = {
            'statusCode': 200,
            'body': cipher,
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


def get_secret(event):

    method = event['httpMethod']
    logger.info(f'Method: {method}')

    if method == 'POST':
        secret = event['body']
        logger.info('Secret parsed!')

    else:
        secret = str(uuid.uuid4())
        logger.info('Secret generated!')

    return secret


def encrypt(secret):

    key = os.environ['KMS_KEY_ALIAS']
    logger.info(f'KMS Key: {key}')

    kms = get_client()
    kms_response = kms.encrypt(KeyId=key, Plaintext=secret.encode())
    logger.info(f'KMS Response:\n{kms_response}')

    blob = base64.b64encode(kms_response['CiphertextBlob'])
    logger.info(f'Blob: {blob}')

    cipher = 'cipher:' + blob.decode()

    return cipher


def get_client():

    region = os.environ['REGION']
    kms = boto3.client('kms', region_name=region)

    return kms
