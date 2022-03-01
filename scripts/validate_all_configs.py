import base64
import logging
import json
import os
import argparse
import boto3
from botocore.exceptions import ClientError
from flatten_json import flatten


logger = logging.getLogger()


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--fail_if_not_exist', default=False, action="store_true", help="Fail if config file doesn't exist")
    parser.add_argument('--loglevel', default="INFO", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Set logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL')
    parser.add_argument(dest='config_files', metavar='', type=str, nargs="+", help='List of files to check')
    args = parser.parse_args()
    logger.setLevel(args.loglevel)
    for arg, value in sorted(vars(args).items()):
        logging.debug('Argument {}: {}'.format(arg, value))
    return args


def parse_event(data):

    logger.info('** Parsing json using default parser **')
    logger.info(f'Data:\n{data}')

    flat_data = flatten(data, '.')
    logger.info(f'Flat data:\n{flat_data}')

    for key, value in flat_data.items():
        if isinstance(value, int):
            flat_data[key] = str(value)

    logger.info(f'Updated Data:\n{flat_data}')

    return flat_data


def check_cipher(key, value):
    """
    Update SSM parameter, only if it differ from the current one.
    """

    logger.info(f'** Key: {key}, Value: {value}')
    if isinstance(value, str) and value.startswith('cipher:') is True:
        value = decrypt(value)


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


def validate_all_configs():
    args = parse_args()
    for filename in args.config_files:
        print(20 * '#')
        print(filename)
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                file_data = f.read()
                json_data = json.loads(file_data)
                # print(json_data)
                keyValueDict = parse_event(json_data)
                for key, value in keyValueDict.items():
                    check_cipher(key, value)
        else:
            print("File doesn't exist:", filename)
    print(20 * '#')


if __name__ == '__main__':
    validate_all_configs()
