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
        logging.debug('Argument %s: %s', arg, value)
    return args


def parse_event(data):

    logger.debug(f'Data:\n{data}')

    flat_data = flatten(data, '.')
    logger.debug(f'Flat data:\n{flat_data}')

    for key, value in flat_data.items():
        if isinstance(value, int):
            flat_data[key] = str(value)

    logger.debug(f'Updated Data:\n{flat_data}')

    return flat_data


def check_cipher(key, value):
    if isinstance(value, str) and value.startswith('cipher:') is True:
        logger.warning('Key: %s', key)
        trim_value = value[7:]
        bytes_value = base64.b64decode(trim_value)

        try:
            kms = get_client('kms')
            _ = kms.decrypt(CiphertextBlob=bytes_value)
        except ClientError as e:
            logger.warning('Key: %s, cipher BAD', key)
            logger.critical('Error while decoding by KMS: %s', e)
        else:
            logger.warning('Key: %s, cipher GOOD', key)
    else:
        logger.info('Key: %s', key)


def get_client(service):
    # REGION should be set by variables AWS_DEFAULT_REGION and AWS_REGION.
    # region = os.environ['REGION']
    # service = boto3.client(service, region_name=region)
    service = boto3.client(service)
    return service


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
