import unittest
import os
import uuid

from moto import mock_kms
from src import encrypt


class test_encrypt(unittest.TestCase):

    def setUp(self):
        self.region = 'us-west-2'
        self.alias = 'alias/kms-test'
        self.secret = 'Hello World!'

    def test_post_secret(self):
        event = {'httpMethod': 'POST', 'body': self.secret}
        secret = encrypt.get_secret(event)
        self.assertEqual(secret, self.secret)

    def test_get_secret(self):
        event = {'httpMethod': 'GET', 'body': ''}
        secret = encrypt.get_secret(event)

        try:
            uuid.UUID(str(secret))
            valid_uuid = True
        except ValueError:
            valid_uuid = False
            
        self.assertTrue(valid_uuid)

    def test_post_empty_body(self):
        event = {'httpMethod': 'POST', 'body': None}
        secret = encrypt.get_secret(event)
        self.assertEqual(secret, None)

    @mock_kms
    def __moto_setup(self):
        kms = encrypt.get_client()
        key = kms.create_key()
        kms.create_alias(AliasName=self.alias, TargetKeyId=key['KeyMetadata']['KeyId'])

    def test_get_client(self):
        os.environ['REGION'] = self.region
        kms = str(encrypt.get_client())
        self.assertTrue('<botocore.client.KMS object at' in kms)
        
    @mock_kms
    def test_encrypt_value(self):
        os.environ['REGION'] = self.region
        os.environ['KMS_KEY_ALIAS'] = self.alias
        self.__moto_setup()

        cipher = encrypt.encrypt(self.secret)
        self.assertTrue(cipher.startswith('cipher:'))
    
    @mock_kms
    def test_handler(self):
        os.environ['REGION'] = self.region
        os.environ['KMS_KEY_ALIAS'] = self.alias

        event = {'httpMethod': 'POST', 'body': self.secret}
        context = None

        self.__moto_setup()
        response = encrypt.handler(event, context)

        status_code = response['statusCode']
        self.assertEqual(status_code, 200)

        cipher = response['body']
        self.assertTrue(cipher.startswith('cipher:'))

        content_type = response['headers']['Content-Type']
        self.assertEqual(content_type, 'text/plain')

    @mock_kms
    def test_post_empty_body_handler(self):
        os.environ['REGION'] = self.region
        os.environ['KMS_KEY_ALIAS'] = self.alias

        event = {'httpMethod': 'POST', 'body': None}
        context = None

        self.__moto_setup()
        response = encrypt.handler(event, context)

        status_code = response['statusCode']
        self.assertEqual(status_code, 400)

        cipher = response['body']
        self.assertTrue('Err: No secret supplied with POST method.' in cipher)

        content_type = response['headers']['Content-Type']
        self.assertEqual(content_type, 'text/plain')

    @mock_kms
    def test_exception(self):
        os.environ['REGION'] = self.region
        os.environ['KMS_KEY_ALIAS'] = self.alias

        event = None
        context = None

        self.__moto_setup()
        response = encrypt.handler(event, context)

        status_code = response['statusCode']
        self.assertEqual(status_code, 500)

        cipher = response['body']
        self.assertTrue('Err: Internal server error.' in cipher)

        content_type = response['headers']['Content-Type']
        self.assertEqual(content_type, 'text/plain')

if __name__ == "__main__":
    unittest.main()