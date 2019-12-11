import unittest
import os
import json

from moto import mock_ssm
from moto import mock_kms
from src import view


class test_view(unittest.TestCase):

    def setUp(self):
        
        self.app_id = 'hello-world'
        self.stage = 'dev'

        self.param = f'/{self.app_id}/{self.stage}/'
        self.region = 'us-west-2'

        self.string_key_1 = 'foo'
        self.string_key_2 = 'bar'
        self.string_key = self.string_key_1 + '.' + self.string_key_2
        self.string_value = 'bazz'
        self.string_param = self.param + self.string_key

        self.secure_string_key = 'buzz'
        self.secure_string_value = 'qux'
        self.secure_string_param = self.param + self.secure_string_key

        self.alias = 'alias/kms-test'
        self.secret = 'Hello World!'
    
    def test_parse_event(self):

        event = {'queryStringParameters': {'appId': self.app_id,'stage': self.stage}}
        app_id, stage = view.parse_event(event)

        self.assertEqual(app_id, self.app_id)
        self.assertEqual(stage, self.stage)

    def test_get_client(self):

        os.environ['REGION'] = self.region

        ssm = str(view.get_client('ssm'))
        self.assertTrue('<botocore.client.SSM object at' in ssm)

        kms = str(view.get_client('kms'))
        self.assertTrue('<botocore.client.KMS object at' in kms)
    
    @mock_ssm
    def __moto_ssm_setup(self):

        ssm = view.get_client('ssm')

        ssm.put_parameter(
            Name=self.string_param,
            Value=self.string_value,
            Type='String'
        )

        ssm.put_parameter(
            Name=self.secure_string_param,
            Value=self.secure_string_value,
            Type='SecureString'
        )

    @mock_kms
    def __moto_kms_setup(self):

        kms = view.get_client('kms')
        key = kms.create_key()
        kms.create_alias(AliasName=self.alias, TargetKeyId=key['KeyMetadata']['KeyId'])
    
    @mock_ssm
    def test_get_params(self):

        self.__moto_ssm_setup()
        naked_params = view.get_params(self.app_id, self.stage)

        self.assertEqual(naked_params[0]['Name'], self.string_param)
        self.assertEqual(naked_params[0]['Value'], self.string_value)
        self.assertEqual(naked_params[0]['Type'], 'String')

        self.assertEqual(naked_params[1]['Name'], self.secure_string_param)
        self.assertEqual(naked_params[1]['Value'], self.secure_string_value)
        self.assertEqual(naked_params[1]['Type'], 'SecureString')
    
    def test_string_parse_params(self):

        naked_params = [{'Name': self.string_param, 'Value': self.string_value, 'Type': 'String'}]
        unflat_params = {self.string_key_1: {self.string_key_2: self.string_value}}

        params = view.parse_params(self.app_id, self.stage, naked_params)
        self.assertEqual(params, json.dumps(unflat_params))

    @mock_kms
    def test_secure_string_parse_params(self):

        os.environ['KMS_KEY_ALIAS'] = self.alias
        self.__moto_kms_setup()

        naked_params = [{'Name': self.secure_string_param, 'Value': self.secure_string_value, 'Type': 'SecureString'}]
        params = view.parse_params(self.app_id, self.stage, naked_params)

        self.assertIsInstance(params, str)
        
        params = json.loads(params)
        self.assertTrue(self.secure_string_key in params)

        value = params[self.secure_string_key]
        self.assertTrue(value.startswith('cipher:'))

    @mock_kms
    def test_encrypt(self):

        os.environ['REGION'] = self.region
        os.environ['KMS_KEY_ALIAS'] = self.alias
        self.__moto_kms_setup()

        cipher = view.encrypt(self.secret)
        self.assertTrue(cipher.startswith('cipher:'))

    @mock_kms
    @mock_ssm
    def test_handler(self):
        os.environ['REGION'] = self.region
        os.environ['KMS_KEY_ALIAS'] = self.alias

        event = {'queryStringParameters': {'appId': self.app_id,'stage': self.stage}}
        context = None

        self.__moto_ssm_setup()
        self.__moto_kms_setup()
        response = view.handler(event, context)

        status_code = response['statusCode']
        self.assertEqual(status_code, 200)

        params = response['body']
        params = json.loads(params)

        self.assertTrue(self.string_key_1 in params)
        self.assertTrue(self.string_key_2 in params[self.string_key_1])
        self.assertTrue(self.string_value in params[self.string_key_1].values())

        self.assertTrue(self.secure_string_key in params)
        cipher = params[self.secure_string_key]
        self.assertTrue(cipher.startswith('cipher'))

        content_type = response['headers']['Content-Type']
        self.assertEqual(content_type, 'application/json')

    @mock_kms
    @mock_ssm
    def test_exception(self):
        os.environ['REGION'] = self.region
        os.environ['KMS_KEY_ALIAS'] = self.alias

        event = None
        context = None

        self.__moto_ssm_setup()
        self.__moto_kms_setup()
        response = view.handler(event, context)

        status_code = response['statusCode']
        self.assertEqual(status_code, 500)

        params = response['body']
        self.assertTrue('Err: Internal server error.' in params)

        content_type = response['headers']['Content-Type']
        self.assertEqual(content_type, 'text/plain')

if __name__ == "__main__":
    unittest.main()