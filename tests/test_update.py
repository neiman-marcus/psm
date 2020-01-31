import unittest
import os
import uuid
import json
from flatten_json import flatten

from moto import mock_kms
from moto import mock_ssm
from src import update
from src import encrypt


class test_encrypt(unittest.TestCase):

    def setUp(self):
        self.app_id = 'hello_world'
        self.stage = 'dev'

        self.path = f'/{self.app_id}/{self.stage}/'
        self.path_override = f'/org/{self.stage}/{self.app_id}/'

        self.region = 'us-west-2'
        self.alias = 'alias/kms-test'
        self.secret = 'Hello World!'

        self.metadata_as_param = 'False'
        self.tags = {'Application': 'PSM'}
        self.metadata = {'metadata': {'tags': self.tags}}

        self.params = {'foo': 'bar', 'bazz': {'buzz': 'qux'}}
        self.merge_data = {**self.metadata, **self.params}
        self.flat_data = flatten(self.merge_data, '.')
        self.existing_param = {'foo': 'bar'}
        self.existing_param_type = 'String'

        self.data = {**self.metadata, **self.params}
        self.body = json.dumps(self.data)
        self.event = {'headers': {'x-test-header': 'test'}, 'queryStringParameters': {'appId': self.app_id,'stage': self.stage},'body': self.body}
        self.event_path_override = {'headers': {'x-path-override': self.path_override},'queryStringParameters': {'appId': self.app_id,'stage': self.stage},'body': self.body}

    def test_parse_event(self):
        os.environ['METADATA_AS_PARAM'] = self.metadata_as_param
        path, app_id, stage, flat_data, tags = update.parse_event(self.event)
        self.assertEqual(app_id, self.app_id)
        self.assertEqual(stage, self.stage)
        self.assertEqual(flat_data, self.flat_data)
        self.assertEqual(tags, self.tags)
        self.assertEqual(path, None)

    def test_parse_event_path_override(self):
        os.environ['METADATA_AS_PARAM'] = self.metadata_as_param
        path, app_id, stage, flat_data, tags = update.parse_event(self.event_path_override)
        self.assertEqual(app_id, self.app_id)
        self.assertEqual(stage, self.stage)
        self.assertEqual(flat_data, self.flat_data)
        self.assertEqual(tags, self.tags)
        self.assertEqual(path, self.path_override)

    def test_get_client(self):
        os.environ['REGION'] = self.region
        ssm = str(update.get_client('ssm'))
        self.assertTrue('<botocore.client.SSM object at' in ssm)

        kms = str(update.get_client('kms'))
        self.assertTrue('<botocore.client.KMS object at' in kms)

    @mock_ssm
    def __moto_ssm_setup(self):
        ssm = update.get_client('ssm')

        for key,value in self.existing_param.items():
            ssm.put_parameter(
                Name=f'/{self.app_id}/{self.stage}/{key}',
                Value=value,
                Type=self.existing_param_type,
                Overwrite=True
            )
    
    @mock_kms
    def __moto_kms_setup(self):
        kms = update.get_client('kms')
        key = kms.create_key()
        kms.create_alias(AliasName=self.alias, TargetKeyId=key['KeyMetadata']['KeyId'])
    
    @mock_ssm
    def test_compare_param(self):
        os.environ['REGION'] = self.region
        self.__moto_ssm_setup()

        compare_true = update.compare_param(self.path, 'foo', 'bar', 'String')
        self.assertFalse(compare_true)

        compare_false = update.compare_param(self.path, 'foo', 'bazz', 'String')
        self.assertTrue(compare_false)

    @mock_kms
    def test_decrypt(self):
        os.environ['REGION'] = self.region
        os.environ['KMS_KEY_ALIAS'] = self.alias

        self.__moto_kms_setup()

        cipher = encrypt.encrypt(self.secret)
        decrypt = update.decrypt(cipher)

        self.assertEqual(decrypt, self.secret)

    @mock_ssm
    def test_put_param(self):
        os.environ['REGION'] = self.region
        self.__moto_ssm_setup()

        ssm = update.get_client('ssm')

        response_false = update.put_param(self.path, 'foo', 'bar', ssm)
        self.assertFalse(response_false)

        response_true = update.put_param(self.path, 'foo', 'bazz', ssm)
        self.assertTrue(response_true)

    @mock_ssm
    def test_tag_param(self):
        os.environ['REGION'] = self.region
        self.__moto_ssm_setup()

        ssm = update.get_client('ssm')
        response = update.tag_param(self.path, 'foo', self.tags, ssm)

        self.assertTrue(response['ResponseMetadata']['HTTPStatusCode'], '200')

if __name__ == "__main__":
    unittest.main()