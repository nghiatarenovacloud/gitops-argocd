import os
import boto3
from botocore.config import Config

class AWSCachedClient:
    account = ''
    region = ''
    client = {}
    solution_version = 'undefined'

    def __init__(self, region):
        self.solution_version = os.getenv('RENOZONE_VERSION', 'undefined')
        self.region = region
        self.boto_config = Config(
            user_agent_extra=f'RENOVACLOUD/RENOZONE/{self.solution_version}',
            retries ={
                'max_attempts': 10,
                'mode': 'standard'
            }
        )

        self.account = self._get_local_account_id()

    def get_connection(self, service, region=None):
        if not region:
            region = self.region

        if service not in self.client:
            self.client[service] = {}

        if region not in self.client[service]:
            self.client[service][region] = boto3.client(service, region_name=region, config=self.boto_config)

        return self.client[service][region]

    def _get_local_account_id(self):
        aws_account_id = self.get_connection('sts',self.region).get_caller_identity().get('Account')
        return aws_account_id

class MissingAssumedRole(Exception):
    pass

class BotoSession:
    client_props = {}
    resource_props = {}
    STS = None
    partition = None
    session = None
    target = None
    role = None

    def create_session(self):
        self.STS = None
        self.STS = boto3.client('sts', config=self.boto_config)
        if not self.target:
            self.target = self.STS.get_caller_identity()['Account']
        remote_account = self.STS.assume_role(
            RoleArn='arn:' + self.partition + ':iam::' + self.target + ':role/' + self.role,
            RoleSessionName="sechub_admin"
        )
        self.session = boto3.session.Session(
            aws_access_key_id=remote_account['Credentials']['AccessKeyId'],
            aws_secret_access_key=remote_account['Credentials']['SecretAccessKey'],
            aws_session_token=remote_account['Credentials']['SessionToken']
        )

        boto3.setup_default_session()

    def __init__(self, account=None, role=None, partition=None):
        if not partition:
            partition = 'aws'
        self.target = account
        if not role:
            raise MissingAssumedRole
        else:
            self.role = role
        self.session = None
        self.partition = os.getenv('AWS_PARTITION', partition)
        self.solution_version = os.getenv('RENOZONE_VERSION', 'undefined')
        self.boto_config = Config(
            user_agent_extra=f'RENOVACLOUD/RENOZONE/{self.solution_version}',
            retries ={
                'max_attempts': 10,
                'mode': 'standard'
            }
        )
        self.create_session()

    def client(self, name, **kwargs):

        self.client_props[name] = self.session.client(name, config=self.boto_config, **kwargs)
        return self.client_props[name]

    def resource(self, name, **kwargs):

        self.resource_props[name] = self.session.resource(name, config=self.boto_config, **kwargs)
        return self.resource_props[name]
