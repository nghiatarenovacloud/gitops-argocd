import re
import json
import inspect
import os
import boto3
from utils import publish_to_sns
from awsclient import AWSCachedClient
from botocore.exceptions import ClientError

securityhub = None
UNHANDLED_CLIENT_ERROR = 'An unhandled client error occurred: '

def get_securityhub():
    global securityhub
    if securityhub == None:
        securityhub = AWSCachedClient(
            os.getenv('AWS_DEFAULT_REGION', 'us-east-1')).get_connection('securityhub')
    return securityhub

def get_ssm_connection(apiclient):
    return apiclient.get_connection('ssm')

class InvalidFindingJson(Exception):
    pass

class Finding(object):
    details = {}
    generator_id = 'error'
    account_id = 'error'
    resource_region = 'error'
    standard_name = ''
    standard_shortname = 'error'
    standard_version = 'error'
    standard_control = 'error'
    remediation_control = ''
    standard_version_supported = 'False'
    title = ''
    description = ''
    region = None
    arn = ''
    uuid = ''

    def __init__(self, finding_rec):
        self.region = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        self.aws_api_client = AWSCachedClient(self.region)

        self.details = finding_rec
        self.arn = self.details.get('Id', 'error')
        self.uuid = self.arn.split('/finding/')[1]
        self.generator_id = self.details.get('GeneratorId', 'error')
        self.account_id = self.details.get('AwsAccountId', 'error')
        resource = self.details.get('Resources', [])[0]
        self.resource_region = resource.get('Region', 'error')

        if not self.is_valid_finding_json():
            raise InvalidFindingJson

        self.title = self.details.get('Title', 'error')
        self.description = self.details.get('Description', 'error')
        self.remediation_url = self.details.get(
            'Remediation', {}).get('Recommendation', {}).get('Url', '')

        if self.details.get('Compliance', None) is not None:
            self._get_security_standard(
                self.details.get('Compliance')
            )
        else:
            self.standard_control = self.details.get(
                'Compliance').get('SecurityControlId')
            self.standard_version = '2.0.0'
            self.standard_name = 'security-control'

        self._get_security_standard_abbreviation_from_ssm()
        self._get_control_remap()
        self._set_standard_version_supported()

    def is_valid_finding_json(self):
        if self.generator_id == 'error':
            return False

        if not self.details.get('Id'):
            return False

        if self.account_id == 'error':
            return False

        return True

    def resolve(self, message):
        self.update_text(message, status='RESOLVED')

    def flag(self, message):
        self.update_text(message, status='NOTIFIED')

    def update_text(self, message, status=None):
        workflow_status = {}
        if status:
            workflow_status = {'Workflow': {'Status': status}}

        try:
            get_securityhub().batch_update_findings(
                FindingIdentifiers=[
                    {
                        'Id': self.details.get('Id'),
                        'ProductArn': self.details.get('ProductArn')
                    }
                ],
                Note={
                    'Text': message,
                    'UpdatedBy': inspect.stack()[0][3]
                },
                **workflow_status
            )

        except Exception as e:
            print(e)
            raise

    def _get_security_standard(self, compliance):
        try:
            for item in compliance["RelatedRequirements"]:
                if "CIS AWS" in item:
                    regex = '(v[0-9].*)'
                    matches = re.search(regex, item)
                    self.standard_version, self.standard_control = matches.group(1)[
                        1:].split("/")
                    self.standard_name = compliance["AssociatedStandards"][0]["StandardsId"].split(
                        "/")[1]
        except Exception as e:
            print(UNHANDLED_CLIENT_ERROR + str(e))
            return

    def _get_control_remap(self):
        self.remediation_control = self.standard_control
        try:
            local_ssm = get_ssm_connection(self.aws_api_client)
            remap = local_ssm.get_parameter(
                Name=f'/RENOZONE/{self.standard_shortname}/{self.standard_version}/{self.standard_control}/remap'
            ).get('Parameter').get('Value')
            self.remediation_control = remap

        except ClientError as ex:
            exception_type = ex.response['Error']['Code']
            if exception_type in "ParameterNotFound":
                return
            else:
                print(UNHANDLED_CLIENT_ERROR + exception_type)
                return

        except Exception as e:
            print(UNHANDLED_CLIENT_ERROR + str(e))
            return

    def _get_security_standard_abbreviation_from_ssm(self):

        try:
            local_ssm = get_ssm_connection(self.aws_api_client)
            abbreviation = local_ssm.get_parameter(
                Name=f'/RENOZONE/{self.standard_name}/{self.standard_version}/shortname'
            ).get('Parameter').get('Value')
            self.standard_shortname = abbreviation

        except ClientError as ex:
            exception_type = ex.response['Error']['Code']
            if exception_type in "ParameterNotFound":
                self.security_standard = 'notfound'
            else:
                print(UNHANDLED_CLIENT_ERROR + exception_type)
                return

        except Exception as e:
            print(UNHANDLED_CLIENT_ERROR + str(e))
            return

    def _set_standard_version_supported(self):
        try:
            local_ssm = get_ssm_connection(self.aws_api_client)

            version_status = local_ssm.get_parameter(
                Name=f'/RENOZONE/{self.standard_name}/{self.standard_version}/status'
            ).get('Parameter').get('Value')

            if version_status == 'enabled':
                self.standard_version_supported = 'True'
            else:
                self.standard_version_supported = 'False'

        except ClientError as ex:
            exception_type = ex.response['Error']['Code']
            if exception_type in "ParameterNotFound":
                self.standard_version_supported = 'False'
            else:
                print(UNHANDLED_CLIENT_ERROR + exception_type)
                self.standard_version_supported = 'False'

        except Exception as e:
            print(UNHANDLED_CLIENT_ERROR + str(e))
            self.standard_version_supported = 'False'


class InvalidValue(Exception):
    pass


class RZNotification(object):
    __security_standard = ''
    __controlid = None
    __region = ''

    severity = 'INFO'
    message = ''
    logdata = []
    send_to_sns = False
    finding_info = {}

    def __init__(self, security_standard, region, controlid=None):
        self.__security_standard = security_standard
        self.__region = region
        if controlid:
            self.__controlid = controlid
        self.applogger = self._get_log_handler()

    def _get_log_handler(self):
        from logger import LogHandler

        applogger_name = self.__security_standard
        if self.__controlid:
            applogger_name += '-' + self.__controlid

        applogger = LogHandler(applogger_name)
        return applogger

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)

    def notify(self):
        sns_notify_json = {
            'severity': self.severity,
            'message': self.message,
            'finding': self.finding_info
        }

        if self.send_to_sns:
            sent_id = publish_to_sns(
                'RENOZONE_Topic',
                json.dumps(
                    sns_notify_json,
                    indent=2,
                    default=str
                ),
                self.__region
            )
            print(f'Notification message ID {sent_id} sent.')
        self.applogger.add_message(
            self.severity + ': ' + self.message
        )
        if self.logdata:
            for line in self.logdata:
                self.applogger.add_message(
                    line
                )
        self.applogger.flush()
