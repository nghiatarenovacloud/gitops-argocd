import json
import boto3
import os
import re
from botocore.config import Config
from botocore.exceptions import ClientError
from logger import Logger
from awsclient import BotoSession
from findings import Finding
import utils

LOG_LEVEL = os.getenv('log_level', 'info')
LOGGER = Logger(loglevel=LOG_LEVEL)

def get_running_account():
    return boto3.client('sts').get_caller_identity()['Account']

def _get_ssm_client(account, role, region=''):
    sess = BotoSession(
        account,
        f'{role}'
    )
    kwargs = {}
    if region:
        kwargs['region_name'] = region
    return sess.client('ssm', **kwargs)

def _check_version(account, role):
    try:
        ssm = _get_ssm_client(account, role)
        rz_version = ssm.get_parameter(
                Name=f'/RENOZONE/version'
            ).get('Parameter').get('Value')
        return rz_version

    except ClientError as ex:
        exception_type = ex.response['Error']['Code']
        if exception_type in "InvalidParameter":
            return False
        else:
            LOGGER.error('An unhandled client error occurred: ' + exception_type)
            return False

    except Exception as e:
        LOGGER.error('An unhandled error occurred: ' + str(e))
        return False

def lambda_handler(event, _):
    answer = utils.StepFunctionLambdaAnswer()
    LOGGER.info(event)
    if "Finding" not in event or \
       "EventType" not in event:
        answer.update({
            'status':'ERROR',
            'message':'Missing required data in request'
        })
        LOGGER.error(answer.message)
        return answer.json()

    finding = Finding(event['Finding'])
    admin_version = _check_version(get_running_account(), None)
    member_version = _check_version(finding.account_id, 'RZ-Orchestrator-Member')
    if admin_version != member_version:
        answer.update({
            'renozone': {
                'compatible': False,
                'member_version': member_version,
                'admin_version' : admin_version
            }
        })
    else:
        answer.update({
            'renozone': {
                'compatible': True,
                'member_version': member_version,
                'admin_version' : admin_version
            }
        })
    return answer.json()
