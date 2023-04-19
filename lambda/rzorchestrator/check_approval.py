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

def _get_ssm_client(account, role, region=''):
    sess = BotoSession(
        account,
        f'{role}'
    )
    kwargs = {}
    if region:
        kwargs['region_name'] = region
    return sess.client('ssm', **kwargs)

def _is_remediation_destructive(_, __, ___):
    return False

def _is_account_sensitive(_):
    return False

def _is_automatic_trigger(event_type):
    if event_type == 'Security Hub Findings - Imported':
        return False
    else:
        return True

def _is_custom_action_trigger(event_type):
    if event_type == 'Security Hub Findings - Imported':
        return True
    else:
        return False

def get_running_account():
    return boto3.client('sts').get_caller_identity()['Account']

def _get_alternate_workflow(accountid):
    running_account = get_running_account()
    WORKFLOW_RUNBOOK = os.getenv('WORKFLOW_RUNBOOK', '')
    WORKFLOW_RUNBOOK_ACCOUNT = os.getenv('WORKFLOW_RUNBOOK_ACCOUNT', 'member')
    WORKFLOW_RUNBOOK_ROLE = os.getenv('WORKFLOW_RUNBOOK_ROLE', '')
    if not WORKFLOW_RUNBOOK:
        return (None, None, None)

    if WORKFLOW_RUNBOOK_ACCOUNT.lower() == 'member':
        WORKFLOW_RUNBOOK_ACCOUNT = accountid
    elif WORKFLOW_RUNBOOK_ACCOUNT.lower() == 'admin':
        WORKFLOW_RUNBOOK_ACCOUNT = running_account
    else:
        LOGGER.error(f'WORKFLOW_RUNBOOK_ACCOUNT config error: "{WORKFLOW_RUNBOOK_ACCOUNT}" is not valid. Must be "member" or "admin"')
        return (None, None, None)
    if _doc_is_active(WORKFLOW_RUNBOOK, WORKFLOW_RUNBOOK_ACCOUNT):
        return(WORKFLOW_RUNBOOK, WORKFLOW_RUNBOOK_ACCOUNT, WORKFLOW_RUNBOOK_ROLE)
    else:
        return(None, None, None)

def _doc_is_active(doc, account):
    try:
        ssm = _get_ssm_client(account, 'RZ-Orchestrator-Member')
        docinfo = ssm.describe_document(
            Name=doc
            )['Document']

        doctype = docinfo.get('DocumentType', 'unknown')
        docstate = docinfo.get('Status', 'unknown')

        if doctype == "Automation" and \
           docstate == "Active":
            return True
        else:
            return False

    except ClientError as ex:
        exception_type = ex.response['Error']['Code']
        if exception_type in "InvalidDocument":
            return False
        else:
            LOGGER.error('An unhandled client error occurred: ' + exception_type)
            return False

    except Exception as e:
        LOGGER.error('An unhandled error occurred: ' + str(e))
        return False

def lambda_handler(event, _):
    answer = utils.StepFunctionLambdaAnswer()
    answer.update({
        'workflowdoc': '',
        'workflowaccount': '',
        'workflowrole': '',
        'workflow_data': {
            'impact': 'nondestructive',
            'approvalrequired': 'false'
        }
    })
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

    auto_trigger = _is_automatic_trigger(event['EventType'])
    is_destructive = _is_remediation_destructive(finding.standard_shortname, finding.standard_version, finding.standard_control)
    is_sensitive = _is_account_sensitive(finding.account_id)

    approval_required = 'false'
    remediation_impact = 'nondestructive'
    use_alt_workflow = 'false'

    if auto_trigger and is_destructive and is_sensitive:
        remediation_impact = 'destructive'
        approval_required = 'true'
        use_alt_workflow = 'true'
    (alt_workflow, alt_account, alt_role) = _get_alternate_workflow(finding.account_id)
    if alt_workflow and use_alt_workflow:
        answer.update({
            'workflowdoc': alt_workflow,
            'workflowaccount': alt_account,
            'workflowrole': alt_role,
            'workflow_data': {
                'impact': remediation_impact,
                'approvalrequired': approval_required
            }
        })

    return answer.json()
