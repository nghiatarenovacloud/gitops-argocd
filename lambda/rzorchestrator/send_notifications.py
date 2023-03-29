import json
from json.decoder import JSONDecodeError
import boto3
import os
import findings
from logger import Logger

AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
AWS_PARTITION = os.getenv('AWS_PARTITION', 'aws')

LOG_LEVEL = os.getenv('log_level', 'info')
LOGGER = Logger(loglevel=LOG_LEVEL)


def format_details_for_output(details):
    details_formatted = []
    if isinstance(details, list):
        details_formatted = details
    elif isinstance(details, str) and details[0:6] == "Cause:":
        try:
            details_formatted = json.dumps(
                json.loads(details[7:]), indent=2).split('\n')
        except JSONDecodeError:
            details_formatted.append(details[7:])
    elif isinstance(details, str):
        try:
            details_formatted = json.loads(details)
        except JSONDecodeError:
            details_formatted.append(details)
    else:
        details_formatted.append(details)

    return details_formatted


def set_message_prefix_and_suffix(event):
    message_prefix = event['Notification'].get('ExecId', '')
    message_suffix = event['Notification'].get('AffectedObject', '')
    if message_prefix:
        message_prefix += ': '
    if message_suffix:
        message_suffix = f' ({message_suffix})'
    return message_prefix, message_suffix


def lambda_handler(event, _):
    message_prefix, message_suffix = set_message_prefix_and_suffix(event)
    finding_status = 'FAILED'
    if event['Notification']['State'].upper == 'SUCCESS':
        finding_status = 'RESOLVED'
    elif event['Notification']['State'].upper == 'QUEUED':
        finding_status = 'PENDING'
    finding = None
    finding_info = ''
    if 'Finding' in event:
        finding = findings.Finding(event['Finding'])
        finding_info = {
            'finding_id': finding.uuid,
            'finding_description': finding.description,
            'standard_name': finding.standard_name,
            'standard_version': finding.standard_version,
            'standard_control': finding.standard_control,
            'title': finding.title,
            'region': finding.region,
            'account': finding.account_id,
            'finding_arn': finding.arn
        }

    if event['Notification']['State'].upper() in ('SUCCESS', 'QUEUED'):
        notification = findings.RZNotification(
            event.get('SecurityStandard', 'RENOZONE'),
            AWS_REGION,
            event.get('ControlId', None)
        )
        notification.severity = 'INFO'
        notification.send_to_sns = True

    elif event['Notification']['State'].upper() == 'FAILED':
        notification = findings.RZNotification(
            event.get('SecurityStandard', 'RENOZONE'),
            AWS_REGION,
            event.get('ControlId', None)
        )
        notification.severity = 'ERROR'
        notification.send_to_sns = True

    elif event['Notification']['State'].upper() in {'WRONGSTANDARD', 'LAMBDAERROR'}:
        notification = findings.RZNotification('RENOZONE', AWS_REGION, None)
        notification.severity = 'ERROR'

    else:
        notification = findings.RZNotification(
            event.get('SecurityStandard', 'RENOZONE'),
            AWS_REGION,
            event.get('ControlId', None)
        )
        notification.severity = 'ERROR'
        if finding:
            finding.flag(event['Notification']['Message'])

    notification.message = message_prefix + \
        event['Notification']['Message'] + message_suffix
    if 'Details' in event['Notification'] and event['Notification']['Details'] != 'MISSING':
        notification.logdata = format_details_for_output(
            event['Notification']['Details'])

    notification.finding_info = finding_info
    notification.notify()
