import os
import time
import json
import logging
from datetime import datetime, date
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config
from utils import partition_from_region
import awsclient

LOG_MAX_BATCH_SIZE = 1048576
LOG_ENTRY_ADDITIONAL = 26
LOG_GROUP = "RENOZONE"

def get_logs_connection(apiclient):
    return apiclient.get_connection('logs')

class FailedToCreateLogGroup(Exception):
    pass

class LogHandler(object):

    def __init__(self, stream_name):

        self.apiclient = awsclient.AWSCachedClient(os.getenv('AWS_DEFAULT_REGION', 'us-east-1'))
        self.stream_name = stream_name.upper()
        self.log_group = LOG_GROUP
        self._stream_token = None
        self._buffer = []
        self._buffer_size = 0

    @property
    def streams_used(self):
        return self._stream_token

    def _create_log_group(self):
        try:
            get_logs_connection(self.apiclient).create_log_group(
                logGroupName=self.log_group
                )
        except Exception as e:
            if type(e).__name__ != "ResourceAlreadyExistsException":
                return False
        return True

    def _create_log_stream(self, log_stream):
        log_stream = log_stream + '-' + str(date.today())
        try:
            print(("Creating log stream {}".format(log_stream)))
            get_logs_connection(self.apiclient).create_log_stream(logGroupName=self.log_group, logStreamName=log_stream)
            self._stream_token = "0"
        except Exception as e:
            if type(e).__name__ == "ResourceAlreadyExistsException":
                print('Log Stream already exists')
            elif type(e).__name__ == "ResourceNotFoundException":
                if self._create_log_group():
                    get_logs_connection(self.apiclient).create_log_stream(logGroupName=self.log_group, logStreamName=log_stream)
                else:
                    raise FailedToCreateLogGroup
            else:
                raise e
        return log_stream

    def add_message(self, message):
        if not message:
            message = '   '
        timestamp = int(time.time() * 1000)
        if self._buffer_size + (len(message) + LOG_ENTRY_ADDITIONAL) > LOG_MAX_BATCH_SIZE:
            self.flush()

        self._buffer.append((timestamp, message))
        self._buffer_size += (len(message) + LOG_ENTRY_ADDITIONAL)

    def flush(self):
        if self._buffer_size == 0:
            return

        log_stream = self._create_log_stream(log_stream=self.stream_name)

        put_event_args = {
            "logGroupName": self.log_group,
            "logStreamName": log_stream,
            "logEvents": [{"timestamp": r[0], "message": r[1]} for r in self._buffer]
        }

        while True:
            try:
                if self._stream_token:
                    put_event_args["sequenceToken"] = self._stream_token
                resp = get_logs_connection(self.apiclient).put_log_events(**put_event_args)
                self._stream_token = resp.get("nextSequenceToken", None)
                break
            except ClientError as ex:
                exception_type = ex.response['Error']['Code']
                if exception_type in ["InvalidSequenceTokenException", "DataAlreadyAcceptedException"]:
                    try:
                        self._stream_token = ex.response['Error']['Message'].split(":")[-1].strip()
                        print("Token changed. Will be retried.")
                        print(("Token for existing stream {} is {}".format(
                            self.stream_name, self._stream_token)))
                    except:
                        self._stream_token = None
                        raise
                else:
                    print(("Error logstream {}, {}".format(self.stream_name, str(ex))))
                    break

        self.clear()
        self._buffer_size = 0

    def clear(self):
        self._buffer = []
        self._buffer_size = 0

class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, (datetime, date)):
            serial = o.isoformat()
            return serial
        raise TypeError("Type %s not serializable" % type(o))

class Logger(object):

    def __init__(self, loglevel='warning'):
        self.config(loglevel=loglevel)

    def config(self, loglevel='warning'):
        loglevel = logging.getLevelName(loglevel.upper())
        mainlogger = logging.getLogger()
        mainlogger.setLevel(loglevel)

        logfmt = '%(levelname)s %(message)s\n'
        if len(mainlogger.handlers) == 0:
            mainlogger.addHandler(logging.StreamHandler())
        mainlogger.handlers[0].setFormatter(logging.Formatter(logfmt))
        self.log = logging.LoggerAdapter(mainlogger, {})

    def _format(self, message):
        try:
            message = json.loads(message)
        except Exception:
            pass
        try:
            return json.dumps(message, indent=4, cls=DateTimeEncoder)
        except Exception:
            return json.dumps(str(message))

    def debug(self, message, **kwargs):
        self.log.debug(self._format(message), **kwargs)

    def info(self, message, **kwargs):
        self.log.info(self._format(message), **kwargs)

    def warning(self, message, **kwargs):
        self.log.warning(self._format(message), **kwargs)

    def error(self, message, **kwargs):
        self.log.error(self._format(message), **kwargs)

    def critical(self, message, **kwargs):
        self.log.critical(self._format(message), **kwargs)

    def exception(self, message, **kwargs):
        self.log.exception(self._format(message), **kwargs)
