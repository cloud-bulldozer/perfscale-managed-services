import elasticsearch
import logging
import time
import os
import errno
import string
import random
import subprocess

_es_ignored_metadata = "before-suite-metrics,route-latencies,route-throughputs,route-availabilities,healthchecks,healthcheckIteration,status"


def _connect_to_es(es_url, insecure):
    if es_url.startswith('https://'):
        import urllib3
        import ssl
        ssl_ctx = ssl.create_default_context()
        if insecure:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        es = elasticsearch.Elasticsearch([es_url], ssl_context=ssl_ctx, verify_certs=False)
    elif es_url.startswith('http://'):
        es = elasticsearch.Elasticsearch([es_url])
    else:
        logging.error('Invalid ES URL: %s' % es_url)
        exit(1)
    return es


def _index_result(es, index, metadata, es_ignored_metadata, index_retry):
    my_doc = _buildDoc(metadata, es_ignored_metadata)

    logging.debug('Document to be uploaded to ES:')
    logging.debug(my_doc)

    _id = ""
    if 'cluster_id' in dict(my_doc).keys():
        _id = my_doc['cluster_id']
    else:
        _id = my_doc['cluster_name']

    for attempt in range(index_retry + 1):
        try:
            time.sleep(5 * attempt)
            logging.debug('Attempting to upload (Attempt: %d) information to ES server with index %s' % (attempt, index))
            es.index(index=index, body=my_doc)
        except Exception as e:
            logging.error(e)
            logging.error('Failed to upload to ES, waiting %d seconds for next upload retry' % (5 * (attempt + 1)))
        else:
            logging.debug('ES upload successful for cluster id %s' % _id)
            return 0
    else:
        logging.error('Reached the maximun number of retries: %d, ES upload failed for %s' % (index_retry, _id))
        return 1


def _buildDoc(metadata, es_ignored_metadata):

    my_doc = {}
    my_doc = _getValue(metadata, es_ignored_metadata)
    return my_doc


def _getValue(value, es_ignored_metadata):
    # Parse booleans
    if isinstance(value, bool):
        return bool(value)

    # Parse int
    try:
        return int(value)
    except Exception as e:
        logging.debug('value {} is not an int {}'.format(value, e))

    # Parse floats
    # By default it was being truncated to int
    try:
        return int(float(value))
    except Exception as e:
        logging.debug('value {} is not an int {}'.format(value, e))

    # Parse strings
    if isinstance(value, str):
        return str(value)

    # Parse a dictionary
    elif isinstance(value, dict):
        dictionary = {}
        for key in value:
            if key not in es_ignored_metadata:
                val = value[key]
                key = key.replace('-', '_').replace(' ', '_').lower()
                v = _getValue(val, es_ignored_metadata)
                dictionary[key] = v
        return dictionary
    return


def _create_path(my_path):
    try:
        logging.info('Create directory %s if it does not exist' % my_path)
        os.makedirs(my_path, exist_ok=True)
    except OSError as e:
        if e.errno != errno.EEXIST:
            logging.error(e)
            exit(1)


def _generate_cluster_name_seed(cluster_name_seed):
    _cluster_name_seed = cluster_name_seed
    allowed_chars = string.ascii_lowercase + string.digits
    for char in _cluster_name_seed:
        if char not in allowed_chars:
            logging.error('Cluster name seed is not valid: %s\nCluster name seed must contain only lowercase letters and digits.' % _cluster_name_seed)
            exit(1)
    random_string = ''.join(random.choice(allowed_chars) for j in range(3))
    if len(_cluster_name_seed) > 6:
        logging.warning('Cluster Name Seed too long (%d), truncated to %s' % (len(_cluster_name_seed), _cluster_name_seed[:6]))
        _cluster_name_seed = _cluster_name_seed[:6]
    _cluster_name_seed += "-" + random_string
    return _cluster_name_seed


def _subprocess_exec(command, output_file=None, extra_params={}, log_output=True):
    '''
    Function to execute commands on a shell.
    command: command to execute to be passed to subprocess. For example: "ls -l"
    output_file: if defined, file to store output of the command. It will turn return values to None
    extra_params: if defined, any extra param to be passed to Popen function in a mapping format. For example: extra_params={'cwd': '/tmp', 'universal_newlines': False}
    log_output: if false, it wont print ERROR logs. useful when looping over commands which fails until they work, like oc login or oc adm

    Function call example: exit_code, out, err = common._subprocess_exec("ls -l", extra_params={'cwd': '/tmp', 'universal_newlines': False}, log_output=False)
    '''
    logging.debug(command)
    stdout = None
    stderr = None
    try:
        log_file = open(output_file, 'w') if output_file else subprocess.PIPE
        process = subprocess.Popen(command.split(), stdout=log_file, stderr=log_file, **extra_params)
        stdout, stderr = process.communicate()
        if process.returncode != 0 and log_output:
            logging.error(f'Failed to execute command: {command}')
            logging.error(stdout if stdout else "")
            logging.error(stderr if stderr else "")
        return process.returncode, stdout, stderr
    except Exception as e:
        logging.error(f'Error executing command: {command}')
        logging.error(str(e))
        logging.error(stdout if stdout else "")
        logging.error(stderr if stderr else "")
        return -1, None, None


class CustomFormatter(logging.Formatter):
    grey = '\x1b[38;21m'
    blue = '\x1b[38;5;39m'
    yellow = '\x1b[38;5;226m'
    red = '\x1b[38;5;196m'
    bold_red = '\x1b[31;1m'
    dark_green = '\x1b[38;5;22m'
    light_green = '\x1b[38;5;46m'
    dull_green = '\x1b[38;5;40m'
    green = '\x1b[38;5;45m'
    light_blue = '\x1b[38;5;117m'
    reset = '\x1b[0m'

    def __init__(self, fmt):
        super().__init__()
        self.fmt = fmt
        self.FORMATS = {
            logging.DEBUG: self.light_blue + self.fmt + self.reset,
            logging.INFO: self.dull_green + self.fmt + self.reset,
            logging.WARNING: self.yellow + self.fmt + self.reset,
            logging.ERROR: self.red + self.fmt + self.reset,
            logging.CRITICAL: self.bold_red + self.fmt + self.reset
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)
