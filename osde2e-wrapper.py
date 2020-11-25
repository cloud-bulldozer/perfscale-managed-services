#!/usr/bin/env python
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import argparse
import elasticsearch
import time
import subprocess
import sys
import shutil
import os
import uuid
import json
import logging
import errno
import git
import threading
import copy
from ruamel.yaml import YAML

yaml = YAML()

def _connect_to_es(server, port, es_ssl):
    _es_connection_string = str(server) + ':' + str(port)
    if es_ssl == "true":
        import urllib3
        import ssl
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        es = elasticsearch.Elasticsearch([_es_connection_string], send_get_body_as='POST',
                                         ssl_context=ssl_ctx, use_ssl=True)
    else:
        es = elasticsearch.Elasticsearch([_es_connection_string], send_get_body_as='POST')

    return es

def _index_result(es,my_uuid,index,metadata_path,cluster_start_time,success,timestamp):
    end_time = time.strftime("%Y-%m-%dT%H:%M:%S")

    logging.info('Checking if metadata file exists')
    try:
        os.path.exists(metadata_path)
    except Exception as err:
        logging.error(err)
        logging.error('Expected %s metadata file not found' % metadata_path)
        exit(1)

    logging.info('Attempting to load metadata json')
    try:
        metadata = json.load(open(metadata_path))
    except Exception as err:
        logging.error(err)
        logging.error('Failed to load metadata.json file located %s' % metadata_path)
        exit(1)

    my_doc = {
        "timestamp": timestamp,
        "cluster_start_time": cluster_start_time,
        "cluster_end_time": end_time,
        "install_successful": success,
        "uuid": my_uuid,
        "cluster_id": metadata['cluster-id'],
        "cluster_name": metadata['cluster-name'],
        "cluster_version": metadata['cluster-version'],
        "environment": metadata['environment'],
        "region": metadata['region'],
        "time_to_ocm_reporting_installed": int(float(metadata['time-to-ocm-reporting-installed'])),
        "time_to_cluster_ready": int(float(metadata['time-to-cluster-ready'])),
        "time_to_upgraded_cluster": int(float(metadata['time-to-upgraded-cluster'])),
        "time_to_upgraded_cluster_ready": int(float(metadata['time-to-upgraded-cluster-ready'])),
        "time_to_certificate_issued": int(float(metadata['time-to-certificate-issued'])),
        "install_phase_pass_rate": metadata['install-phase-pass-rate'],
        "upgrade_phase_pass_rate": metadata['upgrade-phase-pass-rate'],
        "log_metrics": {
            "access_token_500": metadata['log-metrics']['access-token-500'],
            "cluster_mgmt_500": metadata['log-metrics']['cluster-mgmt-500'],
            "cluster_pending": metadata['log-metrics']['cluster-pending'],
            "eof": metadata['log-metrics']['eof'],
            "host_dns_lookup": metadata['log-metrics']['host-dns-lookup']
        }
    }

    logging.debug('Document to be uploaded to ES:')
    logging.debug(my_doc)

    logging.info('Attempting to upload information to ES server with index %s' % index)
    try:
        es.index(index=index, body=my_doc)
    except Exception as e:
        logging.error(repr(e) + "occurred for the json document:")
        exit(1)
    logging.info('ES upload successful for cluster id %s' % my_doc['cluster_id'])


def _create_path(my_path):
    try:
        logging.info('Create directory %s if it does not exist' % my_path)
        os.makedirs(my_path, exist_ok=True)
    except OSError as e:
        if e.errno != errno.EEXIST:
            logging.error(e)
            exit(1)


# If osde2e command path is provided verify we can run the help function
# If it is not provided git clone the osde2e repo, build it and validate as above
def _verify_cmnd(osde2e_cmnd,my_path):
    osde2e_path = my_path + "/osde2e"

    # If the command path was not given, git clone and build
    if osde2e_cmnd is None:
        logging.info('osde2e command not provided')
        logging.info('Cloning osde2e git repository')
        try:
            git.Repo.clone_from("https://github.com/openshift/osde2e.git", osde2e_path, kill_after_timeout=300)
        except git.exc.GitCommandError as err:
            logging.error(err)
            exit(1)

        logging.info('Attempting to build osde2e via make build')
        cmd = ["make", "--directory", osde2e_path, "build"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout,stderr = process.communicate()
        if process.returncode != 0:
            logging.error('Make build in directory %s failed with the following:' % osde2e_path)
            logging.error(stderr.strip().decode("utf-8"))
            exit(1)
        logging.info('osde2e successfully built')
        osde2e_cmnd = osde2e_path + "/out"

    logging.info('Testing osde2e command with: osde2e -h')
    osd_cmd = [osde2e_cmnd + "/osde2e", "-h"]
    ctl_cmd = [osde2e_cmnd + "/osde2ectl", "-h"]
    osd_process = subprocess.Popen(osd_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ctl_process = subprocess.Popen(ctl_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    osd_stdout,osd_stderr = osd_process.communicate()
    ctl_stdout,ctl_stderr = ctl_process.communicate()
    if osd_process.returncode != 0:
        logging.error('%s unable to execute -h' % osde2e_cmnd + "/osde2e")
        logging.error(stderr.strip().decode("utf-8"))
        exit(1)
    if ctl_process.returncode != 0:
        logging.error('%s unable to execute -h' % osde2e_cmnd + "osde2ectl")
        logging.error(stderr.strip().decode("utf-8"))
        exit(1)
    logging.info('osde2e and osde2ectl commands validated with -h. Directory is %s' % osde2e_cmnd)

    return osde2e_cmnd

def _build_cluster(osde2e_cmnd,account_config,my_path,es,index,my_uuid,my_inc,timestamp,dry_run):
    cluster_start_time = time.strftime("%Y-%m-%dT%H:%M:%S")
    success = True

    # osde2e takes a relative path to the account file so we need to create it in a working dir and
    # pass that dir as the cwd to subproccess
    cluster_path = my_path + "/" + str(my_inc)
    os.mkdir(cluster_path)
    yaml.dump(account_config,open(cluster_path + "/cluster_account.yaml",'w'))
    cluster_env = os.environ.copy()
    cluster_env["REPORT_DIR"] = cluster_path
    logging.info('Attempting cluster installation')
    logging.info('Output directory set to %s' % cluster_path)
    cluster_cmd = [osde2e_cmnd, "test","--custom-config", "cluster_account.yaml"]
    if not dry_run:
        process = subprocess.Popen(cluster_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=cluster_env, cwd=cluster_path)
        stdout,stderr = process.communicate()
        if process.returncode != 0:
            logging.error('Failed to build cluster number %d' % my_inc)
            logging.error(stderr.strip().decode("utf-8"))
            success = False
        if es is not None:
            _index_result(es,my_uuid,index,cluster_path + "/metadata.json",cluster_start_time,success,timestamp)

def _watcher(osde2ectl_cmd,account_config,my_path,cluster_count,delay):
    logging.info('Watcher thread started')
    logging.info('Getting status every %d seconds' % int(delay))

    yaml.dump(account_config,open(my_path + "/account_config.yaml",'w'))
    my_config = yaml.load(open(my_path + "/account_config.yaml"))
    my_thread = threading.currentThread()
    cmd = [osde2ectl_cmd, "list", "--custom-config", "account_config.yaml"]

    # To stop the watcher we expect the run attribute to be not True
    while getattr(my_thread, "run", True):
        logging.debug(cmd)
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,cwd=my_path,universal_newlines=True)
        stdout,stderr = process.communicate()

        cluster_count = 0
        state = {}
        status = {}
        error = []
        # Count the various states/status' and report it to logging
        for line in stdout.splitlines():
            if my_config['ocm']['userOverride'] in line:
                cluster_count += 1
                state_key = line.split()[2]
                status_key = line.split()[3]
                state[state_key] = state.get(state_key, 0) + 1
                status[status_key] = status.get(status_key, 0) + 1

                if state_key == "error":
                    error.append(line.split()[1])
                    logging.debug(line.split()[1])

        logging.info('Requested Clusters: %d' % cluster_count)
        if cluster_count != 0:
            logging.info('Current state counts:')
            logging.info(state.items())
            logging.info('Current status counts:')
            logging.info(status.items())
            logging.info('Clusters in error state:')
            logging.info(error)

        time.sleep(delay)
    logging.info('Watcher exiting')

def _cleanup_clusters(osde2ectl_cmd,my_path,account_config):
    logging.info('Starting cluster cleanup')
    cmd = [osde2ectl_cmd, "list", "--custom-config", "account_config.yaml"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,cwd=my_path,universal_newlines=True)
    stdout,stderr = process.communicate()
    error = []
    for line in stdout.splitlines():
        if account_config['ocm']['userOverride'] in line:
            state = line.split()[2]
            cluster_id = line.split()[1]
            if state != "error" and state != "uninstalling":
                logging.debug('Deleting cluster id: %s' % cluster_id)
                del_cmd = [osde2ectl_cmd, "--custom-config", "account_config.yaml", "delete", "-i", cluster_id]
                process = subprocess.Popen(del_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,cwd=my_path,universal_newlines=True)
                stdout,stderr = process.communicate()
                if process.returncode != 0:
                    logging.error('Cluster cleanup failed for cluster id %s with this stdout/stderr:' % cluster_id)
                    logging.error(stdout)
                    logging.error(stderr)
            else:
                error.append(cluster_id)
    logging.info('Clusters in error state. Not deleting:')
    logging.info(error)

def main():
    parser = argparse.ArgumentParser(description="osde2e wrapper script")
    parser.add_argument(
        '-s', '--server',
        help='Provide elastic server information')
    parser.add_argument(
        '-p', '--port',
        help='Provide elastic port information')
    parser.add_argument(
        '--sslskipverify',
        help='if es is setup with ssl, but can disable tls cert verification',
        default=False)
    parser.add_argument(
        '-u', '--uuid',
        help='UUID to provide to elastic')
    parser.add_argument(
        '-c', '--command',
        help='Full path to the osde2e and osde2ectl command directory. If not provided we will download and compile the latest')
    parser.add_argument(
        '--path',
        help='Path to save temporary data')
    parser.add_argument(
        '--account-config',
        required=True,
        help='Yaml account config')
    parser.add_argument(
        '--cleanup',
        help='Should we delete the temporary directory',
        default=False)
    parser.add_argument(
        '-i', '--index',
        help='The index to write to',
        default='osde2e-install-timings')
    parser.add_argument(
        '--cluster-count',
        default=1,
        type=int,
        help='Total number of clusters to create')
    parser.add_argument(
        '--batch-size',
        default=0,
        type=int,
        help='number of clusters in a batch')
    parser.add_argument(
        '--watcher-delay',
        default=60,
        type=int,
        help='Delay between each status check')
    parser.add_argument(
        '--cleanup-clusters',
        default=True,
        help='Cleanup any non-error state clusters upon test completion')
    parser.add_argument(
        '--user-override',
        type=str,
        help='User to set as the owner')
    parser.add_argument(
        '--aws-account-file',
        type=str,
        help='AWS account file to use')
    parser.add_argument(
        '--delay-between-batch',
        type=int,
        help='If set it will wait x seconds between each batch request')
    parser.add_argument(
        '--log-file',
        help='File where to write logs')
    parser.add_argument(
        '--log-level',
        default='INFO',
        help='Log level to show')
    parser.add_argument(
        '--dry-run',
        dest='dry_run',
        action='store_true',
        help='Perform a dry-run of the script without creating any cluster')
    args = parser.parse_args()

    if args.server is not None and args.port is not None:
        es = _connect_to_es(args.server, args.port, args.sslskipverify)
    else:
        es = None

    logger = logging.getLogger()
    logger.setLevel(args.log_level.upper())
    log_format = logging.Formatter(
        '%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    consolelog = logging.StreamHandler()
    consolelog.setFormatter(log_format)
    logger.addHandler(consolelog)
    if args.log_file is not None:
        logging.info('Logging to file: %s' % args.log_file)
        _create_path(os.path.dirname(args.log_file))
        logfile = logging.FileHandler(args.log_file)
        logfile.setFormatter(log_format)
        logger.addHandler(logfile)
        logging.info('Logging to file: %s' % args.log_file)
    else:
        logging.info('Logging to console')

    # global uuid to assign for the group of clusters created. each cluster will have its own cluster-id
    my_uuid = args.uuid
    if my_uuid is None:
        my_uuid = str(uuid.uuid4())
    logging.info('Test running with UUID: %s' % my_uuid)

    my_path = args.path
    if my_path is None:
        my_path = '/tmp/' + my_uuid
    logging.info('Using %s as temp directory' % (my_path))
    _create_path(my_path)

    if os.path.exists(args.account_config):
        logging.debug('Account configuration file exists')
    else:
        logging.error('Account configuration file not found at %s' % args.account_config)
        exit(1)

    # load the account config yaml
    try:
        account_config = yaml.load(open(args.account_config))
    except Exception as err:
        logging.error(err)
        logging.error('Failed to load account configuration yaml')
        exit(1)

    # Verify that ocm and token information are provided
    if "ocm" not in account_config.keys():
        logging.error('No ocm configuration supplied in account configuration file: %s' % args.account_config)
        exit(1)
    elif "token" not in account_config['ocm'].keys():
        logging.error('No ocm token supplied in configuration file: %s' % args.account_config)
        exit(1)

    # Set the user override if provided on the cli or generate a new one
    # if none is set
    if args.user_override is not None:
        account_config['ocm']['userOverride'] = args.user_override
    elif "userOverride" not in account_config['ocm'].keys():
        account_config['ocm']['userOverride'] = str(uuid.uuid4())[:8]
    logging.info('User override set to: %s' % account_config['ocm']['userOverride'])

    cmnd_path = _verify_cmnd(args.command,my_path)

    # launch watcher thread to report status
    if not args.dry_run:
        logging.info('Launching watcher thread')
        watcher = threading.Thread(target=_watcher,args=(cmnd_path + "/osde2ectl",account_config,my_path,args.cluster_count,args.watcher_delay))
        watcher.daemon = True
        watcher.start()
        logging.info('Attempting to start %d clusters with %d batch size' % (args.cluster_count,args.batch_size))
    else:
        logging.info('Dry-run: Watcher thread not started')

    # If the aws account file is given, load its data into a list of dictionaries
    aws_accounts = []
    if args.aws_account_file is not None:
        if os.path.exists(args.aws_account_file):
            logging.debug('AWS Account file exists')
        else:
            logging.error('AWS Account configuration file not found at %s' % args.aws_account_file)
            exit(1)
        logging.info('AWS account file found. Loading account information')
        for line in open(args.aws_account_file).readlines():
            field = line.split(',')
            try:
                aws_accounts.append({'account': field[0].strip(), 'accessKey': field[1].strip(), 'secretKey': field[2].strip()})
            except Exception as err:
                logging.error(err)
                logging.error('Failed to load account information. Exiting')
                exit(1)

    cluster_thread_list = []
    aws_account_counter = 0
    batch_count = 0
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    loop_counter = 0
    try:
        while (loop_counter < args.cluster_count):
            create_cluster = False
            my_cluster_config = copy.deepcopy(account_config)
            # if aws accounts were loaded from a file use them. if # of accounts given is less than the
            # requested amount of clusters loop back over it
            if len(aws_accounts) > 0:
                # If the aws key doesn't exist, create it.
                if "aws" not in my_cluster_config['ocm'].keys():
                    my_cluster_config['ocm'].update({'aws': {}})
                my_cluster_config['ocm']['aws']['account'] = aws_accounts[aws_account_counter]['account']
                my_cluster_config['ocm']['aws']['accessKey'] = aws_accounts[aws_account_counter]['accessKey']
                my_cluster_config['ocm']['aws']['secretKey'] = aws_accounts[aws_account_counter]['secretKey']
                aws_account_counter += 1
                if aws_account_counter >= len(aws_accounts):
                    aws_account_counter = 0

            if args.batch_size != 0:
                if args.delay_between_batch is None:
                    # We add 2 to the batch size. 1 for the main thread and 1 for the watcher
                    while (args.batch_size + 2) <= threading.active_count():
                        # Wait for thread count to drop before creating another
                        time.sleep(1)
                    loop_counter += 1
                    create_cluster = True
                elif batch_count >= args.batch_size:
                    time.sleep(args.delay_between_batch)
                    batch_count = 0
                else:
                    batch_count += 1
                    loop_counter += 1
                    create_cluster = True
            else:
                loop_counter += 1
                create_cluster = True

            if create_cluster:
                logging.info('Starting Cluster thread %d' % (loop_counter + 1))
                try:
                    thread = threading.Thread(target=_build_cluster,args=(cmnd_path + "/osde2e",my_cluster_config,my_path,es,args.index,my_uuid,loop_counter,timestamp,args.dry_run))
                except Exception as err:
                    logging.error(err)
                cluster_thread_list.append(thread)
                thread.start()
                logging.debug('Number of alive threads %d' % threading.active_count())

    except Exception as err:
        logging.error(err)
        logging.error('Thread creation failed')

    # Wait for active threads to finish
    logging.info('All clusters requested. Waiting for them to finish')
    for t in cluster_thread_list:
        try:
            t.join()
        except RuntimeError as err:
            if 'cannot join current thread' in err.args[0]:
                # catchs main thread
                continue
            else:
                raise

    # Stop watcher thread
    if not args.dry_run:
        watcher.run = False
        watcher.join()

    if args.cleanup_clusters is True:
        _cleanup_clusters(cmnd_path + "/osde2ectl",my_path,account_config)

    if args.cleanup is True:
        shutil.rmtree(my_path)


if __name__ == '__main__':
    sys.exit(main())
