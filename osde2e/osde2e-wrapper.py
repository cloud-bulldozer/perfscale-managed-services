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
import time
import subprocess
import sys
import shutil
import os
import uuid
import json
import logging
import git
import threading
import copy
from libs import common
from libs import parentParsers
from ruamel.yaml import YAML


# If osde2e command path is provided verify we can run the help function
# If it is not provided git clone the osde2e repo, build it and validate as above
def _verify_cmnd(osde2e_cmnd, my_path):
    osde2e_path = my_path + "/osde2e"

    # If the command path was not given, git clone and build
    if osde2e_cmnd is None:
        logging.info('osde2e command not provided')
        logging.info('Cloning osde2e git repository')
        try:
            git.Repo.clone_from("https://github.com/openshift/osde2e.git", osde2e_path, kill_after_timeout=300)
        except git.GitCommandError as err:
            logging.error(err)
            exit(1)

        logging.info('Attempting to build osde2e via make build')
        cmd = ["make", "--directory", osde2e_path, "build"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
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
    osd_stdout, osd_stderr = osd_process.communicate()
    ctl_stdout, ctl_stderr = ctl_process.communicate()
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


def _download_kubeconfig(osde2ectl_cmd, cluster_name, my_path):
    logging.debug('Attempting to load metadata json')
    try:
        metadata = json.load(open(my_path + "/metadata.json"))
    except Exception as err:
        logging.error(err)
        logging.error('Failed to load metadata.json file located %s, kubeconfig file wont be downloaded' % my_path)
        return 1
    if 'cluster-id' in metadata and metadata['cluster-id'] != "":
        cluster_id = metadata['cluster-id']
        logging.info('Downloading kubeconfig file for cluster %s on %s' % (cluster_id, my_path))
        cmd = [osde2ectl_cmd, "--custom-config", "cluster_account.yaml", "get", "-k", "-i", cluster_id, "--kube-config-path", my_path]
        logging.debug(cmd)
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=my_path, universal_newlines=True)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            logging.error('Failed to download kubeconfig file for cluster id %s with this stdout/stderr:' % cluster_id)
            logging.error(stdout)
            logging.error(stderr)
        else:
            logging.info('Downloaded kubeconfig file for cluster %s and stored at %s/%s-kubeconfig.txt' % (cluster_id, my_path, cluster_name))
            kubeconfig_file = my_path + "/" + cluster_name + "-" + "kubeconfig.txt"
            return kubeconfig_file
    else:
        logging.error('Failed to load cluster-id from metadata.json file located on %s, kubeconfig file wont be downloaded' % my_path)
        return 1


def _add_machinepool(osde2ectl_cmd, kubeconfig, my_path):
    try:
        metadata = json.load(open(my_path + "/metadata.json"))
    except Exception as err:
        logging.error(err)
        logging.error('Failed to load metadata.json file located %s, machinepool %s wont be created' % (my_path, args.machinepool_name))
        return 1
    if 'cluster-id' in metadata and metadata['cluster-id'] != "":
        cluster_id = metadata['cluster-id']
        logging.info('Checking if ocm tool is available on the system')
        ocm_cmd = ["ocm", "-h"]
        logging.debug(ocm_cmd)
        ocm_process = subprocess.Popen(ocm_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ocm_stdout, ocm_stderr = ocm_process.communicate()
        if ocm_process.returncode != 0:
            logging.error('%s unable to execute -h' % ocm_cmd)
            logging.error(ocm_stderr.strip().decode("utf-8"))
            return 1
        else:
            logging.info('Creating machinepool %s on %s' % (args.machinepool_name, cluster_id))
            # ocm create machinepool --cluster=<your cluster ID> --labels="foo=bar,bar=baz" --replicas=3 --instance-type="m5.xlarge" mp-1
            machinepool_cmd = ["ocm", "create", "machinepool",
                               "--cluster", cluster_id,
                               "--instance-type", args.machinepool_flavour,
                               "--labels", args.machinepool_labels,
                               "--taints", args.machinepool_taints,
                               "--replicas", str(args.machinepool_replicas),
                               args.machinepool_name]
            logging.debug(machinepool_cmd)
            machinepool_process = subprocess.Popen(machinepool_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            machinepool_stdout, machinepool_stderr = machinepool_process.communicate()
            if machinepool_process.returncode != 0:
                logging.error('Unable to create machinepool %s on %s' % (args.machinepool_name, cluster_id))
                logging.error(machinepool_stdout.strip().decode("utf-8"))
                logging.error(machinepool_stderr.strip().decode("utf-8"))
                return 1
            else:
                if args.machinepool_wait:
                    logging.info('Created machinepool %s on %s. Waiting up to %d seconds for hosts to come up' % (args.machinepool_name, cluster_id, args.machinepool_wait_cycles * 5))
                    logging.info('Checking if oc tool is available on the system')
                    oc_cmd = ["oc", "-h"]
                    logging.debug(oc_cmd)
                    oc_process = subprocess.Popen(oc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    oc_stdout, oc_stderr = oc_process.communicate()
                    if oc_process.returncode != 0:
                        logging.error('%s unable to execute -h' % oc_cmd)
                        logging.error(oc_stdout.strip().decode("utf-8"))
                        logging.error(oc_stderr.strip().decode("utf-8"))
                        return 1
                    else:
                        kubeconfig_env = os.environ.copy()
                        kubeconfig_env["KUBECONFIG"] = kubeconfig
                        # 60 cicles, waiting 5 seconds at the end of each cicle, is about 300 seconds (5 minutes)
                        for counter in range(1, args.machinepool_wait_cycles):
                            nodecheck_cmd = ["oc", "get", "nodes", "--no-headers=true",
                                             "-l", args.machinepool_labels,
                                             "-o", "custom-columns=NAME:metadata.name,STATUS:status.conditions[-1].type"]
                            logging.debug(nodecheck_cmd)
                            nodecheck_process = subprocess.Popen(nodecheck_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=kubeconfig_env)
                            nodecheck_stdout, nodecheck_stderr = nodecheck_process.communicate()
                            if nodecheck_process.returncode != 0:
                                logging.error('Unable to execute oc get command, cannot check node status')
                                logging.error(nodecheck_stdout.strip().decode("utf-8"))
                                logging.error(nodecheck_stderr.strip().decode("utf-8"))
                                return 1
                            else:
                                ready_nodes = 0
                                for line in nodecheck_stdout.splitlines():
                                    ready_nodes += 1 if line.split()[1].decode() == "Ready" else None
                                if ready_nodes >= args.machinepool_replicas:
                                    logging.info('Machinepool %s is created and ready nodes count (%d) meet expected (%d)' % (args.machinepool_name, ready_nodes, args.machinepool_replicas))
                                    logging.debug(nodecheck_stdout.strip().decode("utf-8"))
                                    logging.debug(nodecheck_stderr.strip().decode("utf-8"))
                                    break
                                else:
                                    logging.debug('Ready nodes count: %d. Expected: %d' % (ready_nodes, args.machinepool_replicas))
                                    logging.debug('Waiting 5 seconds for next node check. (%d of %d)' % (counter, args.machinepool_wait_cycles))
                                    time.sleep(5)
                        else:
                            logging.error('Machinepool %s is created but ready nodes count (%d) do not meet expected (%d)' % (args.machinepool_name, ready_nodes, args.machinepool_replicas))
                            logging.error(nodecheck_stdout.strip().decode("utf-8"))
                            logging.error(nodecheck_stderr.strip().decode("utf-8"))
                            return 1
    else:
        logging.error('Failed to load cluster-id from metadata.json file located on %s, machinepool %s wont be created' % (my_path, args.machinepool_name))
        return 1


def _build_cluster(osde2e_cmnd, osde2ectl_cmd, account_config, my_path, es, index, my_uuid, my_inc, cluster_count, timestamp, dry_run, index_retry, skip_health_check, must_gather, es_ignored_metadata):
    cluster_start_time = time.strftime("%Y-%m-%dT%H:%M:%S")
    success = True
    # osde2e takes a relative path to the account file so we need to create it in a working dir and
    # pass that dir as the cwd to subproccess
    cluster_path = my_path + "/" + account_config['cluster']['name']
    os.mkdir(cluster_path)
    yaml = YAML(pure=True)
    yaml.default_flow_style = False
    yaml.explicit_start = False
    yaml.explicit_end = False
    yaml.allow_duplicate_keys = True
    yaml.dump(account_config, open(cluster_path + "/cluster_account.yaml", 'w'))
    cluster_env = os.environ.copy()
    cluster_env["REPORT_DIR"] = cluster_path
    if "expiration" in account_config['ocm'].keys():
        cluster_env["CLUSTER_EXPIRY_IN_MINUTES"] = str(account_config['ocm']['expiration'])
    logging.debug('Attempting cluster installation')
    logging.debug('Output directory set to %s' % cluster_path)
    cluster_cmd = [osde2e_cmnd, "test", "--custom-config", "cluster_account.yaml"]
    cluster_cmd.append('--skip-health-check') if skip_health_check else None
    cluster_cmd.append('--must-gather=false') if not must_gather else None
    if args.wildcard_options:
        for param in args.wildcard_options.split():
            cluster_cmd.append(param)
    if not dry_run:
        logging.debug(cluster_cmd)
        installation_log = open(cluster_path + "/" + 'installation.log', 'w')
        process = subprocess.Popen(cluster_cmd, stdout=installation_log, stderr=installation_log, env=cluster_env, cwd=cluster_path)
        logging.info('Started cluster %s (%d of %d)' % (account_config['cluster']['name'], my_inc, cluster_count))
        stdout, stderr = process.communicate()
        cluster_end_time = time.strftime("%Y-%m-%dT%H:%M:%S")
        if process.returncode != 0:
            logging.error('Failed to build cluster %d: %s' % (my_inc, account_config['cluster']['name']))
            logging.error('Check installation.log and test_output.log files on %s for errors' % (cluster_path + "/"))
            success = False
        logging.debug('Attempting to load metadata json')
        metadata = {}
        try:
            metadata = json.load(open(cluster_path + "/metadata.json"))
        except Exception as err:
            logging.error(err)
            logging.error('Failed to load metadata.json file located %s' % cluster_path)
        metadata["cluster_start_time"] = cluster_start_time
        metadata["cluster_end_time"] = cluster_end_time
        metadata["install_successful"] = success
        metadata["uuid"] = my_uuid
        metadata['cluster_name'] = account_config['cluster']['name']
        metadata['multiAZ'] = 'True' if account_config['cluster']['multiAZ'] else None
        metadata["install_counter"] = my_inc
        try:
            with open(cluster_path + "/metadata.json", "w") as metadata_file:
                json.dump(metadata, metadata_file)
        except Exception as err:
            logging.error(err)
            logging.error('Failed to write metadata.json file located %s' % cluster_path)
        kubeconfig_path = _download_kubeconfig(osde2ectl_cmd, account_config['cluster']['name'], cluster_path)
        _add_machinepool(osde2ectl_cmd, kubeconfig_path, cluster_path) if args.machinepool_name else None
        if es is not None:
            metadata["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            common._index_result(es, index, metadata, es_ignored_metadata, index_retry)


def _watcher(osde2ectl_cmd, cluster_name_seed, account_config, my_path, cluster_count, delay, my_uuid):
    logging.info('Watcher thread started')
    logging.info('Getting status every %d seconds' % int(delay))
    yaml = YAML(pure=True)
    yaml.default_flow_style = False
    yaml.explicit_start = False
    yaml.explicit_end = False
    yaml.allow_duplicate_keys = True
    yaml.dump(account_config, open(my_path + "/account_config.yaml", 'w'))
    my_thread = threading.currentThread()
    cmd = [osde2ectl_cmd, "list", "--custom-config", "account_config.yaml"]
    # To stop the watcher we expect the run attribute to be not True
    while getattr(my_thread, "run", True):
        logging.debug(cmd)
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=my_path, universal_newlines=True)
        stdout, stderr = process.communicate()

        current_cluster_count = 0
        state = {}
        status = {}
        error = []
        # Count the various states/status' and report it to logging
        for line in stdout.splitlines():
            if cluster_name_seed in line:
                current_cluster_count += 1
                state_key = line.split()[2]
                status_key = line.split()[3]
                state[state_key] = state.get(state_key, 0) + 1
                status[status_key] = status.get(status_key, 0) + 1

                if state_key == "error":
                    error.append(line.split()[1])
                    logging.debug(line.split()[1])

        logging.info('Requested Clusters for test %s: %d' % (my_uuid, cluster_count))
        if current_cluster_count != 0:
            logging.debug(state.items())
            logging.debug(status.items())
            state_output = "Current clusters state: " + str(current_cluster_count) + " clusters"
            status_output = "Current clusters status: " + str(current_cluster_count) + " clusters"
            for i1 in state.items():
                state_output += " (" + str(i1[0]) + ": " + str(i1[1]) + ")"
            for i2 in status.items():
                status_output += " (" + str(i2[0]) + ": " + str(i2[1]) + ")"
            logging.info(state_output)
            logging.info(status_output)
            if error:
                logging.warning('Clusters in error state: %s' % error)
            account_config['clusters_created'] = current_cluster_count
            account_config['state'] = state
            account_config['status'] = status
        time.sleep(delay)
    logging.info('Watcher exiting')


def _cleanup_clusters(osde2ectl_cmd, cluster_name_seed, my_path, account_config):
    logging.info('Starting cluster cleanup')
    exit_status = 0
    cmd = [osde2ectl_cmd, "list", "--custom-config", "account_config.yaml"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=my_path, universal_newlines=True)
    stdout, stderr = process.communicate()
    error = []
    for line in stdout.splitlines():
        if cluster_name_seed in line:
            state = line.split()[2]
            cluster_id = line.split()[1]
            if state != "error" and state != "uninstalling":
                logging.debug('Deleting cluster id: %s' % cluster_id)
                del_cmd = [osde2ectl_cmd, "--custom-config", "account_config.yaml", "delete", "-i", cluster_id]
                process = subprocess.Popen(del_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=my_path, universal_newlines=True)
                stdout, stderr = process.communicate()
                if process.returncode != 0:
                    logging.error('Cluster cleanup failed for cluster id %s with this stdout/stderr:' % cluster_id)
                    logging.error(stdout)
                    logging.error(stderr)
                    exit_status = 1
            else:
                error.append(cluster_id)
    logging.info('Clusters in error state. Not deleting:')
    logging.info(error)
    return exit_status


def main():
    parser = argparse.ArgumentParser(description="osde2e wrapper script",
                                     parents=[parentParsers.esParser,
                                              parentParsers.runnerParser,
                                              parentParsers.clusterParser,
                                              parentParsers.machinepoolParser,
                                              parentParsers.logParser])
    parser.add_argument(
        '--account-config',
        help='Yaml account config')
    parser.add_argument(
        '-c', '--command',
        help='Full path to the osde2e and osde2ectl command directory. If not provided we will download and compile the latest')
    parser.add_argument(
        '--user-override',
        type=str,
        help='User to set as the owner')
    parser.add_argument(
        '--aws-account-file',
        type=str,
        help='AWS account file to use')
    parser.add_argument(
        '--dry-run',
        dest='dry_run',
        action='store_true',
        help='Perform a dry-run of the script without creating any cluster')
    parser.add_argument(
        '--skip-health-check',
        dest='skip_health_check',
        action='store_true',
        help='Do not execute health checks after cluster installation')
    parser.add_argument(
        '--osde2e-must-gather',
        dest='osde2e_must_gather',
        help='Add a must-gather operation at the end of the osde2e test process',
        action='store_true')

    global args
    args = parser.parse_args()

    if not args.es_index_only and not args.account_config:
        parser.error("argument '--account-config' is required (except when using '--es-index-only')")

    if args.only_delete_clusters and not args.path:
        parser.error("argument '--path' is required when using '--only-delete-clusters'")

    _es_ignored_metadata = []
    if args.es_url is not None:
        es = common._connect_to_es(args.es_url, args.es_insecure)
        if args.es_ignored_metadata is None:
            _es_ignored_metadata = str(args.es_ignored_metadata).split(',')
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
        common._create_path(os.path.dirname(args.log_file))
        logfile = logging.FileHandler(args.log_file)
        logfile.setFormatter(log_format)
        logger.addHandler(logfile)
        logging.info('Logging to file: %s' % args.log_file)
    else:
        logging.info('Logging to console')

    if args.es_index_only:
        logging.info('Starting to upload metadata files to elastic')
        if args.path is not None and es is not None:
            index_result = 0
            from pathlib import Path
            metadata_files = list(Path(args.path).rglob("metadata.json"))
            logging.debug('Metadata files found: %s' % metadata_files)
            for metadata_file in metadata_files:
                logging.debug('Attempting to load metadata json %s' % metadata_file)
                try:
                    metadata = json.load(open(metadata_file))
                    metadata["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                except Exception as err:
                    logging.error(err)
                    logging.error('Failed to load metadata.json file located %s' % metadata_file)
                index_result += common._index_result(es, args.es_index, metadata, _es_ignored_metadata, args.es_index_retry)
        else:
            logging.error('PATH and elastic related parameters required when uploading data to elastic')
            exit(1)
        exit(index_result)

    if args.only_delete_clusters:
        try:
            logging.info('Reading cluster name seed from %s' % args.path)
            cluster_name_seed_file = open(args.path + '/cluster_name_seed')
            cluster_name_seed = cluster_name_seed_file.read().replace("\n", "")
            logging.info('Found cluster name seed as: %s' % cluster_name_seed)
        except Exception as err:
            logging.error(err)
            logging.error('Failed to read %s/cluster_name_seed file' % args.path)
            exit(1)
        try:
            yaml = YAML(pure=True)
            account_config = yaml.load(open(args.account_config))
        except Exception as err:
            logging.error(err)
            logging.error('Failed to load account configuration yaml')
            exit(1)
        cmnd_path = _verify_cmnd(args.command, args.path)
        cleanup_result = _cleanup_clusters(cmnd_path + "/osde2ectl", cluster_name_seed, args.path, account_config)
        exit(cleanup_result)

    # global uuid to assign for the group of clusters created. each cluster will have its own cluster-id
    my_uuid = args.uuid
    if my_uuid is None:
        my_uuid = str(uuid.uuid4())
    logging.info('Test running with UUID: %s' % my_uuid)

    my_path = args.path
    if my_path is None:
        my_path = '/tmp/' + my_uuid
    logging.info('Using %s as working directory' % (my_path))
    common._create_path(my_path)

    if os.path.exists(args.account_config):
        logging.debug('Account configuration file exists')
    else:
        logging.error('Account configuration file not found at %s' % args.account_config)
        exit(1)

    try:
        logging.debug('Saving test UUID to the working directory')
        uuid_file = open(my_path + '/uuid', 'x')
        uuid_file.write(my_uuid)
        uuid_file.close()
    except Exception as err:
        logging.debug('Cannot write file %s/uuid' % my_path)
        logging.error(err)
        exit(1)

    # load the account config yaml
    try:
        yaml = YAML(pure=True)
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

    cluster_name_seed = common._generate_cluster_name_seed(args.cluster_name_seed)

    try:
        logging.debug('Saving cluster name seed %s to the working directory' % cluster_name_seed)
        seed_file = open(my_path + '/cluster_name_seed', 'x')
        seed_file.write(cluster_name_seed)
        seed_file.close()
    except Exception as err:
        logging.debug('Cannot write file %s/cluster_name_seed' % my_path)
        logging.error(err)
        exit(1)

    # Set the user override if provided on the cli or generate a new one
    # if none is set
    if args.user_override is not None:
        account_config['ocm']['userOverride'] = args.user_override
    elif "userOverride" not in account_config['ocm'].keys():
        account_config['ocm']['userOverride'] = str(uuid.uuid4())[:8]
    logging.info('User override set to: %s' % account_config['ocm']['userOverride'])

    if args.expire is not None:
        account_config['ocm']['expiration'] = args.expire
        logging.info('Setting cluster expiration time to: %d' % args.expire)

    cmnd_path = _verify_cmnd(args.command, my_path) if not args.dry_run else ""

    # launch watcher thread to report status
    if not args.dry_run:
        logging.info('Launching watcher thread')
        watcher = threading.Thread(target=_watcher, args=(cmnd_path + "/osde2ectl", cluster_name_seed, account_config, my_path, args.cluster_count, args.watcher_delay, my_uuid))
        watcher.daemon = True
        watcher.start()
        logging.info('Attempting to start %d clusters with %d batch size' % (args.cluster_count, args.batch_size))
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
                if "cluster" not in my_cluster_config.keys() or my_cluster_config['cluster'] is None:
                    my_cluster_config['cluster'] = {}
                my_cluster_config['cluster']['name'] = cluster_name_seed + "-" + str(loop_counter).zfill(4)
                logging.debug('Starting Cluster thread %d for cluster %s' % (loop_counter + 1, my_cluster_config['cluster']['name']))
                try:
                    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
                    thread = threading.Thread(target=_build_cluster, args=(cmnd_path + "/osde2e", cmnd_path + "/osde2ectl", my_cluster_config, my_path, es, args.es_index, my_uuid, loop_counter, args.cluster_count, timestamp, args.dry_run, args.es_index_retry, args.skip_health_check, args.osde2e_must_gather, _es_ignored_metadata))
                except Exception as err:
                    logging.error(err)
                cluster_thread_list.append(thread)
                thread.start()
                logging.debug('Number of alive threads %d' % threading.active_count())

    except Exception as err:
        logging.error(err)
        logging.error('Thread creation failed')

    # Wait for active threads to finish
    logging.info('All clusters (%d) requested. Waiting for them to finish' % len(cluster_thread_list))
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

    if args.cleanup_clusters and not args.dry_run:
        cleanup_result = _cleanup_clusters(cmnd_path + "/osde2ectl", cluster_name_seed, my_path, account_config)
        logging.warning('Cleanup process failed') if cleanup_result != 0 else None

    if args.cleanup:
        shutil.rmtree(my_path)

# Last, output test result
    if not args.dry_run:
        logging.info('************************************************************************')
        logging.info('********* Summary for test %s *********' % (my_uuid))
        logging.info('************************************************************************')
        logging.info('Requested Clusters for test %s: %d' % (my_uuid, args.cluster_count))
        if 'clusters_created' in account_config:
            logging.info('Created   Clusters for test %s: %d' % (my_uuid, account_config['clusters_created']))
            if 'state' in account_config:
                for i1 in account_config['state'].items():
                    logging.info('              %s: %s' % (str(i1[0]), str(i1[1])))
        else:
            logging.info('Created   Clusters for test %s: 0' % (my_uuid))
        logging.info('Batches size: %s' % (str(args.batch_size)))
        logging.info('Delay between batches: %s' % (str(args.delay_between_batch)))
        logging.info('Cluster Name Seed: %s' % (cluster_name_seed))


if __name__ == '__main__':
    sys.exit(main())
