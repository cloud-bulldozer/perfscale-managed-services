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
import requests
import urllib
import logging
import threading
from libs import common
from libs import parentParsers

# If rosa command path is provided verify we can run the help function
# If it is not provided, dowload binary from the latest tag
def _verify_cmnd(rosa_cmnd,my_path):
    # If the command path was not given, download latest binary from github
    if rosa_cmnd is None:
        logging.info('rosa command not provided')
        logging.info('Downloading latest binary rosa-linux-amd64 from https://github.com/openshift/rosa/releases/')
        tags_list = []
        try:
            tags = requests.get(url='https://api.github.com/repos/openshift/rosa/git/refs/tags')
        except requests.ConnectionError as err:
            logging.error('Cannot download tags list from https://api.github.com/repos/openshift/rosa/git/refs/tags')
            logging.error(err)
            exit(1)
        # Get all tags, sort and use the last one
        for tag in tags.json():
            tags_list.append(tag['ref'])
        tags_list.sort()
        logging.debug('Identified latest release as %s' % tags_list[-1].split('/')[-1])
        url = 'https://github.com/openshift/rosa/releases/download/' + tags_list[-1].split('/')[-1] + '/rosa-linux-amd64'
        with urllib.request.urlopen(url) as response, open(my_path + '/rosa', 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
        os.chmod(my_path + '/rosa', 0o777)
        rosa_cmnd = my_path + "/rosa"
    logging.info('Testing rosa command with: rosa -h')
    rosa_cmd = [rosa_cmnd, "-h"]
    rosa_process = subprocess.Popen(rosa_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rosa_stdout,rosa_stderr = rosa_process.communicate()
    if rosa_process.returncode != 0:
        logging.error('%s unable to execute -h' % rosa_cmnd)
        logging.error(rosa_stderr.strip().decode("utf-8"))
        exit(1)
    logging.info('rosa command validated with -h. Directory is %s' % my_path)
    return rosa_cmnd

# No command to download kubeconfig using rosa CLI
# https://issues.redhat.com/browse/SDA-3606
# workarround using ocm cli
# def _download_kubeconfig(osde2ectl_cmd,my_path):
def _download_kubeconfig(cluster_id,my_path):
    logging.info('Checking if ocm tool is available on the system')
    ocm_cmd = ["ocm", "-h"]
    logging.debug(ocm_cmd)
    ocm_process = subprocess.Popen(ocm_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ocm_stdout,ocm_stderr = ocm_process.communicate()
    if ocm_process.returncode != 0:
        logging.error('%s unable to execute -h' % ocm_cmd)
        logging.error(ocm_stderr.strip().decode("utf-8"))
    else:
        logging.info('Downloading kubeconfig file for cluster %s on %s' % (cluster_id,my_path))
        kubeconfig_cmd = ["ocm", "get", "/api/clusters_mgmt/v1/clusters/" + cluster_id + "/credentials"]
        logging.debug(kubeconfig_cmd)
        process = subprocess.Popen(kubeconfig_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,cwd=my_path,universal_newlines=True)
        stdout,stderr = process.communicate()
        if process.returncode != 0:
            logging.error('Failed to download kubeconfig file for cluster id %s with this stdout/stderr:' % cluster_id)
            logging.error(stdout)
            logging.error(stderr)
        else:
            with open(my_path + "/kubeconfig", "w") as kubeconfig_file:
                kubeconfig_file.write(json.loads(stdout)['kubeconfig'])
            logging.info('Downloaded kubeconfig file for cluster %s and stored at %s/kubeconfig' % (cluster_id, my_path))

def _install_addons(rosa_cmnd,cluster_id,addons):
    addons_list = addons.split(",")
    for addon in addons_list:
        logging.info('Installing %s addon on %s' % (addon,cluster_id))
        # TODO: Check if addon is available before executing install command: rosa list addons
        #       because rosa install do not fire any error if tried to install a non-available addon
        addon_cmd = [rosa_cmnd, "install", "addon", "--cluster", cluster_id, addon, "-y"]
        logging.debug(addon_cmd)
        addon_process = subprocess.Popen(addon_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        addon_stdout,addon_stderr = addon_process.communicate()
        if addon_process.returncode != 0:
            logging.error('Unable to install addon %s on %s' % (addon,cluster_id))
            logging.error(addon_stdout.strip().decode("utf-8"))
            logging.error(addon_stderr.strip().decode("utf-8"))
        # TODO: control addon is installed with: rosa list addons -c <<cluster_name>>

def _build_cluster(rosa_cmnd,cluster_name_seed,expiration,rosa_azs,my_path,es,index,my_uuid,my_inc,timestamp,index_retry,addons,es_ignored_metadata,rosa_flavour):
    cluster_start_time = time.strftime("%Y-%m-%dT%H:%M:%S")
    success = True
    metadata = {}
    # pass that dir as the cwd to subproccess
    cluster_path = my_path + "/" + cluster_name_seed + "-" + str(my_inc).zfill(4)
    os.mkdir(cluster_path)
    logging.debug('Attempting cluster installation')
    logging.debug('Output directory set to %s' % cluster_path)
    cluster_name = cluster_name_seed + "-" + str(my_inc).zfill(4)
    metadata["cluster_name"] = cluster_name
    cluster_cmd = [rosa_cmnd, "create","cluster", "--cluster-name", cluster_name, "-y", "--watch"]
    if rosa_azs:
        cluster_cmd.append('--multi-az')
    if rosa_flavour:
        cluster_cmd.append('--flavour=' + rosa_flavour)
    logging.debug(cluster_cmd)
    installation_log = open(cluster_path + "/" + 'installation.log', 'w')
    process = subprocess.Popen(cluster_cmd, stdout=installation_log, stderr=installation_log)
    logging.info('Started cluster %d' % my_inc)
    stdout,stderr = process.communicate()
    cluster_end_time = time.strftime("%Y-%m-%dT%H:%M:%S")
    # Getting information to add it on metadata
    logging.info('Getting information for cluster %s' % cluster_name)
    metadata_cmd = [rosa_cmnd, "describe", "cluster", "-c", cluster_name]
    logging.debug(metadata_cmd)
    metadata_process = subprocess.Popen(metadata_cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True)
    stdout,stderr = metadata_process.communicate()
    for line in stdout.splitlines():
        if line.startswith('ID: '):
            metadata["cluster_id"] = line.split(':')[1].strip()
        elif line.startswith('Region: '):
            metadata["region"] = line.split(':')[1].strip()
        elif line.startswith('Details Page: '):
            metadata["details_url"] = line.split(': ')[1].strip()
    if process.returncode != 0:
        logging.error('Failed to build cluster number %d' % my_inc)
        with open(cluster_path + "/" + 'installation.log',"r") as output_file:
            logging.error(output_file.read())
        success = False
        # Only extending expiration on failed clusters, because ready one will be deleted at the end of the script
        # if expiration:
        #     logging.info('Extending cluster expiration on %d minutes' % expiration)
        # rosa edit cluster -c 1iaaehmdd23lhifqk4fsjghrci82nt51 --expiration-time=2021-01-22T03:05:42.44677Z
        # rosa edit cluster -c 1iaaehmdd23lhifqk4fsjghrci82nt51 --expiration=72h
        # https://issues.redhat.com/browse/SDA-3600
    else:
        _download_kubeconfig(metadata['cluster_id'], cluster_path)
        _install_addons(rosa_cmnd,metadata['cluster_id'], addons) if addons else None
    metadata["cluster_start_time"] = cluster_start_time
    metadata["cluster_end_time"] = cluster_end_time
    metadata["install_successful"] = success
    metadata["uuid"] = my_uuid
    metadata["install_counter"] = str(my_inc).zfill(4)
    try:
        with open(cluster_path + "/metadata.json", "w") as metadata_file:
            json.dump(metadata, metadata_file)
    except Exception as err:
        logging.error(err)
        logging.error('Failed to write metadata.json file located %s' % cluster_path)
    if es is not None:
        metadata["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        common._index_result(es,index,metadata,es_ignored_metadata,index_retry)

def _watcher(rosa_cmnd,cluster_name_seed,cluster_count,delay,my_uuid,clusters_resume):
    time.sleep(30)
    logging.info('Watcher thread started')
    logging.info('Getting status every %d seconds' % int(delay))
    my_thread = threading.currentThread()
    # We need to determine somewhere the number of clusters to show
    cmd = [rosa_cmnd, "list", "clusters"]
    # To stop the watcher we expect the run attribute to be not True
    while getattr(my_thread, "run", True):
        logging.debug(cmd)
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,universal_newlines=True)
        stdout,stderr = process.communicate()
        current_cluster_count = 0
        state = {}
        error = []
        # Count the various states/status' and report it to logging
        for line in stdout.splitlines():
            if cluster_name_seed in line:
                current_cluster_count += 1
                state_key = line.split()[2]
                state[state_key] = state.get(state_key, 0) + 1
                if state_key == "error":
                    error.append(line.split()[0])
        logging.info('Requested Clusters for test %s: %d' % (my_uuid,cluster_count))
        if current_cluster_count != 0:
            logging.debug(state.items())
            state_output = "Current clusters state: " + str(current_cluster_count) + " clusters"
            for i in state.items():
                state_output += " (" + str(i[0]) + ": " + str(i[1]) + ")"
            logging.info(state_output)
            if error:
                logging.warning('Clusters in error state: %s' % error)
            clusters_resume['state'] = state
            clusters_resume['clusters_created'] = current_cluster_count
        time.sleep(delay)
    logging.info('Watcher exiting')

def _cleanup_clusters(rosa_cmnd,cluster_name_seed):
    exit_status = 0
    logging.info('Starting cluster cleanup for %s' % cluster_name_seed)
    cmd = [rosa_cmnd, "list", "clusters"]
    logging.debug(cmd)
    all_clusters = subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True)
    stdout,stderr = all_clusters.communicate()
    error = []
    logging.debug('Finding clusters for %s' % cluster_name_seed)
    for line in stdout.splitlines():
        if cluster_name_seed in line:
            state = line.split()[2]
            cluster_id = line.split()[0]
            if state != "error" and state != "uninstalling":
                logging.debug('Deleting cluster id: %s' % cluster_id)
                del_cmd = [rosa_cmnd, "delete", "cluster", "-c", cluster_id, "-y"]
                process = subprocess.Popen(del_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,universal_newlines=True)
                stdout,stderr = process.communicate()
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
                                              parentParsers.logParser])
    parser.add_argument(
        '--rosa-cli',
        help='Full path to the rosa cli binary. If not provided we will download latest')
    parser.add_argument(
        '--rosa-init',
        dest='rosa_init',
        action='store_true',
        help='Execute `rosa init` command to configure AWS account')
    parser.add_argument(
        '--rosa-token',
        type=str,
        help='ROSA offline access token obtained on https://cloud.redhat.com/openshift/token/rosa')
    parser.add_argument(
        '--rosa-env',
        type=str,
        help='ROSA environment to provide as --env to `rosa login` command. If no defined, will be executed on production')
    parser.add_argument(
        '--rosa-multi-az',
        dest='rosa_azs',
        action='store_true',
        help='Install ROSA clusters with multi-az support, deploying on multiple datacenters')
    parser.add_argument(
        '--rosa-addons',
        type=str,
        help='Comma separated list of addons to add to each cluster after installation is completed')
    parser.add_argument(
        '--rosa-flavour',
        type=str,
        help='AWS Flavor to use for infra nodes')
    parser.add_argument(
        '--aws-profile',
        type=str,
        help='AWS profile to use if more than one are present on aws config file')
    args = parser.parse_args()

    if not args.es_index_only and not args.rosa_token:
        parser.error("argument '--rosa-token' is required (except when using '--es-index-only')")

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
                index_result += common._index_result(es,args.es_index,metadata,_es_ignored_metadata,args.es_index_retry)
        else:
            logging.error('PATH and elastic related parameters required when uploading data to elastic')
            exit(1)
        exit(index_result)

    if args.only_delete_clusters:
        try:
            logging.info('Reading cluster name seed from %s' % args.path)
            cluster_name_seed_file = open(args.path + '/cluster_name_seed')
            cluster_name_seed = cluster_name_seed_file.read().replace("\n","")
            logging.info('Found cluster name seed as: %s' % cluster_name_seed)
        except Exception as err:
            logging.error(err)
            logging.error('Failed to read %s/cluster_name_seed file' % args.path)
            exit(1)
        rosa_cmnd = _verify_cmnd(args.rosa_cli,args.path)
        cleanup_result = _cleanup_clusters(rosa_cmnd,cluster_name_seed)
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

    try:
        logging.debug('Saving test UUID to the working directory')
        uuid_file = open(my_path + '/uuid','x')
        uuid_file.write(my_uuid)
        uuid_file.close()
    except Exception as err:
        logging.debug('Cannot write file %s/uuid' % my_path)
        logging.error(err)
        exit(1)

    cluster_name_seed = common._generate_cluster_name_seed(args.cluster_name_seed)

    try:
        logging.debug('Saving cluster name seed %s to the working directory' % cluster_name_seed)
        seed_file = open(my_path + '/cluster_name_seed','x')
        seed_file.write(cluster_name_seed)
        seed_file.close()
    except Exception as err:
        logging.debug('Cannot write file %s/cluster_name_seed' % my_path)
        logging.error(err)
        exit(1)

    rosa_cmnd = _verify_cmnd(args.rosa_cli,my_path)

    logging.info('Attempting to log in OCM using `rosa login`')
    rosa_login_command = [rosa_cmnd, "login", "--token=" + args.rosa_token]
    if args.rosa_env:
        rosa_login_command.append('--env=' + args.rosa_env)
    logging.debug(rosa_login_command)
    rosa_login_process = subprocess.Popen(rosa_login_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rosa_login_stdout,rosa_login_stderr = rosa_login_process.communicate()
    if rosa_login_process.returncode != 0:
        logging.error('%s unable to execute `rosa login`' % rosa_cmnd)
        logging.error(rosa_login_stderr.strip().decode("utf-8"))
        exit(1)
    else:
        logging.info('`rosa login` execution OK')
        logging.debug(rosa_login_stdout.strip().decode("utf-8"))

    if args.rosa_init:
        logging.info('Executing `rosa init` command to configure AWS account')
        rosa_init_command = [rosa_cmnd, "init", "--token=" + args.rosa_token]
        if args.aws_profile:
            rosa_init_command.append('--profile')
            rosa_init_command.append(args.aws_profile)
        if args.rosa_env:
            rosa_init_command.append('--env=' + args.rosa_env)
        logging.debug(rosa_init_command)
        rosa_init_process = subprocess.Popen(rosa_init_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        rosa_init_stdout,rosa_init_stderr = rosa_init_process.communicate()
        if rosa_init_process.returncode != 0:
            logging.error('%s unable to execute `rosa init`' % rosa_cmnd)
            logging.error(rosa_init_stderr.strip().decode("utf-8"))
            exit(1)
        else:
            logging.info('`rosa init` execution OK')
            logging.debug(rosa_init_stdout.strip().decode("utf-8"))

    # launch watcher thread to report status
    logging.info('Launching watcher thread')
    clusters_resume = {}
    watcher = threading.Thread(target=_watcher,args=(rosa_cmnd,cluster_name_seed,args.cluster_count,args.watcher_delay,my_uuid,clusters_resume))
    watcher.daemon = True
    watcher.start()

    logging.info('Attempting to start %d clusters with %d batch size' % (args.cluster_count,args.batch_size))
    cluster_thread_list = []
    batch_count = 0
    loop_counter = 0
    try:
        while (loop_counter < args.cluster_count):
            create_cluster = False
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
                logging.debug('Starting Cluster thread %d' % (loop_counter + 1))
                try:
                    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
                    thread = threading.Thread(target=_build_cluster,args=(rosa_cmnd,cluster_name_seed,args.expire,args.rosa_azs,my_path,es,args.es_index,my_uuid,loop_counter,timestamp,args.es_index_retry,args.rosa_addons,_es_ignored_metadata,args.rosa_flavour))
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

    watcher.run = False
    watcher.join()

    if args.cleanup_clusters:
        cleanup = _cleanup_clusters(rosa_cmnd,cluster_name_seed)
        logging.warning('Cleanup process failed') if cleanup != 0 else None

    if args.cleanup is True:
        shutil.rmtree(my_path)

# Last, output test result
    logging.info('************************************************************************')
    logging.info('********* Resume for test %s *********' % (my_uuid))
    logging.info('************************************************************************')
    logging.info('Requested Clusters for test %s: %d' % (my_uuid,args.cluster_count))
    logging.info('Created   Clusters for test %s: %d' % (my_uuid,clusters_resume['clusters_created']))
    for i1 in clusters_resume['state'].items():
        logging.info('              %s: %s' % (str(i1[0]),str(i1[1])))
    logging.info('Batches size: %s' % (str(args.batch_size)))
    logging.info('Delay between batches: %s' % (str(args.delay_between_batch)))
    logging.info('Cluster Name Seed: %s' % (cluster_name_seed))


if __name__ == '__main__':
    sys.exit(main())
