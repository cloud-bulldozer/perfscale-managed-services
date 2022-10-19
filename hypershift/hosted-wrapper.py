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
import datetime
import subprocess
import sys
import shutil
import os
import uuid
import json
import base64
import random
import re
import requests
import urllib
import logging
import configparser
from distutils import version as ver
import threading
from git import Repo
from libs import common
from libs import parentParsers


def _verify_cmnds(ocm_cmnd, hypershift_cmnd, my_path, ocm_version, hypershift_version):
    # If the command path was not given, download latest binary from github
    if ocm_cmnd is None:
        logging.info('ocm command not provided')
        logging.info('Downloading binary ocm from https://github.com/openshift-online/ocm-cli/releases/')
        tags_list = []
        try:
            tags = requests.get(url='https://api.github.com/repos/openshift-online/ocm-cli/git/refs/tags')
        except (requests.ConnectionError, urllib.error.HTTPError) as err:
            logging.error('Cannot download tags list from https://api.github.com/repos/openshift-online/ocm-cli/git/refs/tags')
            logging.error(err)
            exit(1)
        # Get all tags, sort and select the correct one
        for tag in tags.json():
            tags_list.append(tag['ref'].split('/')[-1].split('v')[-1])
        logging.debug('List of tags: %s' % tags_list)
        if ocm_version == 'latest':
            version = sorted(tags_list, key=ver.StrictVersion)[-1]
        else:
            version = None
            for tag in tags_list:
                if tag == ocm_version:
                    version = tag
            if version is None:
                version = sorted(tags_list, key=ver.StrictVersion)[-1]
                logging.error('Invalid OCM release %s, downloading latest release identified as %s' % (ocm_version, version))
        logging.info('Downloading release identified as %s' % version)
        try:
            url = 'https://github.com/openshift-online/ocm-cli/releases/download/v' + version + '/ocm-linux-amd64'
            with urllib.request.urlopen(url) as response, open(my_path + '/ocm', 'wb') as out_file:
                shutil.copyfileobj(response, out_file)
            os.chmod(my_path + '/ocm', 0o777)
            ocm_cmnd = my_path + "/ocm"
        except urllib.error.HTTPError as err:
            logging.error('Failed to download valid version %s from GitHub: %s' % (version, err))
            exit(1)
    logging.info('Testing ocm command with: ocm -h')
    ocm_cmd = [ocm_cmnd, "-h"]
    ocm_process = subprocess.Popen(ocm_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ocm_stdout, ocm_stderr = ocm_process.communicate()
    if ocm_process.returncode != 0:
        logging.error('%s unable to execute -h' % ocm_cmnd)
        logging.error(ocm_stderr.strip().decode("utf-8"))
        return 1
    logging.info('ocm command validated with -h. Directory is %s' % my_path)
    if hypershift_cmnd is None:
        logging.info('hypershift command not provided')
        logging.info('Cloning hypershift repo and compiling cli from https://github.com/openshift/hypershift/ using %s branch' % hypershift_version)
        Repo.clone_from("https://github.com/openshift/hypershift.git", my_path + '/hypershift', branch=hypershift_version)
        os.chdir(my_path + '/hypershift')
        logging.info('Compiling hypershift cli on %s' % my_path + '/hypershift')
        make_cmd = ["make", "build"]
        make_process = subprocess.Popen(make_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        make_stdout, make_stderr = make_process.communicate()
        if make_process.returncode != 0:
            logging.error('%s unable to execute' % make_cmd)
            logging.error(make_stderr.strip().decode("utf-8"))
            return 1
        logging.info('hypershift cli compiled and stored at %s' % my_path + 'hypershift/bin/hypershift')
        os.chmod(my_path + '/hypershift/bin/hypershift', 0o777)
        hypershift_cmnd = my_path + "/hypershift/bin/hypershift"
    logging.info('Testing hypershift command with: hypershift -h')
    hypershift_cmd = [hypershift_cmnd, "-h"]
    hypershift_process = subprocess.Popen(hypershift_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    hypershift_stdout, hypershift_stderr = hypershift_process.communicate()
    if hypershift_process.returncode != 0:
        logging.error('%s unable to execute -h' % hypershift_cmnd)
        logging.error(hypershift_stderr.strip().decode("utf-8"))
        return 1
    logging.info('hypershift command validated with -h. Directory is %s' % my_path)
    return (ocm_cmnd, hypershift_cmnd)


def _get_mgmt_cluster_info(ocm_cmnd, mgmt_cluster, es, index, index_retry, uuid, hostedclusters):
    logging.info('Getting Management Cluster Information from %s' % mgmt_cluster)
    ocm_command = [ocm_cmnd, "get", "/api/clusters_mgmt/v1/clusters"]
    ocm_process = subprocess.Popen(ocm_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ocm_stdout, ocm_stderr = ocm_process.communicate()
    if ocm_process.returncode != 0:
        logging.error('%s unable to execute ' % ocm_command)
        logging.error(ocm_stderr.strip().decode("utf-8"))
        return {}
    else:
        for cluster in json.loads(ocm_stdout.decode("utf-8"))['items']:
            if cluster['id'] == mgmt_cluster or cluster['name'] == mgmt_cluster:
                metadata = {}
                metadata['uuid'] = uuid
                metadata['cluster_name'] = cluster['infra_id']
                metadata['cluster_id'] = cluster['id']
                metadata['version'] = cluster['openshift_version']
                metadata['base_domain'] = cluster['dns']['base_domain']
                metadata['aws_region'] = cluster['region']['id']
                metadata['workers'] = cluster['nodes']['compute']
                metadata['workers_type'] = cluster['nodes']['compute_machine_type']['id']
                metadata['network_type'] = cluster['network']['type']
                # metadata["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                metadata["timestamp"] = datetime.datetime.utcnow().isoformat()
                metadata['hostedclusters'] = hostedclusters
                es_ignored_metadata = ""
                if es is not None:
                    common._index_result(es, index, metadata, es_ignored_metadata, index_retry)
                return metadata


def _download_kubeconfig(ocm_cmnd, mgmt_cluster_id, my_path):
    logging.debug('Downloading kubeconfig file for Management Cluster %s on %s' % (mgmt_cluster_id, my_path))
    kubeconfig_cmd = [ocm_cmnd, "get", "/api/clusters_mgmt/v1/clusters/" + mgmt_cluster_id + "/credentials"]
    logging.debug(kubeconfig_cmd)
    process = subprocess.Popen(kubeconfig_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=my_path, universal_newlines=True)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        logging.error('Failed to download kubeconfig file for Management Cluster ID %s with this stdout/stderr:' % mgmt_cluster_id)
        logging.error(stdout)
        logging.error(stderr)
    else:
        kubeconfig_path = my_path + "/mgmt_kubeconfig"
        with open(kubeconfig_path, "w") as kubeconfig_file:
            kubeconfig_file.write(json.loads(stdout)['kubeconfig'])
        logging.debug('Downloaded kubeconfig file for Management Cluster ID %s and stored at %s' % (mgmt_cluster_id, kubeconfig_path))
        return kubeconfig_path


def _build_cluster(hypershift_cmnd, kubeconfig_location, cluster_name_seed, mgmt_cluster_base_domain, cluster_load, load_duration, job_iterations, worker_nodes, mgmt_cluster_aws_zone, pull_secret_file, my_path, my_uuid, my_inc, es, es_url, index, index_retry, mgmt_cluster_name, all_clusters_installed):
    myenv = os.environ.copy()
    myenv["KUBECONFIG"] = kubeconfig_location
    # pass that dir as the cwd to subproccess
    cluster_path = my_path + "/" + cluster_name_seed + "-" + str(my_inc).zfill(4)
    os.mkdir(cluster_path)
    logging.debug('Attempting cluster installation')
    logging.debug('Output directory set to %s' % cluster_path)
    cluster_name = cluster_name_seed + "-" + str(my_inc).zfill(4)
    cluster_cmd = [hypershift_cmnd, "create", "cluster", "aws", "--name", cluster_name, "--base-domain", mgmt_cluster_base_domain, "--additional-tags", "mgmt-cluster=" + mgmt_cluster_name, "--aws-creds", my_path + '/aws_creds', "--pull-secret", pull_secret_file, "--region", mgmt_cluster_aws_zone, "--node-pool-replicas", str(worker_nodes), '--wait', '--timeout', '30m']
    if args.wildcard_options:
        for param in args.wildcard_options.split():
            cluster_cmd.append(param)
    logging.debug(cluster_cmd)
    installation_log = open(cluster_path + "/" + 'installation.log', 'w')
    cluster_start_time = int(time.time())
    process = subprocess.Popen(cluster_cmd, stdout=installation_log, stderr=installation_log, env=myenv)
    logging.info('Started cluster %d with %d workers' % (my_inc, worker_nodes))
    stdout, stderr = process.communicate()
    # Getting information to add it on metadata
    cluster_end_time = int(time.time())
    metadata = get_metadata(kubeconfig_location, cluster_path, cluster_end_time - cluster_start_time, cluster_name, my_uuid, "install")
    try:
        with open(cluster_path + "/metadata_install.json", "w") as metadata_file:
            json.dump(metadata, metadata_file)
    except Exception as err:
        logging.error(err)
        logging.error('Failed to write metadata_install.json file located %s' % cluster_path)
    metadata['mgmt_cluster_name'] = mgmt_cluster_name
    metadata['job_iterations'] = str(job_iterations) if cluster_load else 0
    metadata['load_duration'] = load_duration if cluster_load else ""
    metadata['workers'] = str(worker_nodes)
    if process.returncode == 0:
        if es is not None:
            metadata["timestamp"] = datetime.datetime.utcnow().isoformat()
            es_ignored_metadata = ""
            common._index_result(es, index, metadata, es_ignored_metadata, index_retry)
        if cluster_load:
            with all_clusters_installed:
                logging.info('Waiting for all clusters to be installed to start e2e-benchmarking execution on %s' % cluster_name)
                all_clusters_installed.wait()
            logging.info('Executing e2e-benchmarking to add load on the cluster %s with %s nodes during %s with %d iterations' % (cluster_name, str(worker_nodes), load_duration, job_iterations))
            _cluster_load(kubeconfig_location, my_path, cluster_name, load_duration, job_iterations, es_url, mgmt_cluster_name)
            logging.info('Finished execution of e2e-benchmarking workload on %s' % cluster_name)
    else:
        if es is not None:
            metadata['status'] = "Not Installed"
            metadata["timestamp"] = datetime.datetime.utcnow().isoformat()
            es_ignored_metadata = ""
            common._index_result(es, index, metadata, es_ignored_metadata, index_retry)
        logging.error("Hypershift installation failed for cluster %s" % cluster_name)
        logging.error(stdout)
        logging.error(stderr)


def _cluster_load(kubeconfig, my_path, hosted_cluster_name, load_duration, jobs, es_url, mgmt_cluster_name):
    myenv = os.environ.copy()
    myenv["KUBECONFIG"] = kubeconfig
    logging.info('Getting kubeconfig for hosted cluster %s' % hosted_cluster_name)
    kubeconfig_hosted = ["oc", "get", "secret", hosted_cluster_name + "-admin-kubeconfig", "-o", "json", "-n", "clusters"]
    logging.debug(kubeconfig_hosted)
    kubeconfig_hosted_process = subprocess.Popen(kubeconfig_hosted, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=myenv)
    kubeconfig_hosted_stdout, kubeconfig_hosted_stderr = kubeconfig_hosted_process.communicate()
    kubeconfig_hosted_content = base64.b64decode(json.loads(kubeconfig_hosted_stdout)['data']['kubeconfig']).decode('ascii')
    try:
        logging.debug('Saving kubeconfig file of %s to the working directory' % hosted_cluster_name)
        seed_file = open(my_path + "/" + hosted_cluster_name + "/kubeconfig", 'x')
        seed_file.write(kubeconfig_hosted_content)
        seed_file.close()
    except Exception as err:
        logging.debug('Cannot write file %s/%s/kubeconfig' % (my_path, hosted_cluster_name))
        logging.error(err)
        return 1
    load_env = os.environ.copy()
    load_env["KUBECONFIG"] = my_path + "/" + hosted_cluster_name + "/kubeconfig"
    logging.info('Cloning e2e-benchmarking repo https://github.com/cloud-bulldozer/e2e-benchmarking.git')
    Repo.clone_from("https://github.com/cloud-bulldozer/e2e-benchmarking.git", my_path + "/" + hosted_cluster_name + '/e2e-benchmarking')
    os.chdir(my_path + "/" + hosted_cluster_name + '/e2e-benchmarking/workloads/kube-burner')
    load_env["JOB_ITERATIONS"] = str(jobs)
    load_env["CHURN"] = "true"
    load_env["CHURN_DURATION"] = load_duration
    load_env["CHURN_PERCENT"] = "10"
    load_env["CHURN_WAIT"] = "30s"
    load_env["JOB_TIMEOUT"] = "6h"
    load_env["CLEANUP_WHEN_FINISH"] = "true"
    load_env["INDEXING"] = "true"
    load_env["HYPERSHIFT"] = "true"
    load_env["MGMT_CLUSTER_NAME"] = mgmt_cluster_name
    load_env["HOSTED_CLUSTER_NS"] = "clusters-" + hosted_cluster_name
    if es_url is not None:
        load_env["ES_SERVER"] = es_url
    load_env["PROM_URL"] = "https://thanos-query.apps.observability.perfscale.devcluster.openshift.com"
    load_env["THANOS_RECEIVER_URL"] = "http://thanos.apps.observability.perfscale.devcluster.openshift.com/api/v1/receive"
    load_env["LOG_LEVEL"] = "debug"
    load_env["WORKLOAD"] = "cluster-density-ms"
    load_env["KUBE_DIR"] = my_path + "/" + hosted_cluster_name
    load_command = ["./run.sh"]
    logging.debug(load_command)
    load_log = open(my_path + "/" + hosted_cluster_name + '/cluster_load.log', 'w')
    load_process = subprocess.Popen(load_command, stdout=load_log, stderr=load_log, env=load_env)
    load_process_stdout, load_process_stderr = load_process.communicate()


def get_metadata(kubeconfig, my_path, duration, cluster_name, uuid, operation):
    myenv = os.environ.copy()
    myenv["KUBECONFIG"] = kubeconfig
    metadata = {}
    logging.info('Getting information for hosted cluster %s' % cluster_name)
    metadata_hosted = ["oc", "get", "hostedcluster", "-n", "clusters", cluster_name, "-o", "json"]
    logging.debug(metadata_hosted)
    metadata_hosted_process = subprocess.Popen(metadata_hosted, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=myenv)
    metadata_hosted_stdout, metadata_hosted_stderr = metadata_hosted_process.communicate()
    try:
        metadata_hosted_info = json.loads(metadata_hosted_stdout)
        metadata["cluster_name"] = metadata_hosted_info['metadata']['name']
        metadata["network_type"] = metadata_hosted_info['spec']['networking']['networkType']
        metadata["control_plane_topology"] = metadata_hosted_info['spec']['controllerAvailabilityPolicy']
        metadata["infrastructure_topology"] = metadata_hosted_info['spec']['infrastructureAvailabilityPolicy']
        metadata["status"] = metadata_hosted_info['status']['version']['history'][0]['state']
        metadata["version"] = metadata_hosted_info['status']['version']['history'][0]['version']
    except Exception as err:
        logging.error("Cannot load metadata for cluster %s" % cluster_name)
        logging.error(err)
    metadata["duration"] = duration
    metadata["operation"] = operation
    metadata["uuid"] = uuid
    return metadata


def _watcher(kubeconfig_location, cluster_name_seed, cluster_count, delay, my_uuid, clusters_resume, all_clusters_installed):
    myenv = os.environ.copy()
    myenv["KUBECONFIG"] = kubeconfig_location
    time.sleep(60)
    logging.info('Watcher thread started')
    logging.info('Getting status every %d seconds' % int(delay))
    # We need to determine somewhere the number of clusters to show
    cmd = ["oc", "get", "hostedclusters", "-n", "clusters", "-o", "json"]
    # To stop the watcher we expect the run attribute to be not True
    while True:
        logging.debug(cmd)
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=myenv)
        stdout, stderr = process.communicate()
        installing_clusters = 0
        installed_clusters = 0
        other_clusters = 0
        other_list = []
        try:
            clusters = json.loads(stdout)['items']
        except ValueError as err:
            logging.error("Failed to get hosted clusters list: %s" % err)
            logging.error(stdout)
            logging.error(stderr)
            clusters = {}
        for cluster in clusters:
            if 'metadata' in cluster and 'name' in cluster['metadata'] and cluster_name_seed in cluster['metadata']['name']:
                status = cluster['status']['version']['history'][0] if 'status' in cluster and 'version' in cluster['status'] and 'history' in cluster['status']['version'] and len(cluster['status']['version']['history'][0]) > 0 else {}
                if 'state' in status and status['state'] == 'Completed':
                    installed_clusters += 1
                elif 'state' in status and status['state'] == 'Partial':
                    installing_clusters += 1
                else:
                    other_clusters += 1
                    other_list.append(cluster['metadata']['name'])
        logging.info('Requested Clusters for test %s: %d of %d' % (my_uuid, installing_clusters + installed_clusters + other_clusters, cluster_count))
        logging.info('   Installing: %d' % installing_clusters)
        logging.info('   Ready: %d' % installed_clusters)
        logging.info('   Other: %d (%s)' % (other_clusters, other_list))
        if installed_clusters == cluster_count:
            with all_clusters_installed:
                logging.info('All requested clusters on ready status, notifying threads to start e2e-benchmarking processes')
                all_clusters_installed.notify_all()
            break
        elif installed_clusters + other_clusters == cluster_count and installing_clusters == 0:
            logging.error('No cluster pending to install and not all clusters are ready. Exiting...')
            exit(1)
        else:
            logging.info("Waiting %d seconds for next watcher run" % delay)
            time.sleep(delay)
    logging.info('Watcher exiting')


def _cleanup_cluster(hypershift_cmnd, kubeconfig, mgmt_cluster_name, cluster_name, my_path, aws_region, my_uuid, es, index, index_retry):
    myenv = os.environ.copy()
    myenv["KUBECONFIG"] = kubeconfig
    cluster_path = my_path + "/" + cluster_name
    metadata = get_metadata(kubeconfig, cluster_path, 0, cluster_name, my_uuid, "destroy")
    logging.debug('Destroying cluster name: %s' % cluster_name)
    del_cmd = [hypershift_cmnd, "destroy", "cluster", "aws", "--name", cluster_name, "--aws-creds", my_path + "/aws_creds", "--region", aws_region]
    logging.debug(del_cmd)
    cleanup_log = open(cluster_path + '/cleanup.log', 'w')
    cluster_start_time = int(time.time())
    process = subprocess.Popen(del_cmd, stdout=cleanup_log, stderr=cleanup_log, env=myenv)
    stdout, stderr = process.communicate()
    cluster_end_time = int(time.time())
    metadata['mgmt_cluster_name'] = mgmt_cluster_name
    metadata['duration'] = cluster_end_time - cluster_start_time
    metadata['job_iterations'] = ""
    metadata['load_duration'] = ""
    metadata['workers'] = ""
    if process.returncode != 0:
        logging.error('Hosted cluster destroy failed for cluster name %s with this stdout/stderr:' % cluster_name)
        logging.error(stdout)
        logging.error(stderr)
        return 1
    try:
        with open(my_path + "/" + cluster_name + "/metadata_destroy.json", "w") as metadata_file:
            json.dump(metadata, metadata_file)
    except Exception as err:
        logging.error(err)
        logging.error('Failed to write metadata_destroy.json file located %s' % cluster_path)
    if es is not None:
        # metadata["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        metadata["timestamp"] = datetime.datetime.utcnow().isoformat()
        es_ignored_metadata = ""
        common._index_result(es, index, metadata, es_ignored_metadata, index_retry)


def main():
    parser = argparse.ArgumentParser(description="hypershift wrapper script",
                                     parents=[parentParsers.esParser,
                                              parentParsers.runnerParser,
                                              parentParsers.clusterParser,
                                              parentParsers.logParser])
    parser.add_argument(
        '--aws-account-file',
        type=str,
        required=True,
        help='AWS account file to use')
    parser.add_argument(
        '--aws-profile',
        type=str,
        help='AWS profile to use if more than one are present on aws config file')
    parser.add_argument(
        '--ocm-token',
        type=str,
        required=True,
        help='Token for accessing OCM')
    parser.add_argument(
        '--pull-secret-file',
        type=str,
        required=True,
        help='File containing a valid OCP4 pull secret')
    parser.add_argument(
        '--mgmt-cluster',
        type=str,
        help='Cluster Name or ID of the Hypershift Management Cluster')
    parser.add_argument(
        '--mgmt-kubeconfig',
        type=str,
        help='Hypershift Management Cluster kubeconfig file path')
    parser.add_argument(
        '--workers',
        type=str,
        required=True,
        default='1',
        help='Number of workers for the hosted cluster. If list (comma separated), iteration over the list until reach number of clusters')
    parser.add_argument(
        '--ocm-url',
        type=str,
        help='OCM environment',
        default='https://api.stage.openshift.com')
    parser.add_argument(
        '--ocm-cli',
        type=str,
        help='Full path to the ocm cli binary. If not provided we will download it from GitHub')
    parser.add_argument(
        '--ocm-cli-version',
        type=str,
        help='When downloading from GitHub, release to download. (Default: latest, to download the most recent release)',
        default='latest')
    parser.add_argument(
        '--hypershift-cli',
        type=str,
        help='Full path to the hypershift cli binary. If not provided we will compile it from github')
    parser.add_argument(
        '--hypershift-cli-version',
        type=str,
        help='When downloading from GitHub, branch to pull. Default: main',
        default='main')
    parser.add_argument(
        '--add-cluster-load',
        action='store_true',
        help='Execute e2e script after hosted cluster is installed to load it')
    parser.add_argument(
        '--cluster-load-duration',
        type=str,
        default='4h',
        help='CHURN_DURATION parameter used on the e2e script')
    parser.add_argument(
        '--cluster-load-jobs-per-worker',
        type=int,
        default=10,
        help='Optimus number of job iterations per worker. Workload will scale it to the number of workers')
    parser.add_argument(
        '--cluster-load-job-variation',
        type=int,
        default=0,
        help='Percentage of variation of jobs to execute. Job iterations will be a number from jobs_per_worker * workers * (-X%% to +X%%)')

    global args
    args = parser.parse_args()

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
        uuid_file = open(my_path + '/uuid', 'x')
        uuid_file.write(my_uuid)
        uuid_file.close()
    except Exception as err:
        logging.debug('Cannot write file %s/uuid' % my_path)
        logging.error(err)
        exit(1)

    es = common._connect_to_es(args.es_url, args.es_insecure) if args.es_url is not None else None

    # Check if we have a valid AWS file, with correct profile and exists at least access key and secret
    if args.aws_account_file:
        if os.path.exists(args.aws_account_file):
            logging.debug('AWS Account file exists')
        else:
            logging.error('AWS Account configuration file not found at %s' % args.aws_account_file)
            exit(1)
        logging.info('AWS account file found. Loading account information')
        aws_config = configparser.RawConfigParser()
        aws_config.read(args.aws_account_file)
        if len(aws_config.sections()) == 1:
            profile = aws_config.sections()[0]
        else:
            if not args.aws_profile:
                parser.error("Multiple profiles detected on AWS credentials file but no --aws-profile parameter")
            else:
                if args.aws_profile not in aws_config.sections():
                    parser.error("--aws-profile value not detected on AWS credentials file")
                else:
                    profile = args.aws_profile
        if 'aws_access_key_id' not in aws_config[profile] or 'aws_secret_access_key' not in aws_config[profile]:
            parser.error("Missing keys for profile on AWS credentials file")
        else:
            logging.info('AWS configuration verified for profile %s on file %s' % (profile, args.aws_account_file))
            write_config = configparser.RawConfigParser()
            write_config[profile] = {}
            write_config[profile]['aws_access_key_id'] = aws_config[profile]['aws_access_key_id']
            write_config[profile]['aws_secret_access_key'] = aws_config[profile]['aws_secret_access_key']
            with open(my_path + '/aws_creds', 'w') as configfile:
                write_config.write(configfile)
                logging.info('AWS creds for profile %s saved on %s' % (profile, my_path + '/aws_creds'))
    else:
        parser.error("argument '--aws-account-file' is required")

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

    ocm_cmnd, hypershift_cmnd = _verify_cmnds(args.ocm_cli, args.hypershift_cli, my_path, args.ocm_cli_version, args.hypershift_cli_version)

    logging.info('Attempting to log in OCM using `ocm login`')
    ocm_login_command = [ocm_cmnd, "login", "--url=" + args.ocm_url, "--token=" + args.ocm_token]
    logging.debug(ocm_login_command)
    ocm_login_process = subprocess.Popen(ocm_login_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ocm_login_stdout, ocm_login_stderr = ocm_login_process.communicate()
    if ocm_login_process.returncode != 0:
        logging.error('%s unable to execute `ocm login`' % ocm_cmnd)
        logging.error(ocm_login_stderr.strip().decode("utf-8"))
        exit(1)
    else:
        logging.info('`ocm login` execution OK')
        logging.debug(ocm_login_stdout.strip().decode("utf-8"))

    try:
        with open(args.pull_secret_file, "r") as pull_secret_file:
            json.load(pull_secret_file)
            logging.info('%s is a valid json file' % args.pull_secret_file)
    except Exception as err:
        logging.error(err)
        logging.error('Failed to read pull secret file %s' % args.pull_secret_file)
        exit(1)

    mgmt_metadata = _get_mgmt_cluster_info(ocm_cmnd, args.mgmt_cluster, es, args.es_index, args.es_index_retry, my_uuid, args.cluster_count)

    if 'cluster_id' not in mgmt_metadata or 'base_domain' not in mgmt_metadata or 'aws_region' not in mgmt_metadata:
        logging.error('Failed to obtain Management Cluster information from %s' % args.mgmt_cluster)
        exit(1)
    else:
        logging.debug('Management Cluster information for %s:' % mgmt_metadata['cluster_name'])
        logging.debug('             Custer ID:   %s' % mgmt_metadata['cluster_id'])
        logging.debug('             Base Domain: %s' % mgmt_metadata['base_domain'])
        logging.debug('             AWS Zone:    %s' % mgmt_metadata['aws_region'])

    # Get connected to management cluster
    if args.mgmt_kubeconfig:
        mgmt_kubeconfig_path = args.mgmt_kubeconfig
    elif args.mgmt_cluster:
        logging.debug('Downloading kubeconfig for Management Cluster %s:' % args.mgmt_cluster)
        mgmt_kubeconfig_path = _download_kubeconfig(ocm_cmnd, mgmt_metadata['cluster_id'], my_path)
        if not os.path.exists(mgmt_kubeconfig_path):
            logging.error('Management Cluster kubeconfig not found %s' % mgmt_kubeconfig_path)
            exit(1)
        else:
            mgmt_env = os.environ.copy()
            mgmt_env["KUBECONFIG"] = mgmt_kubeconfig_path
            # Check if hosted cluster CRD is installed
            logging.info('Checking if hosted cluster CRD is installed on Management Cluster...')
            oc_cmd = ["oc", "get", "crd", "hostedclusters.hypershift.openshift.io"]
            logging.debug(oc_cmd)
            oc_process = subprocess.Popen(oc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=mgmt_env)
            oc_stdout, oc_stderr = oc_process.communicate()
            if oc_process.returncode != 0:
                logging.error('%s Hosted clusters CRD is not installed on %s' % mgmt_metadata['cluster_name'])
            else:
                logging.info('Hosted clusters CRD installed')
    else:
        parser.error("Any of --mgmt-cluster or --mgmt-kubeconfig are required.")
        exit(1)

    # launch watcher thread to report status
    logging.info('Launching watcher thread')
    clusters_resume = {}
    all_clusters_installed = threading.Condition()
    watcher = threading.Thread(target=_watcher, args=(mgmt_kubeconfig_path, cluster_name_seed, args.cluster_count, args.watcher_delay, my_uuid, clusters_resume, all_clusters_installed))
    watcher.daemon = True
    watcher.start()

    logging.info('Attempting to start %d clusters with %d batch size' % (args.cluster_count, args.batch_size))
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
                pattern = re.compile(r"^(\d+)(,\s*\d+)*$")
                if args.workers.isdigit():
                    workers = args.workers
                elif bool(pattern.match(args.workers)):
                    workers = int(args.workers.split(",")[(loop_counter - 1) % len(args.workers.split(","))])
                    if args.add_cluster_load:
                        low_jobs = int((args.cluster_load_jobs_per_worker * workers) - (float(args.cluster_load_job_variation) * float(args.cluster_load_jobs_per_worker * workers) / 100))
                        high_jobs = int((args.cluster_load_jobs_per_worker * workers) + (float(args.cluster_load_job_variation) * float(args.cluster_load_jobs_per_worker * workers) / 100))
                        jobs = random.randint(low_jobs, high_jobs)
                        logging.debug("Selected jobs: %d" % jobs)
                    else:
                        jobs = 0
                else:
                    logging.error("Invalid value for parameter --workers %s. Setting workers to 0" % args.workers)
                    workers = 0
                    jobs = 0
                try:
                    thread = threading.Thread(target=_build_cluster, args=(hypershift_cmnd, mgmt_kubeconfig_path, cluster_name_seed, mgmt_metadata['base_domain'], args.add_cluster_load, args.cluster_load_duration, jobs, workers, mgmt_metadata['aws_region'], args.pull_secret_file, my_path, my_uuid, loop_counter, es, args.es_url, args.es_index, args.es_index_retry, mgmt_metadata["cluster_name"], all_clusters_installed))
                except Exception as err:
                    logging.error(err)
                cluster_thread_list.append(thread)
                thread.start()
                logging.debug('Number of alive threads %d' % threading.active_count())

    except Exception as err:
        logging.error(err)
        logging.error('Thread creation failed')

    logging.info('All clusters (%d) requested. Waiting for installations to finish' % len(cluster_thread_list))
    watcher.join()

    # Wait for active threads to finish
    logging.info('Waiting for  all threads (%d) to finish' % len(cluster_thread_list))
    for t in cluster_thread_list:
        try:
            t.join()
        except RuntimeError as err:
            if 'cannot join current thread' in err.args[0]:
                # catchs main thread
                continue
            else:
                raise

    if args.cleanup_clusters:
        logging.info('Attempting to delete all hosted clusters with seed %s' % (cluster_name_seed))
        delete_cluster_thread_list = []
        cleanup_env = os.environ.copy()
        cleanup_env["KUBECONFIG"] = mgmt_kubeconfig_path
        cmd = ["oc", "get", "hostedclusters", "-n", "clusters"]
        logging.debug(cmd)
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=cleanup_env)
        stdout, stderr = process.communicate()
        for line in stdout.splitlines():
            if cluster_name_seed in line.split()[0]:
                logging.debug('Starting Hosted cluster cleanup %s' % line.split()[0])
                try:
                    thread = threading.Thread(target=_cleanup_cluster, args=(hypershift_cmnd, mgmt_kubeconfig_path, mgmt_metadata["cluster_name"], line.split()[0], my_path, mgmt_metadata['aws_region'], my_uuid, es, args.es_index, args.es_index_retry))
                except Exception as err:
                    logging.error('Thread creation failed')
                    logging.error(err)
                delete_cluster_thread_list.append(thread)
                thread.start()
                logging.debug('Number of alive threads %d' % threading.active_count())

        # Wait for active threads to finish
        logging.info('All clusters (%d) requested to be deleted. Waiting for them to finish' % len(delete_cluster_thread_list))
        for t in delete_cluster_thread_list:
            try:
                t.join()
            except RuntimeError as err:
                if 'cannot join current thread' in err.args[0]:
                    # catchs main thread
                    continue
                else:
                    raise

    if args.cleanup:
        logging.info('Cleaning working directory %s' % my_path)
        shutil.rmtree(my_path)

# Last, output test result
    logging.info('************************************************************************')
    logging.info('********* Summary for test %s *********' % (my_uuid))
    logging.info('************************************************************************')
    logging.info('Requested Clusters for test %s: %d' % (my_uuid, args.cluster_count))
    if 'clusters_created' in clusters_resume:
        logging.info('Created   Clusters for test %s: %d' % (my_uuid, clusters_resume['clusters_created']))
        if 'state' in clusters_resume:
            for i1 in clusters_resume['state'].items():
                logging.info('              %s: %s' % (str(i1[0]), str(i1[1])))
    else:
        logging.info('Created   Clusters for test %s: 0' % (my_uuid))
    logging.info('Batches size: %s' % (str(args.batch_size)))
    logging.info('Delay between batches: %s' % (str(args.delay_between_batch)))
    logging.info('Cluster Name Seed: %s' % (cluster_name_seed))


if __name__ == '__main__':
    sys.exit(main())
