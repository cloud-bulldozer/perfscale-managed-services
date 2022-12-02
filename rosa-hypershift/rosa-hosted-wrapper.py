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
from random import randrange


def _verify_cmnds(ocm_cmnd, rosa_cmnd, my_path, ocm_version, rosa_version):
    if rosa_cmnd is None:
        logging.info('rosa command not provided')
        logging.info('Downloading binary rosa-linux-amd64 from https://github.com/openshift/rosa/releases/')
        tags_list = []
        try:
            tags = requests.get(url='https://api.github.com/repos/openshift/rosa/git/refs/tags')
        except requests.ConnectionError as err:
            logging.error('Cannot download tags list from https://api.github.com/repos/openshift/rosa/git/refs/tags')
            logging.error(err)
            exit(1)
        # Get all tags, sort and select the correct one
        for tag in tags.json():
            tags_list.append(tag['ref'].split('/')[-1].split('v')[-1])
        logging.debug('List of tags: %s' % tags_list)
        if rosa_version == 'latest':
            version = sorted(tags_list, key=ver.StrictVersion)[-1]
        else:
            version = None
            for tag in tags_list:
                if tag == rosa_version:
                    version = tag
            if version is None:
                version = sorted(tags_list, key=ver.StrictVersion)[-1]
                logging.error('Invalid ROSA release %s, downloading latest release identified as %s' % (rosa_version, version))
        logging.info('Downloading ROSA release identified as %s' % version)
        try:
            url = 'https://github.com/openshift/rosa/releases/download/v' + version + '/rosa-linux-amd64'
            logging.debug('Downloading from %s' % url)
            with urllib.request.urlopen(url) as response, open(my_path + '/rosa', 'wb') as out_file:
                shutil.copyfileobj(response, out_file)
            os.chmod(my_path + '/rosa', 0o777)
            rosa_cmnd = my_path + "/rosa"
        except urllib.error.HTTPError as err:
            logging.error('Failed to download valid version %s from GitHub: %s' % (version, err))
            exit(1)
    logging.info('Testing rosa command with: rosa -h')
    rosa_cmd = [rosa_cmnd, "-h"]
    rosa_process = subprocess.Popen(rosa_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rosa_stdout, rosa_stderr = rosa_process.communicate()
    if rosa_process.returncode != 0:
        logging.error('%s unable to execute -h' % rosa_cmnd)
        logging.error(rosa_stderr.strip().decode("utf-8"))
        exit(1)
    logging.info('rosa command validated with -h. Directory is %s' % my_path)
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
        logging.info('Downloading OCM release identified as %s' % version)
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
    return (ocm_cmnd, rosa_cmnd)


def _get_provision_shard(ocm_cmnd, cluster_name, aws_region):
    logging.info('Searching for Provision Shard of Management Cluster %s installed on %s AWS region' % (cluster_name, aws_region))
    ocm_command = [ocm_cmnd, "get", "/api/clusters_mgmt/v1/provision_shards?search=region.id+is+%27" + aws_region + "%27+and+management_cluster+is+%27" + cluster_name + "%27"]
    logging.debug(ocm_command)
    ocm_process = subprocess.Popen(ocm_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ocm_stdout, ocm_stderr = ocm_process.communicate()
    if ocm_process.returncode != 0:
        logging.error('%s unable to execute ' % ocm_command)
        logging.error(ocm_stderr.strip().decode("utf-8"))
    else:
        if int(json.loads(ocm_stdout.decode("utf-8"))['total']) > 0:
            shard_list = []
            for shard in json.loads(ocm_stdout.decode("utf-8"))['items']:
                if 'status' in shard and shard['status'] in ['active', 'maintenance']:
                    shard_list.append(shard['id'])
            if len(shard_list) == 0:
                logging.error('No active provision Shard found for  Management Cluster %s installed on %s AWS region' % (cluster_name, aws_region))
                exit(1)
            elif len(shard_list) == 1:
                logging.info('Using %s Provision Shard for Management Cluster %s installed on %s AWS region' % (shard_list[0], cluster_name, aws_region))
                return shard_list[0]
            else:
                logging.info('Detected multiples Provision Shards for Management Cluster %s installed on %s AWS region, using %s' % (cluster_name, aws_region, shard_list[0]))
                logging.debug(shard_list)
                return shard_list[0]
        else:
            logging.error('Provision Shard not found for  Management Cluster %s installed on %s AWS region' % (cluster_name, aws_region))
            exit(1)


def _get_mgmt_cluster_info(ocm_cmnd, mgmt_cluster, org_id, aws_region, es, index, index_retry, uuid, hostedclusters):
    logging.info('Searching for Management Clusters on Org %s installed on %s AWS region' % (org_id, aws_region))
    ocm_command = [ocm_cmnd, "get", "/api/clusters_mgmt/v1/clusters?search=organization.id+is+%27" + org_id + "%27+and+region.id+is+%27" + aws_region + "%27"]
    logging.debug(ocm_command)
    ocm_process = subprocess.Popen(ocm_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ocm_stdout, ocm_stderr = ocm_process.communicate()
    metadata = {}
    if ocm_process.returncode != 0:
        logging.error('%s unable to execute ' % ocm_command)
        logging.error(ocm_stderr.strip().decode("utf-8"))
    else:
        for cluster in json.loads(ocm_stdout.decode("utf-8"))['items']:
            if cluster['id'] == mgmt_cluster or cluster['name'] == mgmt_cluster:
                metadata['uuid'] = uuid
                metadata['cluster_name'] = cluster['name']
                metadata['infra_id'] = cluster['infra_id']
                metadata['cluster_id'] = cluster['id']
                metadata['version'] = cluster['openshift_version']
                metadata['base_domain'] = cluster['dns']['base_domain']
                metadata['aws_region'] = cluster['region']['id']
                if 'compute' in cluster['nodes']:
                    metadata['workers'] = cluster['nodes']['compute']
                else:  # when autoscaling enabled
                    metadata['workers'] = cluster['nodes']['autoscale_compute']['min_replicas']
                    metadata['workers_min'] = cluster['nodes']['autoscale_compute']['min_replicas']
                    metadata['workers_max'] = cluster['nodes']['autoscale_compute']['max_replicas']
                metadata['workers_type'] = cluster['nodes']['compute_machine_type']['id']
                metadata['network_type'] = cluster['network']['type']
                metadata["timestamp"] = datetime.datetime.utcnow().isoformat()
                metadata['hostedclusters'] = hostedclusters
                metadata['install_method'] = "rosa"
                metadata['provision_shard'] = _get_provision_shard(ocm_cmnd, metadata['cluster_name'], aws_region)
                es_ignored_metadata = ""
                if es is not None:
                    common._index_result(es, index, metadata, es_ignored_metadata, index_retry)
        if metadata == {}:
            logging.error("Management Cluster %s not found for Org %s on %s AWS region" % (mgmt_cluster, org_id, aws_region))
            exit(1)
    return metadata


def _download_kubeconfig(ocm_cmnd, cluster_id, my_path):
    logging.debug('Downloading kubeconfig file for Cluster %s on %s' % (cluster_id, my_path))
    kubeconfig_cmd = [ocm_cmnd, "get", "/api/clusters_mgmt/v1/clusters/" + cluster_id + "/credentials"]
    logging.debug(kubeconfig_cmd)
    process = subprocess.Popen(kubeconfig_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=my_path, universal_newlines=True)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        logging.error('Failed to download kubeconfig file for Cluster ID %s with this stdout/stderr:' % cluster_id)
        logging.error(stdout)
        logging.error(stderr)
        return ""
    else:
        kubeconfig_path = my_path + "/kubeconfig"
        with open(kubeconfig_path, "w") as kubeconfig_file:
            kubeconfig_file.write(json.loads(stdout)['kubeconfig'])
        logging.debug('Downloaded kubeconfig file for Cluster ID %s and stored at %s' % (cluster_id, kubeconfig_path))
        return kubeconfig_path


def _build_cluster(ocm_cmnd, rosa_cmnd, cluster_name_seed, must_gather_all, mgmt_cluster_name, provision_shard, wait_time, cluster_load, load_duration, job_iterations, worker_nodes, my_path, my_uuid, my_inc, es, es_url, index, index_retry, all_clusters_installed):
    # pass that dir as the cwd to subproccess
    cluster_path = my_path + "/" + cluster_name_seed + "-" + str(my_inc).zfill(4)
    os.mkdir(cluster_path)
    logging.debug('Attempting cluster installation')
    logging.debug('Output directory set to %s' % cluster_path)
    cluster_name = cluster_name_seed + "-" + str(my_inc).zfill(4)
    cluster_cmd = [rosa_cmnd, "create", "cluster", "--cluster-name", cluster_name, "--replicas", str(worker_nodes), "--hosted-cp", "--sts", "--mode", "auto", "-y"]
    if provision_shard:
        cluster_cmd.append("--properties")
        cluster_cmd.append("provision_shard_id:" + provision_shard)
    if args.wildcard_options:
        for param in args.wildcard_options.split():
            cluster_cmd.append(param)
    logging.debug(cluster_cmd)
    installation_log = open(cluster_path + "/" + 'installation.log', 'w')
    cluster_start_time = int(time.time())
    process = subprocess.Popen(cluster_cmd, stdout=installation_log, stderr=installation_log)
    logging.info('Started cluster %d with %d workers' % (my_inc, worker_nodes))
    stdout, stderr = process.communicate()
    metadata = {}
    if process.returncode == 0:
        watch_cmd = [rosa_cmnd, "logs", "install", "-c", cluster_name, "--watch"]
        logging.debug(watch_cmd)
        watch_process = subprocess.Popen(watch_cmd, stdout=installation_log, stderr=installation_log)
        watch_stdout, watch_stderr = watch_process.communicate()
        cluster_end_time = int(time.time())
        metadata = get_metadata(cluster_name, rosa_cmnd)
        kubeconfig = _download_kubeconfig(ocm_cmnd, metadata['cluster_id'], cluster_path)
        if cluster_load and kubeconfig == "":
            logging.error("Failed to download kubeconfig file. Disabling e2e-benchmarking execution on %s" % cluster_name)
            cluster_load = False
            metadata['status'] = "Ready. Not Access"
        workers_ready = _wait_for_workers(kubeconfig, worker_nodes, wait_time, cluster_name)
        if cluster_load and workers_ready != worker_nodes:
            logging.error("Insufficient number of workers (%d). Expected: %d. Disabling e2e-benchmarking execution on %s" % (workers_ready, worker_nodes, cluster_name))
            cluster_load = False
            metadata['status'] = "Ready. No Workers"
        cluster_workers_ready = int(time.time())
        metadata['workers_ready'] = cluster_workers_ready - cluster_start_time if workers_ready == worker_nodes else ""
    else:
        cluster_end_time = int(time.time())
        logging.error("Failed to install cluster %s" % cluster_name)
        logging.debug(stdout)
        logging.debug(stderr)
        metadata['status'] = "Not Ready"
    metadata['mgmt_cluster_name'] = mgmt_cluster_name
    metadata['duration'] = cluster_end_time - cluster_start_time
    metadata['job_iterations'] = str(job_iterations) if cluster_load else 0
    metadata['load_duration'] = load_duration if cluster_load else ""
    metadata['workers'] = str(worker_nodes)
    metadata['uuid'] = my_uuid
    metadata['operation'] = "install"
    metadata['install_method'] = "rosa"
    try:
        with open(cluster_path + "/metadata_install.json", "w") as metadata_file:
            json.dump(metadata, metadata_file)
    except Exception as err:
        logging.error(err)
        logging.error('Failed to write metadata_install.json file located %s' % cluster_path)
    if es is not None:
        metadata["timestamp"] = datetime.datetime.utcnow().isoformat()
        es_ignored_metadata = ""
        common._index_result(es, index, metadata, es_ignored_metadata, index_retry)
    if cluster_load:
        with all_clusters_installed:
            logging.info('Waiting for all clusters to be installed to start e2e-benchmarking execution on %s' % cluster_name)
            all_clusters_installed.wait()
        logging.info('Executing e2e-benchmarking to add load on the cluster %s with %s nodes during %s with %d iterations' % (cluster_name, str(worker_nodes), load_duration, job_iterations))
        _cluster_load(kubeconfig, cluster_path, cluster_name, mgmt_cluster_name, load_duration, job_iterations, es_url)
        logging.info('Finished execution of e2e-benchmarking workload on %s' % cluster_name)
    if must_gather_all or process.returncode != 0:
        random_sleep = random.randint(60, 300)
        logging.info("Waiting %d seconds before dumping hosted cluster must-gather" % random_sleep)
        time.sleep(random_sleep)
        logging.info("Saving must-gather file of hosted cluster %s" % cluster_name)
        _get_must_gather(cluster_path, cluster_name)


def _get_workers_ready(kubeconfig, cluster_name):
    myenv = os.environ.copy()
    myenv["KUBECONFIG"] = kubeconfig
    logging.info('Getting node information for cluster %s' % cluster_name)
    nodes_command = ["oc", "get", "nodes", "-o", "json"]
    logging.debug(nodes_command)
    nodes_process = subprocess.Popen(nodes_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=myenv)
    nodes_stdout, nodes_stderr = nodes_process.communicate()
    try:
        nodes_json = json.loads(nodes_stdout)
    except Exception as err:
        logging.error("Cannot load command result for cluster %s" % cluster_name)
        logging.error(err)
        return 0
    nodes = nodes_json['items'] if 'items' in nodes_json else []
    status = []
    for node in nodes:
        conditions = node['status']['conditions'] if 'status' in node and 'conditions' in node['status'] else []
        for condition in conditions:
            if 'type' in condition and condition['type'] == 'Ready':
                status.append(condition['status'])
    status_list = {i: status.count(i) for i in status}
    ready_nodes = status_list['True'] if 'True' in status_list else 0
    return ready_nodes


def _wait_for_workers(kubeconfig, worker_nodes, wait_time, cluster_name):
    myenv = os.environ.copy()
    myenv["KUBECONFIG"] = kubeconfig
    starting_time = datetime.datetime.utcnow().timestamp()
    logging.debug("Waiting %d minutes for nodes to be Ready on cluster %s" % (wait_time, cluster_name))
    while datetime.datetime.utcnow().timestamp() < starting_time + wait_time * 60:
        logging.info('Getting node information for cluster %s' % cluster_name)
        nodes_command = ["oc", "get", "nodes", "-o", "json"]
        logging.debug(nodes_command)
        nodes_process = subprocess.Popen(nodes_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=myenv)
        nodes_stdout, nodes_stderr = nodes_process.communicate()
        try:
            nodes_json = json.loads(nodes_stdout)
        except Exception as err:
            logging.error("Cannot load command result for cluster %s" % cluster_name)
            logging.error(err)
            continue
        nodes = nodes_json['items'] if 'items' in nodes_json else []
        status = []
        for node in nodes:
            conditions = node['status']['conditions'] if 'status' in node and 'conditions' in node['status'] else []
            for condition in conditions:
                if 'type' in condition and condition['type'] == 'Ready':
                    status.append(condition['status'])
        status_list = {i: status.count(i) for i in status}
        ready_nodes = status_list['True'] if 'True' in status_list else 0
        if ready_nodes == worker_nodes:
            logging.info("Found %d Ready nodes on cluster %s. Expected: %d. Stopping wait." % (ready_nodes, cluster_name, worker_nodes))
            return ready_nodes
        else:
            logging.info("Found %d Ready nodes on cluster %s. Expected: %d. Waiting 15 seconds for next check..." % (ready_nodes, cluster_name, worker_nodes))
            time.sleep(15)
    logging.error("Waiting time expired. After %d minutes there are %d ready nodes (Expected: %d) on cluster %s" % (wait_time, ready_nodes, worker_nodes, cluster_name))
    return ready_nodes


def _cluster_load(kubeconfig, my_path, hosted_cluster_name, mgmt_cluster_name, load_duration, jobs, es_url):
    load_env = os.environ.copy()
    load_env["KUBECONFIG"] = kubeconfig
    logging.info('Cloning e2e-benchmarking repo https://github.com/cloud-bulldozer/e2e-benchmarking.git')
    Repo.clone_from("https://github.com/cloud-bulldozer/e2e-benchmarking.git", my_path + '/e2e-benchmarking')
    os.chdir(my_path + '/e2e-benchmarking/workloads/kube-burner')
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
    load_env["HOSTED_CLUSTER_NS"] = ".*-" + hosted_cluster_name
    if es_url is not None:
        load_env["ES_SERVER"] = es_url
    load_env["PROM_URL"] = "https://thanos-query.apps.observability.perfscale.devcluster.openshift.com"
    load_env["THANOS_RECEIVER_URL"] = "http://thanos.apps.observability.perfscale.devcluster.openshift.com/api/v1/receive"
    load_env["LOG_LEVEL"] = "debug"
    load_env["WORKLOAD"] = "cluster-density-ms"
    load_env["JOB_PAUSE"] = str(randrange(100, 1000)) + "s"
    load_env["KUBE_DIR"] = my_path
    load_command = ["./run.sh"]
    logging.debug(load_command)
    load_log = open(my_path + '/cluster_load.log', 'w')
    load_process = subprocess.Popen(load_command, stdout=load_log, stderr=load_log, env=load_env)
    load_process_stdout, load_process_stderr = load_process.communicate()


def _get_must_gather(cluster_path, cluster_name):
    myenv = os.environ.copy()
    myenv["KUBECONFIG"] = cluster_path + "/kubeconfig"
    logging.info('Gathering facts of hosted cluster %s' % cluster_name)
    must_gather_command = ["oc", "adm", "must-gather", "--dest-dir", cluster_path + "/must_gather"]
    logging.debug(must_gather_command)
    must_gather_log = open(cluster_path + '/must_gather.log', 'w')
    must_gather_process = subprocess.Popen(must_gather_command, stdout=must_gather_log, stderr=must_gather_log, env=myenv)
    must_gather_stdout, must_gather_stderr = must_gather_process.communicate()
    if must_gather_process.returncode != 0:
        logging.error("Failed to obtain must-gather from %s" % cluster_name)
        return 1
    logging.info('Compressing must gather artifacts on %s file' % cluster_path + "/must_gather.tar.gz")
    must_gather_compress_command = ["tar", "czvf", "must_gather.tar.gz", cluster_path + "/must_gather"]
    logging.debug(must_gather_compress_command)
    must_gather_compress_process = subprocess.Popen(must_gather_compress_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=myenv)
    must_gather_compress_stdout, must_gather_compress_stderr = must_gather_compress_process.communicate()
    if must_gather_compress_process.returncode != 0:
        logging.error("Failed to compress must-gather of %s cluster from %s to %s" % (cluster_name, cluster_path + "/must_gather", cluster_path + "/must_gather.tar.gz"))
        return 1
    logging.info('Deleting non-compressed must-gather files of hosted cluster %s' % cluster_name)
    must_gather_delete_command = ["rm", "-rf", cluster_path + "/must_gather"]
    logging.debug(must_gather_delete_command)
    must_gather_delete_process = subprocess.Popen(must_gather_delete_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=myenv)
    must_gather_delete_stdout, must_gather_delete_stderr = must_gather_delete_process.communicate()
    if must_gather_delete_process.returncode != 0:
        logging.error("Failed to delete non-compressed must-gather files of hosted cluster %s" % cluster_name)
        return 1


def _get_mgmt_cluster_must_gather(kubeconfig, my_path):
    myenv = os.environ.copy()
    myenv["KUBECONFIG"] = kubeconfig
    logging.info('Gathering facts of management cluster')
    must_gather_command = ["oc", "adm", "must-gather", "--dest-dir", my_path + "/must_gather"]
    logging.debug(must_gather_command)
    must_gather_log = open(my_path + '/management_cluster_must_gather.log', 'w')
    must_gather_process = subprocess.Popen(must_gather_command, stdout=must_gather_log, stderr=must_gather_log, env=myenv)
    must_gather_stdout, must_gather_stderr = must_gather_process.communicate()
    if must_gather_process.returncode != 0:
        logging.error("Failed to obtain must-gather from Management Cluster")
        return 1
    logging.info('Compressing must gather artifacts on %s file' % (my_path + "/management_cluster_must_gather.tar.gz"))
    must_gather_compress_command = ["tar", "czvf", my_path + "/management_cluster_must_gather.tar.gz", my_path + "/must_gather"]
    logging.debug(must_gather_compress_command)
    must_gather_compress_process = subprocess.Popen(must_gather_compress_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=myenv)
    must_gather_compress_stdout, must_gather_compress_stderr = must_gather_compress_process.communicate()
    if must_gather_compress_process.returncode != 0:
        logging.error("Failed to compress must-gather of Management Cluster from %s to %s" % (my_path + "/must_gather", my_path + "must_gather.tar.gz"))
        return 1
    logging.info('Deleting non-compressed must-gather files of Management Cluster')
    must_gather_delete_command = ["rm", "-rf", my_path + "/must_gather"]
    logging.debug(must_gather_delete_command)
    must_gather_delete_process = subprocess.Popen(must_gather_delete_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=myenv)
    must_gather_delete_stdout, must_gather_delete_stderr = must_gather_delete_process.communicate()
    if must_gather_delete_process.returncode != 0:
        logging.error("Failed to delete non-compressed must-gather files of Management Cluster")
        return 1


def get_metadata(cluster_name, rosa_cmnd):
    metadata = {}
    logging.info('Getting information for cluster %s' % cluster_name)
    metadata_hosted = [rosa_cmnd, "describe", "cluster", "-c", cluster_name, "-o", "json"]
    logging.debug(metadata_hosted)
    metadata_hosted_process = subprocess.Popen(metadata_hosted, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    metadata_hosted_stdout, metadata_hosted_stderr = metadata_hosted_process.communicate()
    try:
        metadata_hosted_info = json.loads(metadata_hosted_stdout)
        metadata["cluster_name"] = metadata_hosted_info['name']
        metadata["cluster_id"] = metadata_hosted_info['id']
        metadata["network_type"] = metadata_hosted_info['network']['type']
        metadata['workers'] = metadata_hosted_info['nodes']['compute']
        metadata["status"] = metadata_hosted_info['state']
        metadata["version"] = metadata_hosted_info['version']['raw_id']
    except Exception as err:
        logging.error("Cannot load metadata for cluster %s" % cluster_name)
        logging.error(err)
    return metadata


def _watcher(rosa_cmnd, my_path, cluster_name_seed, cluster_count, delay, my_uuid, clusters_resume, all_clusters_installed, cluster_load):
    time.sleep(60)
    logging.info('Watcher thread started')
    logging.info('Getting status every %d seconds' % int(delay))
    cmd = [rosa_cmnd, "list", "clusters", "-o", "json"]
    while True:
        logging.debug(cmd)
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()
        current_cluster_count = 0
        installed_clusters = 0
        clusters_with_all_workers = 0
        state = {}
        error = []
        try:
            clusters = json.loads(stdout)
        except ValueError as err:
            logging.error("Failed to get hosted clusters list: %s" % err)
            logging.error(stdout)
            logging.error(stderr)
            clusters = {}
        for cluster in clusters:
            if 'name' in cluster and cluster_name_seed in cluster['name']:
                current_cluster_count += 1
                state_key = cluster['state'] if 'state' in cluster else ""
                if state_key == "error":
                    error.append(cluster['name'])
                elif state_key == "ready":
                    state[state_key] = state.get(state_key, 0) + 1
                    installed_clusters += 1
                    required_workers = cluster['nodes']['compute']
                    ready_workers = _get_workers_ready(my_path + "/" + cluster['name'] + "/kubeconfig", cluster['name'])
                    if ready_workers == required_workers:
                        clusters_with_all_workers += 1
                elif state_key != "":
                    state[state_key] = state.get(state_key, 0) + 1
        logging.info('Requested Clusters for test %s: %d of %d' % (my_uuid, current_cluster_count, cluster_count))
        state_output = ""
        for i in state.items():
            state_output += "(" + str(i[0]) + ": " + str(i[1]) + ") "
            logging.info(state_output)
        if error:
            logging.warning('Clusters in error state: %s' % error)
        if installed_clusters == cluster_count:
            if cluster_load and clusters_with_all_workers == cluster_count:
                logging.info('All clusters on ready status and all clusters with all workers ready. Waiting 5 extra minutes to allow all cluster installations to arrive notify status')
                time.sleep(300)
                with all_clusters_installed:
                    logging.info('All requested clusters on ready status, notifying threads to start e2e-benchmarking processes')
                    all_clusters_installed.notify_all()
                    break
            elif not cluster_load:
                logging.info('All clusters on ready status and no loading process required. Waiting 5 extra minutes to allow all cluster installations to finish.')
                time.sleep(300)
                break
            else:
                logging.info("Waiting %d seconds for next watcher run" % delay)
                time.sleep(delay)
        else:
            logging.info("Waiting %d seconds for next watcher run" % delay)
            time.sleep(delay)
    logging.info('Watcher exiting')


def _cleanup_cluster(rosa_cmnd, cluster_name, mgmt_cluster_name, my_path, my_uuid, es, index, index_retry):
    cluster_path = my_path + "/" + cluster_name
    metadata = get_metadata(cluster_name, rosa_cmnd)
    logging.debug('Destroying cluster name: %s' % cluster_name)
    del_cmd = [rosa_cmnd, "delete", "cluster", "-c", cluster_name, "-y", "--watch"]
    logging.debug(del_cmd)
    cleanup_log = open(cluster_path + '/cleanup.log', 'w')
    cluster_start_time = int(time.time())
    process = subprocess.Popen(del_cmd, stdout=cleanup_log, stderr=cleanup_log)
    stdout, stderr = process.communicate()
    cluster_delete_end_time = int(time.time())

    logging.debug('Destroying STS associated resources of cluster name: %s' % cluster_name)
    delete_operator_roles = [rosa_cmnd, "delete", "operator-roles", "-c", cluster_name, "-m", "auto", "-y"]
    process_operator = subprocess.Popen(delete_operator_roles, stdout=cleanup_log, stderr=cleanup_log)
    stdout, stderr = process_operator.communicate()
    delete_oidc_providers = [rosa_cmnd, "delete", "oidc-provider", "-c", cluster_name, "-m", "auto", "-y"]
    process_oidc = subprocess.Popen(delete_oidc_providers, stdout=cleanup_log, stderr=cleanup_log)
    stdout, stderr = process_oidc.communicate()
    cluster_end_time = int(time.time())

    metadata['install_method'] = "rosa"
    metadata['mgmt_cluster_name'] = mgmt_cluster_name
    metadata['duration'] = cluster_delete_end_time - cluster_start_time
    metadata['all_duration'] = cluster_end_time - cluster_start_time
    metadata['job_iterations'] = ""
    metadata['load_duration'] = ""
    metadata['operation'] = "destroy"
    metadata['uuid'] = my_uuid
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
        help='AWS profile to use if more than one are present on aws config file',
        required=True)
    parser.add_argument(
        '--aws-region',
        type=str,
        help='AWS region to be used',
        default="us-east-2")
    parser.add_argument(
        '--ocm-token',
        type=str,
        required=True,
        help='Token to be used by OCM and ROSA commands')
    parser.add_argument(
        '--mgmt-cluster',
        type=str,
        help='Management Cluster name or ID')
    parser.add_argument(
        '--mgmt-org-id',
        type=str,
        help='OCM Org ID where Management Cluster is located')
    parser.add_argument(
        '--workers',
        type=str,
        required=True,
        default='2',
        help='Number of workers for the hosted cluster (min: 2). If list (comma separated), iteration over the list until reach number of clusters')
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
        '--rosa-env',
        type=str,
        help='ROSA environment (prod, staging, integration)',
        default='staging')
    parser.add_argument(
        '--rosa-cli',
        type=str,
        help='Full path to the rosa cli binary. If not provided we will download it from github')
    parser.add_argument(
        '--rosa-cli-version',
        type=str,
        help='When downloading from GitHub, release to download. (Default: latest, to download the most recent release)',
        default='latest')
    parser.add_argument(
        '--rosa-init',
        dest='rosa_init',
        action='store_true',
        help='Execute `rosa init` command to configure AWS account')
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
    parser.add_argument(
        '--workers-wait-time',
        type=int,
        default=15,
        help="Waiting time in minutes for the workers to be Ready after cluster installation. Default: 15 minutes")
    parser.add_argument(
        '--must-gather-all',
        action='store_true',
        help='If selected, collect must-gather from all cluster, if not, only collect from failed clusters')

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

    if os.path.exists(args.aws_account_file):
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
                    parser.error("profile %s especified as --aws-profile not found on AWS credentials file %s" % (args.aws_profile, args.aws_account_file))
                else:
                    profile = args.aws_profile
        if 'aws_access_key_id' not in aws_config[profile] or 'aws_secret_access_key' not in aws_config[profile]:
            parser.error("Missing keys for profile on AWS credentials file")
        else:
            logging.info('AWS configuration verified for profile %s on file %s' % (profile, args.aws_account_file))
            os.environ['AWS_PROFILE'] = profile
            os.environ['AWS_REGION'] = args.aws_region
            os.environ["AWS_ACCESS_KEY_ID"] = aws_config[profile]['aws_access_key_id']
            os.environ["AWS_SECRET_ACCESS_KEY"] = aws_config[profile]['aws_secret_access_key']
    else:
        logging.error('AWS Account configuration file not found at %s' % args.aws_account_file)
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

    ocm_cmnd, rosa_cmnd = _verify_cmnds(args.ocm_cli, args.rosa_cli, my_path, args.ocm_cli_version, args.rosa_cli_version)

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

    logging.info('Attempting to log in OCM using `rosa login`')
    rosa_login_command = [rosa_cmnd, "login", "--token", args.ocm_token, '--env', args.rosa_env]
    logging.debug(rosa_login_command)
    rosa_login_process = subprocess.Popen(rosa_login_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rosa_login_stdout, rosa_login_stderr = rosa_login_process.communicate()
    if rosa_login_process.returncode != 0:
        logging.error('%s unable to execute `rosa login`' % rosa_cmnd)
        logging.error(rosa_login_stderr.strip().decode("utf-8"))
        exit(1)
    else:
        logging.info('`rosa login` execution OK')
        logging.debug(rosa_login_stdout.strip().decode("utf-8"))

    if args.rosa_init:
        logging.info('Executing `rosa init` command to configure AWS account')
        rosa_init_command = [rosa_cmnd, "init", "--token", args.ocm_token, "--env", args.rosa_env]
        logging.debug(rosa_init_command)
        rosa_init_process = subprocess.Popen(rosa_init_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        rosa_init_stdout, rosa_init_stderr = rosa_init_process.communicate()
        if rosa_init_process.returncode != 0:
            logging.error('%s unable to execute `rosa init`' % rosa_cmnd)
            logging.error(rosa_init_stderr.strip().decode("utf-8"))
            exit(1)
        else:
            logging.info('`rosa init` execution OK')
            logging.debug(rosa_init_stdout.strip().decode("utf-8"))

    # Get connected to management cluster
    if args.mgmt_cluster:
        if args.mgmt_org_id:
            logging.info("Getting information of %s management cluster on %s organization" % (args.mgmt_cluster, args.mgmt_org_id))
            mgmt_metadata = _get_mgmt_cluster_info(ocm_cmnd, args.mgmt_cluster, args.mgmt_org_id, args.aws_region, es, args.es_index, args.es_index_retry, my_uuid, args.cluster_count)
            mgmt_kubeconfig_path = _download_kubeconfig(ocm_cmnd, mgmt_metadata['cluster_id'], my_path) if 'cluster_id' in mgmt_metadata else ""
            access_to_mgmt_cluster = True if mgmt_kubeconfig_path != "" else False
            logging.debug('Management Cluster information for %s:' % mgmt_metadata['cluster_name'])
            logging.debug('             Custer ID:   %s' % mgmt_metadata['cluster_id'])
            logging.debug('             Base Domain: %s' % mgmt_metadata['base_domain'])
            logging.debug('             AWS Zone:    %s' % mgmt_metadata['aws_region'])
            logging.debug('             Access:      %s' % str(access_to_mgmt_cluster))
        else:
            logging.error("Parameter --mgmt-org-id is required when --mgmt-cluster-name is provided")
            exit(1)
    else:
        access_to_mgmt_cluster = False

    # launch watcher thread to report status
    logging.info('Launching watcher thread')
    clusters_resume = {}
    all_clusters_installed = threading.Condition()
    watcher = threading.Thread(target=_watcher, args=(rosa_cmnd, my_path, cluster_name_seed, args.cluster_count, args.watcher_delay, my_uuid, clusters_resume, all_clusters_installed, args.add_cluster_load))
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
                if args.workers.isdigit() and int(args.workers) >= 2:
                    workers = int(args.workers)
                elif bool(pattern.match(args.workers)):
                    num = int(args.workers.split(",")[(loop_counter - 1) % len(args.workers.split(","))])
                    if num >= 2:
                        workers = num
                    else:
                        logging.error("Invalid value on workers list %s. Setting workers to 2" % num)
                        workers = 2
                else:
                    logging.error("Invalid value for parameter --workers %s. Setting workers to 2" % args.workers)
                    workers = 2
                if args.add_cluster_load:
                    low_jobs = max(0, int((args.cluster_load_jobs_per_worker * workers) - (float(args.cluster_load_job_variation) * float(args.cluster_load_jobs_per_worker * workers) / 100)))
                    high_jobs = int((args.cluster_load_jobs_per_worker * workers) + (float(args.cluster_load_job_variation) * float(args.cluster_load_jobs_per_worker * workers) / 100))
                    jobs = random.randint(low_jobs, high_jobs)
                    logging.debug("Selected jobs: %d" % jobs)
                else:
                    jobs = 0
                try:
                    thread = threading.Thread(target=_build_cluster, args=(ocm_cmnd, rosa_cmnd, cluster_name_seed, args.must_gather_all, args.mgmt_cluster, mgmt_metadata['provision_shard'], args.workers_wait_time, args.add_cluster_load, args.cluster_load_duration, jobs, workers, my_path, my_uuid, loop_counter, es, args.es_url, args.es_index, args.es_index_retry, all_clusters_installed))
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

    if access_to_mgmt_cluster:
        logging.info('Collect must-gather from Management Cluster %s' % mgmt_metadata['cluster_name'])
        _get_mgmt_cluster_must_gather(mgmt_kubeconfig_path, my_path)

    if args.cleanup_clusters:
        logging.info('Attempting to delete all hosted clusters with seed %s' % (cluster_name_seed))
        delete_cluster_thread_list = []
        cmd = [rosa_cmnd, "list", "clusters", "-o", "json"]
        logging.debug(cmd)
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()
        try:
            clusters = json.loads(stdout)
        except ValueError as err:
            logging.error("Failed to get clusters list: %s" % err)
            logging.error(stdout)
            logging.error(stderr)
            clusters = {}
        for cluster in clusters:
            if 'name' in cluster and cluster_name_seed in cluster['name']:
                logging.debug('Starting cluster cleanup %s' % cluster['name'])
                try:
                    thread = threading.Thread(target=_cleanup_cluster, args=(rosa_cmnd, cluster['name'], args.mgmt_cluster, my_path, my_uuid, es, args.es_index, args.es_index_retry))
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
