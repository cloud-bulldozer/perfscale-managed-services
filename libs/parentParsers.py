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
from . import common


esParser = argparse.ArgumentParser(add_help=False)
esParser.add_argument(
    '--es-url',
    help='Provide ES connection URL')
esParser.add_argument(
    '--es-insecure',
    dest='es_insecure',
    action='store_true',
    help='if ES is setup with ssl, but can disable tls cert verification')
esParser.add_argument(
    '--es-index',
    help='The index to write to',
    default='osde2e-install-timings')
esParser.add_argument(
    '--es-index-retry',
    help='Number of retries (default: 5) on ES uploading. The time between retries increases exponentially',
    default=5,
    type=int)
esParser.add_argument(
    '--es-index-only',
    dest='es_index_only',
    action='store_true',
    help='Do not install any new cluster, just upload to ES all metadata files found on PATH')
esParser.add_argument(
    '--es-ignored-metadata',
    dest='es_ignored_metadata',
    default=common._es_ignored_metadata,
    help='List of coma separated keys to ignore from the metadata file.')
esParser.add_argument(
    '--uuid',
    help='UUID to provide to ES')

runnerParser = argparse.ArgumentParser(add_help=False)
runnerParser.add_argument(
    '--path',
    help='Path to save temporary data')
runnerParser.add_argument(
    '--cleanup',
    help='Should we delete the temporary directory',
    dest='cleanup',
    action='store_true')
runnerParser.add_argument(
    '--delay-between-batch',
    type=int,
    help='If set it will wait x seconds between each batch request')
runnerParser.add_argument(
    '--batch-size',
    default=0,
    type=int,
    help='number of clusters in a batch')
runnerParser.add_argument(
    '--watcher-delay',
    default=60,
    type=int,
    help='Delay between each status check')

clusterParser = argparse.ArgumentParser(add_help=False)
clusterParser.add_argument(
    '--cluster-name-seed',
    type=str,
    default='perfsc',
    help='Seed used to generate cluster names. 6 chars max')
clusterParser.add_argument(
    '--cluster-count',
    default=1,
    type=int,
    help='Total number of clusters to create')
clusterParser.add_argument(
    '--expire',
    type=int,
    help='Minutes until cluster expires and it is deleted by OSD')
clusterParser.add_argument(
    '--cleanup-clusters',
    dest='cleanup_clusters',
    action='store_true',
    help='Cleanup any non-error state clusters upon test completion')
clusterParser.add_argument(
    '--only-delete-clusters',
    dest='only_delete_clusters',
    action='store_true',
    help="Just delete clusters found on folder specified by '--path' and exit")
clusterParser.add_argument(
    '--wildcard-options',
    type=str,
    help="Between quotes, any other parameter to be transfered to the binary without any validation")


machinepoolParser = argparse.ArgumentParser(add_help=False)
machinepoolParser.add_argument(
    '--machinepool-name',
    type=str,
    help='Add a machinepool after cluster is installed')
machinepoolParser.add_argument(
    '--machinepool-labels',
    type=str,
    default='node-role.kubernetes.io/workload=',
    help='Labels to add on the machinepool. Default: node-role.kubernetes.io/workload=')
machinepoolParser.add_argument(
    '--machinepool-taints',
    type=str,
    default='role=workload:NoSchedule',
    help='Taints to add on the machinepool. Default: role=workload:NoSchedule')
machinepoolParser.add_argument(
    '--machinepool-flavour',
    type=str,
    default='m5.xlarge',
    help='AWS flavour to use in the machinepool. Default: m5.xlarge')
machinepoolParser.add_argument(
    '--machinepool-replicas',
    type=int,
    default=2,
    help='Number of hosts to create on the machinepool. Default: 2')
machinepoolParser.add_argument(
    '--machinepool-wait',
    dest='machinepool_wait',
    action='store_true',
    help='After creating the machinepool, wait until nodes to come up')
machinepoolParser.add_argument(
    '--machinepool-wait-cycles',
    default=60,
    type=int,
    help='Number of 5 seconds wait cycles until halts the waiting')

logParser = argparse.ArgumentParser(add_help=False)
logParser.add_argument(
    '--log-file',
    help='File where to write logs')
logParser.add_argument(
    '--log-level',
    default='INFO',
    help='Log level to show')
