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


_parentParser = argparse.ArgumentParser(add_help=False)
_parentParser.add_argument(
    '--es-url',
    help='Provide ES connection URL')
_parentParser.add_argument(
    '--es-insecure',
    dest='es_insecure',
    action='store_true',
    help='if ES is setup with ssl, but can disable tls cert verification')
_parentParser.add_argument(
    '--es-index',
    help='The index to write to',
    default='osde2e-install-timings')
_parentParser.add_argument(
    '--es-index-retry',
    help='Number of retries (default: 5) on ES uploading. The time between retries increases exponentially',
    default=5,
    type=int)
_parentParser.add_argument(
    '--es-index-only',
    dest='es_index_only',
    action='store_true',
    help='Do not install any new cluster, just upload to ES all metadata files found on PATH')
_parentParser.add_argument(
    '--es-ignored-metadata',
    dest='es_ignored_metadata',
    default=common._es_ignored_metadata,
    nargs='+',
    help='List of keys to ignore from the metadata file.')
_parentParser.add_argument(
    '--uuid',
    help='UUID to provide to ES')
_parentParser.add_argument(
    '--path',
    help='Path to save temporary data')
_parentParser.add_argument(
    '--cleanup',
    help='Should we delete the temporary directory',
    default=False)
_parentParser.add_argument(
    '--cluster-name-seed',
    type=str,
    default='osde2e',
    help='Seed used to generate cluster names. 6 chars max')
_parentParser.add_argument(
    '--cluster-count',
    default=1,
    type=int,
    help='Total number of clusters to create')
_parentParser.add_argument(
    '--batch-size',
    default=0,
    type=int,
    help='number of clusters in a batch')
_parentParser.add_argument(
    '--watcher-delay',
    default=60,
    type=int,
    help='Delay between each status check')
_parentParser.add_argument(
    '--expire',
    type=int,
    help='Minutes until cluster expires and it is deleted by OSD')
_parentParser.add_argument(
    '--cleanup-clusters',
    default=True,
    help='Cleanup any non-error state clusters upon test completion')
_parentParser.add_argument(
    '--delay-between-batch',
    type=int,
    help='If set it will wait x seconds between each batch request')
_parentParser.add_argument(
    '--log-file',
    help='File where to write logs')
_parentParser.add_argument(
    '--log-level',
    default='INFO',
    help='Log level to show')
