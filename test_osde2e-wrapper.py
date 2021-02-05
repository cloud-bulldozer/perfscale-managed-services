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

import unittest
import importlib
import json


metadata = json.loads("""
{
"timestamp": "2021-02-05T16:16:11", "cluster-id": "1ikrg2ioq096pvkruhrs6o7p0btb7blp", "cluster-name": "osde2e-18hgn", "cluster-version": "openshift-v4.6.15", "environment": "prod", "region": "us-east-1", "time-to-ocm-reporting-installed": "1770.729182375", "time-to-cluster-ready": "1740.389981614", "time-to-upgraded-cluster": "0", "time-to-upgraded-cluster-ready": "0", "time-to-certificate-issued": "119.030519994", "install-phase-pass-rate": "-1", "upgrade-phase-pass-rate": "-1", "log-metrics": {"access-token-500": 0, "cluster-mgmt-500": 0, "cluster-pending": 0, "eof": 0, "host-dns-lookup": 0}, "before-suite-metrics": {"AMI ID Retieval Failure": 0, "AWS client creation failure": 0, "AWS credentials not valid": 0, "AWS error due to missing source clusterconfig": 0, "AWS image AMI failure": 0, "AWS region not enabled": 0, "BYOC account vaildation failure": 0, "Error in PollClusterHealth": 0, "Setting osa_use_marketplace_ami property manually": 0, "Test Panicked due to runtime error": 0, "cluster-health-check": 0, "cluster-install timeout": 0, "cluster-retrieval OCM error": 0, "cluster-setup": 0, "error creating cluster": 0, "failed to get access keys for user 'osdCcsAdmin'": 0, "missing quota for cluster creation": 0, "quota-check": 0, "running task Updating Alertmanager failed": 0, "timed out waiting for the condition during syncRequiredMachineConfigPools": 0}, "route-latencies": {}, "route-throughputs": {}, "route-availabilities": {}, "healthchecks": {}, "healthcheckIteration": 118, "status": "ready", "cluster_start_time": "2021-02-04T14:34:49", "cluster_end_time": "2021-02-04T15:38:13", "install_successful": true, "uuid": "98f26b1d-faaf-4894-ac22-0a5383849b78", "install_counter": 82}
""")

expected = {'timestamp': '2021-02-05T16:16:11',
            'cluster_start_time': '2021-02-04T14:34:49',
            'cluster_end_time': '2021-02-04T15:38:13',
            'install_successful': True,
            'uuid': '98f26b1d-faaf-4894-ac22-0a5383849b78',
            'install_counter': 82,
            'cluster_id': '1ikrg2ioq096pvkruhrs6o7p0btb7blp',
            'cluster_name': 'osde2e-18hgn',
            'cluster_version': 'openshift-v4.6.15',
            'environment': 'prod',
            'region': 'us-east-1',
            'details_url': '',
            'time_to_ocm_reporting_installed': 1770,
            'time_to_cluster_ready': 1740,
            'time_to_upgraded_cluster': 0,
            'time_to_upgraded_cluster_ready': 0,
            'time_to_certificate_issued': 119,
            'install_phase_pass_rate': '-1',
            'upgrade_phase_pass_rate': '-1',
            'log_metrics': {
                'access_token_500': 0,
                'cluster_mgmt_500': 0,
                'cluster_pending': 0,
                'eof': 0,
                'host_dns_lookup': 0,
                },
            }


class TestBuildDocument(unittest.TestCase):

    def test_buildDoc(self):
        wrapper = importlib.import_module("osde2e-wrapper")
        doc = wrapper.buildDoc(metadata)
        self.maxDiff = None
        self.assertDictEqual(doc,expected)


if __name__ == '__main__':
    unittest.main()
