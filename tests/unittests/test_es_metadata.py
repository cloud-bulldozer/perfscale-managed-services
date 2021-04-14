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
import json
from libs import common


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
            'time_to_ocm_reporting_installed': 1770,
            'time_to_cluster_ready': 1740,
            'time_to_upgraded_cluster': 0,
            'time_to_upgraded_cluster_ready': 0,
            'time_to_certificate_issued': 119,
            'install_phase_pass_rate': -1,
            'upgrade_phase_pass_rate': -1,
            'route_availabilities': {},
            'route_latencies': {},
            'route_throughputs': {},
            'healthchecks': {},
            'healthcheckiteration': 118,
            'status': 'ready',
            'log_metrics': {
                'access_token_500': 0,
                'cluster_mgmt_500': 0,
                'cluster_pending': 0,
                'eof': 0,
                'host_dns_lookup': 0,
                },
            'before_suite_metrics': {
                'ami_id_retieval_failure': 0,
                'aws_client_creation_failure': 0,
                'aws_credentials_not_valid': 0,
                'aws_error_due_to_missing_source_clusterconfig': 0,
                'aws_image_ami_failure': 0,
                'aws_region_not_enabled': 0,
                'byoc_account_vaildation_failure': 0,
                'cluster_health_check': 0,
                'cluster_install_timeout': 0,
                'cluster_retrieval_ocm_error': 0,
                'cluster_setup': 0,
                'error_creating_cluster': 0,
                'error_in_pollclusterhealth': 0,
                "failed_to_get_access_keys_for_user_'osdccsadmin'": 0,
                'missing_quota_for_cluster_creation': 0,
                'quota_check': 0,
                'running_task_updating_alertmanager_failed': 0,
                'setting_osa_use_marketplace_ami_property_manually': 0,
                'test_panicked_due_to_runtime_error': 0,
                'timed_out_waiting_for_the_condition_during_syncrequiredmachineconfigpools': 0
                },
            }

expected2 = {'timestamp': '2021-02-05T16:16:11',
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
             'time_to_ocm_reporting_installed': 1770,
             'time_to_cluster_ready': 1740,
             'time_to_upgraded_cluster': 0,
             'time_to_upgraded_cluster_ready': 0,
             'time_to_certificate_issued': 119,
             'install_phase_pass_rate': -1,
             'upgrade_phase_pass_rate': -1,
             'route_availabilities': {},
             'route_latencies': {},
             'route_throughputs': {},
             'healthchecks': {},
             'healthcheckiteration': 118,
             'status': 'ready',
             'log_metrics': {
                 'access_token_500': 0,
                 'cluster_mgmt_500': 0,
                 'cluster_pending': 0,
                 'host_dns_lookup': 0,
                 },
             }


class TestBuildDocument(unittest.TestCase):

    def test_buildDoc(self):
        doc = common._buildDoc(metadata, [])
        self.maxDiff = None
        self.assertDictEqual(doc,expected)
        # Test ignored<etadata feature
        doc = common._buildDoc(metadata, ['before-suite-metrics','eof'])
        self.maxDiff = None
        self.assertDictEqual(doc,expected2)

class Case(object):
    def __init__(self, caseName, value, expectedType, expectError):
        self.caseName = caseName
        self.value = value
        self.expectedType = expectedType
        self.expectError = expectError

class TestParseValues(unittest.TestCase):

    def test_getValue(self):
        cases = []
        cases.append(Case("01-boolean", True, bool, False))
        cases.append(Case("02-boolean", False, bool, False))
        cases.append(Case("03-notBoolean", 0, bool, True))
        cases.append(Case("04-notBoolean", 1, bool, True))
        cases.append(Case("05-notBoolean", "1", bool, True))
        cases.append(Case("06-notBoolean", "asdf", bool, True))
        cases.append(Case("07-notBoolean", 12.9876543, bool, True))
        cases.append(Case("08-notBoolean", "12.9876543", bool, True))
        cases.append(Case("09-notBoolean", {}, bool, True))
        cases.append(Case("10-notBoolean", [], bool, True))
        cases.append(Case("01-notInt", True, int, True))
        cases.append(Case("02-notInt", False, int, True))
        cases.append(Case("03-int", 0, int, False))
        cases.append(Case("04-int", 1, int, False))
        cases.append(Case("05-int", "1", int, False))
        cases.append(Case("06-notInt", "asdf", int, True))
        # This might be confussing but we are not using the decimal
        # part of the number so it gets truncated into an int.
        cases.append(Case("07-notInt", 12.9876543, int, False))
        cases.append(Case("08-notInt", "12.9876543", int, False))
        cases.append(Case("09-notInt", {}, int, True))
        cases.append(Case("10-notInt", [], int, True))
        cases.append(Case("01-notFloat", True, float, True))
        cases.append(Case("02-notFloat", False, float, True))
        cases.append(Case("03-notFloat", 0, float, True))
        cases.append(Case("04-notFloat", 1, float, True))
        cases.append(Case("05-notFloat", "1", float, True))
        cases.append(Case("06-notFloat", "asdf", float, True))
        # This might be confussing but we are not using the decimal
        # part of the number so it gets truncated into an int.
        cases.append(Case("07-float", 12.9876543, int, False))
        cases.append(Case("08-float", "12.9876543", int, False))
        cases.append(Case("09-notFloat", {}, float, True))
        cases.append(Case("10-notFloat", [], float, True))
        cases.append(Case("01-notString", True, str, True))
        cases.append(Case("02-notString", False, str, True))
        cases.append(Case("03-notString", 0, str, True))
        cases.append(Case("04-notString", 1, str, True))
        cases.append(Case("05-notString", "1", str, True))
        cases.append(Case("06-string", "asdf", str, False))
        cases.append(Case("07-notString", 12.9876543, str, True))
        cases.append(Case("08-notString", "12.9876543", str, True))
        cases.append(Case("09-notString", {}, str, True))
        cases.append(Case("10-notString", [], str, True))
        cases.append(Case("01-notDict", True, dict, True))
        cases.append(Case("02-notDict", False, dict, True))
        cases.append(Case("03-notDict", 0, dict, True))
        cases.append(Case("04-notDict", 1, dict, True))
        cases.append(Case("05-notDict", "1", dict, True))
        cases.append(Case("06-notDict", "asdf", dict, True))
        cases.append(Case("07-notDict", 12.9876543, dict, True))
        cases.append(Case("08-notDict", "12.9876543", dict, True))
        cases.append(Case("09-dict", {}, dict, False))
        cases.append(Case("10-notDict", [], dict, True))
        cases.append(Case("11-dict", {'1': {'2': {'3': {'4': 6}}}}, dict, False))

        for case in cases:
            v = common._getValue(case.value,[])
            if not case.expectError:
                self.assertEqual(case.expectedType, type(v), "error in case {}: input {}".format(case.caseName, case.value))
            else:
                self.assertNotEqual(case.expectedType, type(v), "error in case {}: input {}".format(case.caseName, case.value))


if __name__ == '__main__':
    unittest.main()
