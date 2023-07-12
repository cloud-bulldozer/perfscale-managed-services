# rosa-hypershift-wrapper

## What does it do?

The rosa-hypershift-wrapper is an enhanced tool that extends the functionality of the standard rosa CLI tool. It offers additional features and checks to streamline the cluster deployment process.

Here's an overview of its workflow:

1. **Download Dependencies**: The wrapper automatically fetches the latest versions of rosa, ocm CLI bits from the GitHub repository.

2. **Cluster Build and Configuration**: With the wrapper, you can easily build multiple clusters of different configurations by specifying various options to meet your requirements.

3. **Installation and Status Monitoring**: The wrapper monitors the installation progress and ensures that the clusters are ready for use. It keeps track of the status of each cluster, ensuring that they are successfully deployed and operational via watcher threads.

4. **E2E-Benchmarking**: The wrapper includes functionality to execute end-to-end benchmarking scripts. These scripts apply load and performance tests to evaluate the clusters' capabilities and identify any potential bottlenecks or performance issues.

5. **Data Upload to Elasticsearch**: The timing data collected during the benchmarking process is automatically uploaded to Elasticsearch. This enables you to analyze and visualize the performance metrics of your clusters.

6. **Cleanup of Non-Errored Clusters**: The wrapper performs cleanup operations to remove any non-errored clusters. This ensures a clean and organized environment, removing clusters that have been successfully deployed and evaluated.

7. **Cluster Error Handling**: If any clusters encounter errors during the deployment or benchmarking phases, they are left intact. This allows for further analysis and troubleshooting to identify and resolve any issues that may have occurred.

8. **Install & Uninstall logs**: Each cluster's installation and uninstallation details are organized and stored in separate folders. This makes it easier to track and manage the specific details and artifacts associated with each cluster.

Overall, the rosa-hypershift-wrapper simplifies and enhances the process of building, deploying, benchmarking, and managing clusters, providing a more efficient and streamlined experience.


In the example provided, we will create 10 hosted clusters in a staging environment. The cluster names will be prefixed with ocp412, and the clusters will be installed with OpenShift Container Platform (OCP) version 4.12.15.

Once the installation is complete, the wrapper will execute e2e-benchmarking scripts to evaluate the performance of the clusters. The benchmarking results will be documented and stored in the corresponding Elasticsearch URL (ES_URL).

```
$ python rosa-hypershift/rosa-hosted-wrapper.py --cluster-name-seed ocp412 --cluster-count 10 --aws-account-file <PATH>/.aws/credentials --aws-profile default --rosa-cli <PATH_TO>/rosa --ocm-token <OCM_TOKEN> --workers 3 --es-url https://<USERNAME>:<PASSWORD>@<ES_URL>:443 --es-index hypershift-wrapper-timers --es-insecure --log-level DEBUG --log-file /tmp/ocp413.log --batch-size 1 --delay-between-batch 20 --cluster-load-duration 15m --cluster-load-jobs-per-worker 3,9,12 --cluster-load-job-variation 0 --wildcard-options "--version 4.12.15" --create-vpc --terraform-cli <PATH_TO>/terraform --manually-cleanup-secgroups --workers-wait-time 60 --delay-between-cleanup 30 --add-cluster-load --common-operator-roles  --rosa-env staging
```
In the provided example, we will create 5 hosted clusters in a staging environment. The cluster names will be prefixed with ocp413, and the clusters will be installed with OpenShift Container Platform (OCP) version 4.13.0. The installation will target a provision shard.

After the clusters are successfully installed, the wrapper will execute e2e-benchmarking scripts to assess the performance of the clusters. The benchmarking results will be documented and stored in the corresponding Elasticsearch URL (ES_URL).
```
$ python rosa-hypershift/rosa-hosted-wrapper.py --cluster-name-seed ocp413 --cluster-count 5 --aws-account-file <PATH>/.aws/credentials --aws-profile default --rosa-cli <PATH_TO>/rosa --ocm-token <OCM_TOKEN> --workers 3 --es-url https://<USERNAME>:<PASSWORD>@<ES_URL>:443 --es-index hypershift-wrapper-timers --es-insecure --log-level DEBUG --log-file /tmp/ocp413.log --batch-size 1 --delay-between-batch 20 --cluster-load-duration 15m --cluster-load-jobs-per-worker 9 --cluster-load-job-variation 0 --wildcard-options "--version 4.12.15" --create-vpc --terraform-cli <PATH_TO>/terraform --manually-cleanup-secgroups --workers-wait-time 60 --delay-between-cleanup 30 --add-cluster-load --common-operator-roles  --rosa-env staging  --provision-shard <SC_PROVISION_SHARD>
```


## Required packages

- python3
- pip3

A requirements.txt file contains the required python-pip packages and can be installed via:

```
$ pip3 install -r requirments.txt
```

## Required Variables

The wrapper takes the following required variables:

| Option | Description | Default |
|--------|-------------|---------|
| --cluster-name-seed| Seed used to generate cluster names. 6 chars max | perfc |
| --ocm-token | Obtain offline via on https://cloud.redhat.com/openshift/token | -- |
| --cluster-count | Total number of clusters to create | -- |
| --aws-account-file | AWS account file to use | -- |
| --aws-profile | AWS profile to use if more than one are present on aws config file | -- |
| --workers | Number of workers for the hosted cluster (min: 3). If list (comma separated), iteration over the list until reach number of clusters | 3 |


---
## Elasticsearch variables:

**NOTE**: If Elasticsearch server and port are omitted then the cluster test will run as normal without uploading any information

| Option | Description | Default |
|--------|-------------|---------|
| --es-url | The elasticsearch server URL, including protocol and port (if required)| -- |
| --es-insecure | If ES is setup with ssl, but can disable tls cert verification | False |
| --es-index | The index to write to. | hypershift-wrapper-timers |
| --es-index-retry | Number of retries to connect to ES | 5 |
| --es-index-only | Upload all metadata.json files found under PATH to elasticsearch | -- |

## Optional variables:

Optional variables are parameters that offer flexibility and allow users to customize the behavior or configuration of the program based on their specific needs.

| Option | Description | Default |
|--------|-------------|---------|
| --uuid | UUID to use for the test. If one is not provided it will be generated for you. | -- |
| --path | Full path to a temporary location to use for the test. | /tmp/[uuid] |
| --cleanup | Delete the temporary directory (including all the data from the clusters) upon completion. | False |
| --rosa-cli | Full path to the rosa cli command. If not provided we will download latest from github | -- |
| --ocm-url | OCM environment | https://api.stage.openshift.com |
| --ocm-cli-version | Path to the ocm binary, downloads the bits from GitHub | -- |
| --rosa-env | ROSA Environment ( staging, integration) | production |
| --rosa-cli | Path to the rosa binary. If none provided, downloads the bits from GitHub | -- |
| --rosa-cli-version | Supply required version of rosa binary from GitHub | Defaults to latest |
| --rosa-init | Initialize AWS account configuration | False |
| --add-cluster-load | Execute e2e script after hosted cluster is installed to load | -- |
| --cluster-load-duration| Churn Duration Parameter used on the e2e script | 4h |
| --cluster-load-jobs-per-worker | Job iterations per worker, scales with number of workers | -- |
| --cluster-load-job-variation | Percentage of variation of jobs to execute | -- |
| --workers-wait-time | Time to wait for the workers to be Ready after cluster installation or machinepool creation| Defaults 60 minutes|
| --terraform-cli | PATH to the terraform binary | -- |
| --terraform-retry | terraform commands retries | 5 |
| --create-vpc | One VPC pe each Hosted Cluster | -- |
| --clusters-per-vpc | Number of clusters to create on each VPC | Default: 1, Max: 10|
| --must-gather-all | Capture must-gather from all clusters, else only from failed clusters | -- |
| --oidc-config-id | Supply a custom oidc config id for the oidc provider, wont delete when supplied | -- |
| --common-operator-roles | Create unique operator roles and use them on for respective cluster installations | -- |
| --workload-type | Pass the workload type | Defaults to cluster-density-ms |
| --kube-burner-version | Supply Kube-burner version | Defaults to 1.5 |
| --e2e-git-details | Supply the e2e-repo GitHub URL | https://github.com/cloud-bulldozer/e2e-benchmarking.git |
| --git-branch | Specify a desired branch of the corresponding git repo | Defaults to master |
| --manually-cleanup-secgroups | Delete security groups before deleting the VPC | -- |
| --wait-before-cleanup | Number of minutes to wait before cleanup clusters | 0 |
| --batch-size | Number of clusters to create in a batch. If not set it will try and create them all at once. <br>**NOTE**: If not used in conjunction with --delay-between-batch the cluster creation will block at the set batch size until one completes then continue. I.e. if 3 clusters are requested with a batch size of 2. The first two will be requested and then it will block until one of those completes to request the third. | -- |
| --delay-between-batch | If set, wait X seconds between each batch request | -- |
| --delay-between-cleanup | If set, will wait x seconds between each cluster deletion | -- |
| --watcher-delay | Delay between each status check in seconds. | 60 |
| --expire | Minutes until cluster expires and it is automatically deleted | -- |
| --cleanup-clusters | Cleanup any non-error state clusters upon test completion. | False |
| --log-file | Capture operational logs in this file | -- |
| --log-level | Level of logs to show. | INFO |
| --wildcard-options | [Any other option to be passed to the rosa binary](#wildcard-variable) | -- |

## Optional Machinepool variables

A new machinepool can be created on each cluster after installation if `--machinepool-name` parameter is added. The rest of machinepool related parameters will have the default value if no specified.

| Option | Description | Default |
|--------|-------------|---------|
| --machinepool-name | Name of the machinepool to be created | -- |
| --machinepool-labels | Labels to add on the machinepool | node-role.kubernetes.io/workload= |
| --machinepool-taints | Taints to add on the machinepool | role=workload:NoSchedule |
| --machinepool-flavour | AWS flavour to use in the machinepool | m5.xlarge |
| --machinepool-replicas | Number of hosts to create on the machinepool | 3 |
| --machinepool-wait-time | Waiting time in seconds nodes to come up | False |

## Wildcard variable

As each new ROSA CLI version is released, an expanded set of parameters becomes available to fine-tune deployments. Using the `--wildcard-options` flag, we can pass a string directly to the `rosa create cluster` command, allowing for greater control and customization of the deployment process. This empowers users to tailor the cluster creation according to their specific requirements, leveraging the flexibility and extensibility offered by the ROSA CLI.

For example:

`rosa-hosted-wrapper.py --cluster-name-seed mrnd --cluster-count 1 --wildcard-options "--region us-west-2"`

## AWS Configuration File

Access to AWS is based on the common AWS cli configuration file, usually located on ~/.aws/config

## Important things to note

The rosa-hosted-wrapper will create a thread for each cluster you wish to create and track
the status of the cluster installations via watcher thread

This can quickly lead to resource constraint if not planned accordingly.

## Max open file limits

Each instance of rosa-hosted-wrapper- that is invoked by this wrapper will open a number of files for writing (~70). Please ensure
that your maximum open file limit is sufficient for the number of clusters you wish to create.

To increase Hard and Soft Open file limit you can run:

```
ulimit -Hn 99999999
ulimit -Sn 99999999
```