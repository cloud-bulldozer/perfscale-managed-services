# osde2e-scale-wrapper

## What does it do?

The osde2e-scale-wrapper provides additional functionality and checks on top of the standard
osde2e and osde2ectl utilities.

It will download the latest osde2e bits from github, compile the go code, execute the build
of X clusters with a range of options, monitor the installation/ready status of the clusters,
upload the resultant timeing data that is provided into Elasticsearch and then cleanup any
non-errored clusters. Errored clusters are left to allow additional diagnosis.
After each cluster installation, kubeconfig file for that cluster will be downloaded and located
on its own folder.

Example minimal invocation:

```
$ python3 osde2e-wrapper.py --account-config /home/foo/my_config.yaml
```

Example invocation with options:

```
$ python3 osde2e-wrapper.py --path /tmp/foo --es-url https://my.es.server.com:80 --account-config /home/foo/my_config.yaml --cluster-count 2 --batch-size 2 --aws-account-file /home/foo/aws_creds --user-override myfoo
```

## Required packages

- python3
- pip3
- Go
- make

A requirements.txt file is provided which contains the required python3 pip packages and can be installed via

```
$ pip3 install -r requirments.txt
```

## Variables

The wrapper takes the following required variables:

| Option | Description | Default |
|--------|-------------|---------|
| --account-config | The account configuration file to be used as the basis for the run.<br>**NOTE: See the Account Configuration File section for more details** | -- |
| --cluster-name-seed | Seed for naming all clusters. No more than 6 chars or it will be truncated | osde2e |

### Optional Elasticsearch variables

**NOTE: If elasticsearch server and port are omitted then the cluster test will run as normal
without uploading any information**

| Option | Description | Default |
|--------|-------------|---------|
| --es-url | The elasticsearch server URL, including protocol and port (if required)| -- |
| --es-insecure | If ES is setup with ssl, but can disable tls cert verification | False |
| --es-index | The index to write to. | osde2e-install-timings |
| --es-index-retry | Number of retries to connect to ES | 5 |
| --es-index-only | Upload all metadata.json files found under PATH to elasticsearch | -- |
| --es-ignored-metadata | List of keys to ignore from the metadata file | ```before-suite-metrics route-latencies route-throughputs route-availabilities healthchecks healthcheckIteration status``` |


### Optional variables

| Option | Description | Default |
|--------|-------------|---------|
| --uuid | Uuid to use for the test. If one is not provided it will be generated for you. | -- |
| --path | Full path to a temporary location to use for the test. | /tmp/[uuid] |
| --cleanup | Delete the temporary directory (including all the data from the clusters) upon completion. | False |
| --command | Full path to the osde2e and osde2ectl command directory. If not provided we will download and compile the latest | -- |
| --cluster-count | Total number of clusters to create. | 1 |
| --batch-size | Number of clusters to create in a batch. If not set it will try and create them all at once. <br>**NOTE**: If not used in conjunction with --delay-between-batch the cluster creation will block at the set batch size until one completes then continue. I.e. if 3 clusters are requested with a batch size of 2. The first two will be requested and then it will block until one of those completes to request the third. | -- |
| --delay-between-batch | If set, we will wait X seconds between each batch request | -- |
| --watcher-delay | Delay between each status check in seconds. | 60 |
| --expire | Minutes until cluster expires and it is deleted by OSD. It sets CLUSTER_EXPIRY_IN_MINUTES var for osde2e | -- |
| --cleanup-clusters | Cleanup any non-error state clusters upon test completion. | True |
| --user-override | User to set as the owner. <br>**NOTE: this takes precidence over what is provided in the account-config file** | -- |
| --aws-account-file | AWS account file that provides account,accessKey,secretKey. This file will be looped over as needed to achieve all clusters requested. Example format: <br> ```0009808111,AAAA53YREVPCS111,00019ILbzo+yWU9C5FG5YrnoZC5eBg2111```<br>```0007006111,AAAAUZRL736SW6111,000P/b94AL+LSCzJBWbZCYRuYArF9Zr111```<br>Having AWS_PROFILE variable set will choose which profile to use. | -- |
| --log-file | File where to write logs. | -- |
| --log-level | Level of logs to show. | INFO |
| --dry-run | Perform a dry-run of the script without creating any cluster | False |
| --skip-health-check | Do not run Health Checks after cluster is installed by osde2e | False |
| --osde2e-must-gather | Enable gathering facts after cluster installation | False |

## Account Configuration File

The account configuration file is a yaml formated file that provides vital information for communication with
ocm and AWS.

The configuration file requires some information to be provided for a successful cluster creation.

```yaml
cloudProvider:
  providerId: aws            # The cloud provider (only aws is supported atm)
  region: us-west-2          # The cloud region
ocm:
  env: stage                 # The ocm environment
  token: kaljhsad978Y89      # A valid ocm token
```

The file supports any additional information you could pass to osde2e via a configuration file. An example
with some additional information such as the openshift cluster version, a user override and aws credentials.

```yaml
cloudProvider:
  providerId: aws
  region: us-west-2
cluster:
  version: openshift-v4.5.13
ocm:
  env: stage
  token: kjashf9KJND87
  userOverride: myFoo
  ccs: True
  aws:
    account: 12345
    accessKey: ABCD1243
    secretKey: BDL9823sd87

```

## Important things to note

The osde2e-wrapper will create a thread for each cluster you wish to create as well as a watcher thread to track
the status of the cluster installations.

This can quickly lead to resource constraint if not planned accordingly.

### Memory

While not inately memory instensive itself, the wrapper does call osde2e for each cluster installation. Because of
this, a system can find itself with memory pressure if running a large number of installations.

### Max open file limits

Each instance of osde2e that is invoked by this wrapper will open a number of files for writing (~70). Please ensure
that your maximum open file limit is sufficient for the number of clusters you wish to create.

To increase you maximum hard and soft open file limit you can run:

```sh
ulimit -Hn 99999999
ulimit -Sn 99999999
```

### Inotify limits

Each instance of osde2e that is invoked by this wrapper uses an instance of inotify. The default max_user_instances
is usually set low (~128). Please ensure you have enough for 1 per cluster. Additionally, increasing you max_user_watches
is also advised. Setting each to 20000 should be more than sufficient for a 1000 cluster test.

These values can be changed by running the following.

```sh
sysctl user.max_inotify_instances=20000
sysctl user.max_inotify_watches=20000
```
