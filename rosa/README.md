# rosa-scale-wrapper

## What does it do?

The rosa-scale-wrapper provides additional functionality and checks on top of the standard rosa cli tool

It will download the latest rosa cli bits from github, execute the build
of X clusters with a range of options, monitor the installation/ready status of the clusters,
upload the resultant timeing data that is provided into Elasticsearch and then cleanup any
non-errored clusters. Errored clusters are left to allow additional diagnosis.
After each cluster installation
on its own folder.

Example invocation:

```
$ python3 rosa-wrapper.py --rosa-token "<<offline token>>" --rosa-env staging --cluster-name-seed mrnd --rosa-cli /usr/local/bin/rosa --log-level debug --cluster-count 10 --batch-size 1 --delay-between-batch 15
```

## Required packages

- python3
- pip3

A requirements.txt file is provided which contains the required python3 pip packages and can be installed via

```
$ pip3 install -r requirments.txt
```

## Variables

The wrapper takes the following required variables:

| Option | Description | Default |
|--------|-------------|---------|
| --cluster-name-seed| Seed for naming all clusters. No more than 6 chars or it will be truncated | -- |
| --rosa-token | Offline token obtained on https://cloud.redhat.com/openshift/token/rosa | -- |

### Optional Elasticsearch variables:

**NOTE: If elasticsearch server and port are omitted then the cluster test will run as normal
without uploading any information**

| Option | Description | Default |
|--------|-------------|---------|
| --es-url | The elasticsearch server URL, including protocol and port (if required)| -- |
| --es-insecure | If ES is setup with ssl, but can disable tls cert verification | False |
| --es-index | The index to write to. | osde2e-install-timings |
| --es-index-retry | Number of retries to connect to ES | 5 |
| --es-index-only | Upload all metadata.json files found under PATH to elasticsearch | -- |

### Optional variables:

| Option | Description | Default |
|--------|-------------|---------|
| --uuid | Uuid to use for the test. If one is not provided it will be generated for you. | -- |
| --path | Full path to a temporary location to use for the test. | /tmp/[uuid] |
| --cleanup | Delete the temporary directory (including all the data from the clusters) upon completion. | False |
| --rosa-cli | Full path to the rosa cli command. If not provided we will download latest from github | -- |
| --rosa-init | Run `rosa init` to initialize AWS account configuration. | False |
| --rosa-env | Rosa environment where to install clusters. | -- |
| --rosa-multi-az | Install ROSA clusters with multi-az support, deploying on multiple datacenters | False |
| --rosa-addons | Comma separated list of addons to be added after cluster installation | -- |
| --aws-profile | AWS profile to use if there is more than one on AWS cli configuration file | -- |
| --cluster-count | Total number of clusters to create. | 1 |
| --batch-size | Number of clusters to create in a batch. If not set it will try and create them all at once. <br>**NOTE**: If not used in conjunction with --delay-between-batch the cluster creation will block at the set batch size until one completes then continue. I.e. if 3 clusters are requested with a batch size of 2. The first two will be requested and then it will block until one of those completes to request the third. | -- |
| --delay-between-batch | If set, we will wait X seconds between each batch request | -- |
| --watcher-delay | Delay between each status check in seconds. | 60 |
| --expire | Minutes until cluster expires and it is deleted by OSD. It sets CLUSTER_EXPIRY_IN_MINUTES var for osde2e | -- |
| --cleanup-clusters | Cleanup any non-error state clusters upon test completion. | True |
| --log-file | File where to write logs. | -- |
| --log-level | Level of logs to show. | INFO |

## AWS Configuration File

Access to AWS is based on the common AWS cli configuration file, usually located on ~/.aws/config

## Important things to note

The rosa-wrapper will create a thread for each cluster you wish to create as well as a watcher thread to track
the status of the cluster installations.

This can quickly lead to resource constraint if not planned accordingly.

### Memory [pending to review]

While not inately memory instensive itself, the wrapper does call rosa for each cluster installation. Because of
this, a system can find itself with memory pressure if running a large number of installations.

### Max open file limits

Each instance of osde2e that is invoked by this wrapper will open a number of files for writing (~70). Please ensure
that your maximum open file limit is sufficient for the number of clusters you wish to create.

To increase you maximum hard and soft open file limit you can run:

```
ulimit -Hn 99999999
ulimit -Sn 99999999
```

### Inotify limits

Each instance of osde2e that is invoked by this wrapper uses an instance of inotify. The default max_user_instances
is usually set low (~128). Please ensure you have enough for 1 per cluster. Additionally, increasing you max_user_watches
is also advised. Setting each to 20000 should be more than sufficient for a 1000 cluster test.

These values can be changed by running the following.

```
sysctl user.max_inotify_instances=20000
sysctl user.max_inotify_watches=20000
```

## TODO
- Add expiration extension management (https://issues.redhat.com/browse/SDA-3600)
- Review numbering on threads, its seems to be always on +1
