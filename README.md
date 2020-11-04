# osde2e-scale-wrapper

## What does it do?

The osde2e-scale-wrapper provides additional functionality and checks on top of the standard
osde2e and osde2ectl utilities. 

It will download the latest osde2e bits from github, compile the go code, execute the build
of X clusters with a range of options, monitor the installation/ready status of the clusters,
upload the resultant timeing data that is provided into Elasticsearch and then cleanup any
non-errored clusters. Errored clusters are left to allow additional diagnosis

Example invocation:

```
$ python3 osde2e-wrapper.py --path /tmp/foo -s my.es.server.com -p 80 --account-config /home/foo/my_config.yaml --cluster-count 2 --batch-size 2 --aws-account-file /home/foo/aws_creds --user-override myfoo
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

'--account-config' The account configuration file to be used as the basis for the run.
                   **NOTE: See the Account Configuration File section for more details**


### Optional Elasticsearch variables:

**NOTE: If elasticsearch server and port are omitted then the cluster test will run as normal
without uploading any information**

| Option | Description | Default |
|--------|-------------|---------|
| --server | The elasticsearch server| -- |
| --port | The elasticsearch port | -- |
| --sslskipverify | If elasticsearch is setup with ssl we can disable tls cert verification. | False |
| --index | The index to write to. | osde2e-install-timings |

### Optional variables:

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
| --cleanup-clusters | Cleanup any non-error state clusters upon test completion. | True |
| --user-override | User to set as the owner. **NOTE: this takes precidence over what is provided in the account-config file** | -- |
| --aws-account-file | AWS account file that provides account,accessKey,secretKey. This file will be looped over as needed to <br> achieve all clusters requested. Example format: <br> ```0009808111,AAAA53YREVPCS111,00019ILbzo+yWU9C5FG5YrnoZC5eBg2111```<br>```0007006111,AAAAUZRL736SW6111,000P/b94AL+LSCzJBWbZCYRuYArF9Zr111``` | -- |

## Account Configuration File

The account configuration file is a yaml formated file that provides vital information for communication with
ocm and AWS.

The configuration file requires some information to be provided for a successful cluster creation.

```
cloudProvider:
  providerId: aws            # The cloud provider (only aws is supported atm)
  region: us-west-2          # The cloud region
ocm:
  env: stage                 # The ocm environment
  token: kaljhsad978Y89      # A valid ocm token
```

The file supports any additional information you could pass to osde2e via a configuration file. An example
with some additional information such as the openshift cluster version, a user override and aws credentials.

```
cloudProvider:
  providerId: aws
  region: us-west-2
cluster:
  version: openshift-v4.5.13
ocm:
  env: stage
  token: kjashf9KJND87
  userOverride: myFoo
  aws:
    account: 12345
    accessKey: ABCD1243
    secretKey: BDL9823sd87

```
