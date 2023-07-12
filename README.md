# Perfscale Managed Services

This repo contains script to automate and test deployments on [Red Hat Managed Services](https://www.openshift.com/learn/topics/managed-services)

## Available Environments

- [Red Hat OpenShift Service on AWS (ROSA)](https://www.openshift.com/products/amazon-openshift)

## Managed OCP4 installed on AWS

### Available Testers

- [osde2e-wrapper](./osde2e/README.md)
- [rosa-wrapper](./rosa/README.md)
- [hypershift-wrapper](./hypershift/README.md)
- [rosa-hypershift-wrapper](./rosa-hypershift/README.md)

## Running tests

### Local testing

To run tests locally use the folling command:

`tox .`

If you have a dirty virtual environment use the option `-r` in `tox` to recreate the environments.

### Testing in a container

The container must have internet access to build, it is not necessary to install any requirenments in your workstation.

First build the image that will run the tests:

`podman build -f tests/Dockerfile --tag tox-test:latest .`

The tag can be anything you want and can be changed, in thsi case we are using `tox-test:latest`.

To run the tests execute:

`podman run --rm -ti tox-test:latest`

You can execute any sub-environment of `tox` by doing the following:

`podman run --rm -ti tox-test:latest tox -e stage`
