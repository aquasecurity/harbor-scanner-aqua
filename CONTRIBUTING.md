# Contributing

## Table of Contents

* [Set up Local Development Environment](#set-up-local-development-environment)
* [Setup Development Environment with Vagrant](#setup-development-environment-with-vagrant)
* [Build Binaries](#build-binaries)
* [Run Tests](#run-tests)
  * [Run Unit Tests](#run-unit-tests)
  * [Run Integration Tests](#run-integration-tests)

## Set up Local Development Environment

1. The project requires [Go 1.15][go-download] or later. We also assume that you're familiar with Go's
   [GOPATH workspace][go-code] convention, and have the appropriate environment variables set.
3. Install Docker, Docker Compose, and Make.
4. Get the source code.
   ```
   git clone https://github.com/aquasecurity/harbor-scanner-aqua.git
   cd harbor-scanner-aqua
   ```

## Setup Development Environment with Vagrant

1. Get the source code.
   ```
   git clone https://github.com/aquasecurity/harbor-scanner-aqua.git
   cd harbor-scanner-aqua
   ```
2. Create and configure a guest development machine, which is based on Ubuntu 20.4.3 LTS and has Go, Docker, Docker Compose,
   Make, and Harbor v2.4.0 preinstalled. Harbor is installed in the `/opt/harbor` directory.
   ```
   export AQUA_REGISTRY_USERNAME=<provide your username>
   export AQUA_REGISTRY_PASSWORD=<provide your password>
   export AQUA_VERSION="6.5"
   export HARBOR_VERSION="v2.4.0"
   
   vagrant up
   ```

The Harbor UI is accessible at http://localhost:8181 (admin/Harbor12345). The Aqua Management Console is accessible at
http://localhost:9181 (administrator/@Aqua12345). Note that you'll be prompted for a valid licence key upon successful
login to the Aqua Management Console.
   
To SSH into a running Vagrant machine.
```
vagrant ssh
```

The `/vagrant` directory in the development machine is shared between project (host) and guest.

```
vagrant@ubuntu-focal:~$ cd /vagrant
```

## Build Binaries

Run `make` to build the binary in `./scanner-adapter`.

```
make
```

To build into a Docker container `aquasec/harbor-scanner-aqua:dev`.

```
make docker-build
```

## Run Tests

### Run Unit Tests

```
make test
```

### Run Integration Tests

```
make test-integration
```

[go-download]: https://golang.org/dl/
[go-code]: https://golang.org/doc/code.html
