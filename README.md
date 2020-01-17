[![GitHub release][release-img]][release]
[![Build Actions][build-action-img]][build-action]
[![Codecov][codecov-img]][codecov]
[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]

# Harbor Scanner Adapter for Aqua CSP Scanner

The Harbor [Scanner Adapter][image-vulnerability-scanning-proposal] for Aqua CSP is a service that translates
the [Harbor][harbor-url] scanning API into `scannercli` commands and allows Harbor to use Aqua CSP scanner
for providing vulnerability reports on images stored in Harbor registry as part of its vulnerability scan feature.

> **NOTE**: This adapter is only required if you want Harbor to use Aqua CSP for its image scanning feature.
> If your objective is to use Aqua CSP to provide its own analysis reports against images stored in Harbor,
> that can be achieved without this adapter.

## TOC

- [Requirements](#requirements)
- [How it works?](#how-it-works)
- [Getting started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Build](#build)
  - [Running on minikube](#running-on-minikube)
- [Deployment](#deployment)
  - [Kubernetes](#kubernetes)
- [Configuration](#configuration)
- [License](#license)

## Requirements

1. This adapter requires Aqua CSP >= 4.5 deployment to operate against. The adapter can be deployed before the Aqua CSP
   installation, but the Aqua CSP management console URL and credentials must be known to configure the adapter with
   the environment variables.
2. The adapter service requires the `scannercli` executable binary, in version matching the Aqua CSP, to be mounted
   at `/usr/local/bin/scannercli`. The provided Helm chart mounts the `scannercli` executable automatically by pulling
   the `registry.aquasec.com/scanner:$AQUA_CSP_VERSION` from Aqua Registry and running it as an [init container][k8s-init-containers].
   The init container's command is configured to copy the executable from the container's filesystem to an [emptyDir][k8s-volume-emptyDir]
   volume, which is shared with the main container. This makes the `scannercli` executable available to the main container at
   `/usr/local/bin/scannercli`.

   > **NOTE**: Make sure that you provide valid Aqua Registry credentials received from Aqua Security as Helm values
   > in order to create the corresponding image pull secret.

   If you're not using Kubernetes to run the adapter service, you have to download the `scannercli` executable from the
   Aqua downloads page manually and mount it at `/usr/local/bin/scannercli`.
   See [Aqua Scanner Executable Binary][aqua-docs-scanner-binary] for more details on manual download.
3. It is highly recommended to create a new user in the Aqua CSP deployment with credentials dedicated to the Harbor
   adapter. The adapter does not require access to the management console. Therefore only the `Scanner` role must be
   assigned to such user in order to grant permissions for `scannercli` utilities, which are used by the adapter
   behind the scenes.

   ![Scanner user](docs/images/aqua_ui_user.png)
4. It is also highly recommended to create a new user in Harbor with credentials dedicated to the Aqua CSP scanner.
   Use those credentials to create a new integration with Harbor registry.

   ![Harbor integration](docs/images/aqua_ui_harbor_registry.png)

## How it works?

In essence, a scan request payload sent by Harbor to the adapter:

```json
{
  "registry": {
    "url": "https://core.harbor.domain",
    "authorization": "Basic BASE64_ENCODED_CREDENTIALS"
  },
  "artifact": {
    "repository": "library/mongo",
    "tag": "3.4-xenial",
    "digest": "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b",
    "mime_type": "application/vnd.docker.distribution.manifest.v2+json"
  }
}
```

is translated to the following `scannercli` command:

```
$ scannercli scan \
    --user $SCANNER_AQUA_USERNAME \
    --password $SCANNER_AQUA_PASSWORD \
    --host $SCANNER_AQUA_HOST \
    --registry $SCANNER_AQUA_REGISTRY \
    --dockerless \
    --jsonfile /var/lib/scanner/reports/scan_report_071315299.json
    library/mongo:3.4-xenial
```

Finally, the output report is translated to Harbor model so it can be displayed in Harbor UI.

## Getting started

These instructions will get you a copy of the adapter service up and running on your local
machine for development and testing purposes. See [deployment](#deployment) for notes on
how to deploy on a live system.

### Prerequisites

* [Go (version 1.13+)](https://golang.org/doc/devel/release.html#go1.13)
* Docker

### Build

Run `make` to build the binary in `./scanner-adapter`:

```
make
```

To build into a Docker container:

```
make build-image
```

### Running on [minikube][minikube-url]

1. Set up environment for the Docker client:
   ```
   $ eval $(minikube docker-env)
   ```
2. Build a Docker image `aquasec/harbor-scanner-aqua:dev`:
   ```
   $ make container
   ```
3. Install the `harbor-scanner-aqua` release with `helm`:
   ```
   $ helm install harbor-scanner-aqua ./helm/harbor-scanner-aqua \
                  --namespace harbor \
                  --set aqua.version=4.5 \
                  --set aqua.registry.server=registry.aquasec.com \
                  --set aqua.registry.username=$AQUA_REGISTRY_USERNAME \
                  --set aqua.registry.password=$AQUA_REGISTRY_PASSWORD \
                  --set scanner.image.tag=dev \
                  --set scanner.logLevel=trace \
                  --set scanner.aqua.username=$AQUA_CONSOLE_USERNAME \
                  --set scanner.aqua.password=$AQUA_CONSOLE_PASSWORD \
                  --set scanner.aqua.host=http://csp-console-svc.aqua:8080
   ```

## Deployment

### Kubernetes

1. Generate certificate and private key files:
   ```
   $ openssl genrsa -out tls.key 2048
   $ openssl req -new -x509 \
                 -key tls.key \
                 -out tls.crt \
                 -days 365 \
                 -subj /CN=harbor-scanner-aqua.harbor
   ```
2. Install the `harbor-scanner-aqua` chart:
   ```
   $ helm install harbor-scanner-aqua ./helm/harbor-scanner-aqua \
                  --namespace harbor \
                  --set service.port=8443 \
                  --set scanner.api.tlsEnabled=true \
                  --set scanner.api.tlsCertificate="`cat tls.crt`" \
                  --set scanner.api.tlsKey="`cat tls.key`" \
                  --set aqua.version=4.5 \
                  --set aqua.registry.server=registry.aquasec.com \
                  --set aqua.registry.username=$AQUA_REGISTRY_USERNAME \
                  --set aqua.registry.password=$AQUA_REGISTRY_PASSWORD \
                  --set scanner.aqua.username=$AQUA_CONSOLE_USERNAME \
                  --set scanner.aqua.password=$AQUA_CONSOLE_PASSWORD \
                  --set scanner.aqua.host=http://csp-console-svc.aqua:8080
   ```
3. Configure the scanner adapter in Harbor web console.
   1. Navigate to **Interrogation Services** and click **+ NEW SCANNER**.
      ![Scanners config](docs/images/harbor_ui_scanners_config.png)
   2. Enter https://harbor-scanner-aqua.harbor:8443 as the **Endpoint** URL and click **TEST CONNECTION**.
      ![Add scanner](docs/images/harbor_ui_add_scanner.png)
   3. If everything is fine click **ADD** to save the configuration.
4. Select the **Aqua** scanner and set it as default by clicking **SET AS DEFAULT**.
   ![Set default scanner](docs/images/harbor_ui_default_scanner.png)
   Make sure that the **Default** label is displayed next to the **Aqua** scanner's name.

## Configuration

Configuration of the adapter is done via environment variables at startup.

|              Name             |  Default |                                 Description                               |
|-------------------------------|----------|---------------------------------------------------------------------------|
| `SCANNER_LOG_LEVEL`           | `info`   | The log level of `trace`, `debug`, `info`, `warn`, `warning`, `error`, `fatal` or `panic`. The standard logger logs entries with that level or anything above it. |
| `SCANNER_API_ADDR`            | `:8080`  | Binding address for the API HTTP server                                   |
| `SCANNER_API_TLS_CERTIFICATE` |          | The absolute path to the x509 certificate file                            |
| `SCANNER_API_TLS_KEY`         |          | The absolute path to the x509 private key file                            |
| `SCANNER_API_READ_TIMEOUT`    | `15s`    | The maximum duration for reading the entire request, including the body   |
| `SCANNER_API_WRITE_TIMEOUT`   | `15s`    | The maximum duration before timing out writes of the response             |
| `SCANNER_API_IDLE_TIMEOUT`    | `60s`    | The maximum amount of time to wait for the next request when keep-alives are enabled |
| `SCANNER_AQUA_USERNAME`       | N/A      | Aqua management console username (required)                               |
| `SCANNER_AQUA_PASSWORD`       | N/A      | Aqua management console password (required)                               |
| `SCANNER_AQUA_HOST`           | `http://csp-console-svc.aqua:8080` | Aqua management console address                 |
| `SCANNER_AQUA_REGISTRY`       | `Harbor` | The name of the Harbor registry configured in Aqua management console     |
| `SCANNER_AQUA_REPORTS_DIR`    | `/var/lib/scanner/reports` | Directory to save temporary scan reports                |
| `SCANNER_AQUA_USE_IMAGE_TAG`  | `true`  | The flag to determine whether the image tag or digest is used in the image reference passed to `scannercli` |
| `SCANNER_STORE_REDIS_URL`             | `redis://harbor-harbor-redis:6379` | Redis server URI for a redis store      |
| `SCANNER_STORE_REDIS_NAMESPACE`       | `harbor.scanner.aqua:store` | A namespace for keys in a redis store          |
| `SCANNER_STORE_REDIS_POOL_MAX_ACTIVE` | `5`  | The max number of connections allocated by the pool for a redis store |
| `SCANNER_STORE_REDIS_POOL_MAX_IDLE`   | `5`  | The max number of idle connections in the pool for a redis store      |
| `SCANNER_STORE_REDIS_SCAN_JOB_TTL`    | `1h` | The time to live for persisting scan jobs and associated scan reports |

## License

This project is licensed under the Apache 2.0 license - see the [LICENSE](LICENSE) file for details.

[release-img]: https://img.shields.io/github/release/aquasecurity/harbor-scanner-aqua.svg
[release]: https://github.com/aquasecurity/harbor-scanner-aqua/releases
[build-action-img]: https://github.com/aquasecurity/harbor-scanner-aqua/workflows/build/badge.svg
[build-action]: https://github.com/aquasecurity/harbor-scanner-aqua/actions
[codecov-img]: https://codecov.io/gh/aquasecurity/harbor-scanner-aqua/branch/master/graph/badge.svg
[codecov]: https://codecov.io/gh/aquasecurity/harbor-scanner-aqua
[report-card-img]: https://goreportcard.com/badge/github.com/aquasecurity/harbor-scanner-aqua
[report-card]: https://goreportcard.com/report/github.com/aquasecurity/harbor-scanner-aqua
[license-img]: https://img.shields.io/github/license/aquasecurity/harbor-scanner-aqua.svg
[license]: https://github.com/aquasecurity/harbor-scanner-aqua/blob/master/LICENSE
[minikube-url]: https://github.com/kubernetes/minikube
[harbor-url]: https://github.com/goharbor/harbor
[image-vulnerability-scanning-proposal]: https://github.com/goharbor/community/blob/master/proposals/pluggable-image-vulnerability-scanning_proposal.md
[k8s-init-containers]: https://kubernetes.io/docs/concepts/workloads/pods/init-containers/
[k8s-volume-emptyDir]: https://kubernetes.io/docs/concepts/storage/volumes/#emptydir
[aqua-docs-scanner-binary]: https://read.aquasec.com/docs/aqua-scanner-executable-binary
