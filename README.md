[![GitHub release][release-img]][release]
[![Build Actions][build-action-img]][build-action]
[![Codecov][codecov-img]][codecov]
[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]

# Harbor Scanner Adapter for Aqua CSP Scanner

## TOC

- [Getting started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Build](#build)
  - [Running on minikube](#running-on-minikube)
- [Deployment](#deployment)
  - [Kubernetes](#kubernetes)
- [Configuration](#configuration)
- [License](#license)

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
make container
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
                  --set image.tag=dev \
                  --set scanner.logLevel=trace \
                  --set scanner.aqua.user=$AQUA_USER \
                  --set scanner.aqua.password=$AQUA_PASSWORD \
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
                  --set scanner.aqua.user=$AQUA_USER \
                  --set scanner.aqua.password=$AQUA_PASSWORD \
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
| `SCANNER_AQUA_USER`           | N/A      | Aqua management console username (required)                               |
| `SCANNER_AQUA_PASSWORD`       | N/A      | Aqua management console password (required)                               |
| `SCANNER_AQUA_HOST`           | `http://aqua-web.aqua-security:8080` | Aqua management console address               |
| `SCANNER_AQUA_REGISTRY`       | `Harbor` | The name of the Harbor registry configured in Aqua management console     |
| `SCANNER_AQUA_REPORTS_DIR`    | `/var/lib/scanner/reports` | Directory to save temporary scan reports                |

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
