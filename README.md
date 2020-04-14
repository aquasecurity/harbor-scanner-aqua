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
- [How does it work?](#how-does-it-work)
- [Getting started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Build](#build)
  - [Running on Kubernetes](#running-on-kubernetes)
- [Deployment](#deployment)
  - [Kubernetes](#kubernetes)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Requirements

1. Harbor >= 1.10
2. This adapter requires Aqua CSP >= 4.5 deployment to operate against. The adapter can be deployed before the Aqua CSP
   installation, but the Aqua CSP management console URL and credentials must be known to configure the adapter with
   the [environment variables](#configuration).
3. The adapter service requires the `scannercli` executable binary, in version matching the Aqua CSP, to be mounted
   at `/usr/local/bin/scannercli`. The provided Helm chart mounts the `scannercli` executable automatically by pulling
   the `registry.aquasec.com/scanner:$AQUA_CSP_VERSION` image from Aqua Registry and running it as an [init container][k8s-init-containers].
   The init container's command is configured to copy the executable from the container's filesystem to an [emptyDir][k8s-volume-emptyDir]
   volume, which is shared with the main container. This makes the `scannercli` executable available to the main container at
   `/usr/local/bin/scannercli`.

   > **NOTE**: Make sure that you provide valid Aqua Registry credentials received from Aqua Security as Helm values
   > in order to create the corresponding image pull secret.

   If you're not using Kubernetes to run the adapter service, you have to download the `scannercli` executable from the
   Aqua downloads page manually and mount it at `/usr/local/bin/scannercli`.
   See [Aqua Scanner Executable Binary][aqua-docs-scanner-binary] for more details on manual download.
4. It is highly recommended to create a new user in the Aqua CSP management console with credentials dedicated to the
   Harbor adapter, e.g. `harbor_scanner`. The adapter does not need full access to Aqua: the `Scanner` role is the only permission
   required for the `scannercli` executable binary which is run by the adapter service on each scan request.
   Therefore, create your `harbor_scanner` user and assign it only the `Scanner` role. 

   ![](docs/images/aqua_user_for_harbor.png)
5. It is also highly recommended to create a new user in Harbor for the Aqua CSP scanner, with permission only to pull images from Harbor, e.g. `aqua_scanner`. Please remember to add this user as a member of the project in Harbor that you intend to
   scan the images from.

   ![](docs/images/harbor_user_for_aqua.png)
6. Finally add a new Harbor registry integration in Aqua CSP management console and use the credentials of the user
   created in the previous step. Please note that the value of the **Registry Name** field corresponds to the
   `SCANNER_AQUA_REGISTRY` [configuration](#configuration) variable.

   ![](docs/images/adding_harbor_registry_in_aqua.png)

## How does it work?

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

Finally, the output report is transformed to Harbor model and display in Harbor UI.

## Getting started

These instructions will get you a copy of the adapter service up and running on your local
machine for development and testing purposes. See [deployment](#deployment) for notes on
how to deploy on a live system.

### Prerequisites

* [Go (version 1.13+)](https://golang.org/doc/devel/release.html#go1.13)
* Docker
* Harbor >= 1.10
* Aqua CSP >= 4.5

### Build

Run `make` to build the binary in `./scanner-adapter`:

```
$ make
```

To build into a Docker container:

```
$ make build-image
```

### Running on Kubernetes

> In the following instructions I assume that you installed Harbor >= 1.10 with [Helm chart for Harbor][harbor-helm-chart]
> in the `harbor` namespace, and it's accessible at https://core.harbor.domain.
> ```
> $ helm repo add harbor https://helm.goharbor.io
> $ kubectl create namespace harbor
> $ helm install harbor harbor/harbor --version $HARBOR_VERSION \
>     --namespace harbor \
>     --set clair-enabled=false
> ```
>
> I also assume that you installed Aqua CSP >= 4.5 with [Aqua Security Helm charts][aqua-helm-chart] in the `aqua`
> namespace, and the management console is accessible at http://csp-console-svc.aqua:8080 from within the cluster.
> ```
> $ helm repo add aqua-helm https://helm.aquasec.com
> $ kubectl create namespace aqua
> $ helm install csp aqua-helm/server --version $AQUA_VERSION \
>     --namespace aqua \
>     --set imageCredentials.repositoryUriPrefix="registry.aquasec.com" \
>     --set imageCredentials.registry="registry.aquasec.com" \
>     --set imageCredentials.username=$AQUA_REGISTRY_USERNAME \
>     --set imageCredentials.password=$AQUA_REGISTRY_PASSWORD \
>     --set admin.token=$AQUA_ADMIN_TOKEN \
>     --set admin.password=$AQUA_ADMIN_PASSWORD
>     --set scanner.enabled="true" \
>     --set scanner.replicaCount=1 \
>     --set scanner.user=$SCANNER_USER \
>     --set scanner.password=$SCANNER_PASSWORD
> ```

1. Set up environment for the Docker client:
   ```
   $ eval $(minikube docker-env)
   ```
2. Build a Docker image `aquasec/harbor-scanner-aqua:dev`:
   ```
   $ make docker-build
   ```
3. Install the `harbor-scanner-aqua` release with `helm` in the `harbor` namespace:
   ```
   $ helm install harbor-scanner-aqua ./helm/harbor-scanner-aqua \
       --namespace harbor \
       --set aqua.version=$AQUA_VERSION \
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

> I assume that you installed Aqua CSP >= 4.5 with [Aqua Security Helm charts][aqua-helm-chart] in the `aqua`
> namespace, and the management console is accessible at http://csp-console-svc.aqua:8080 from within the cluster.

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
       --set aqua.version=$AQUA_VERSION \
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
   Make sure the **Default** label is displayed next to the **Aqua** scanner's name.

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
| `SCANNER_CLI_NO_VERIFY`       | `false` | The flag passed to `scannercli` to skip verifying TLS certificates         |
| `SCANNER_CLI_SHOW_NEGLIGIBLE` | `true`  | The flag passed to `scannercli` to show negligible/unknown severity vulnerabilities |
| `SCANNER_STORE_REDIS_URL`             | `redis://harbor-harbor-redis:6379` | Redis server URI for a redis store      |
| `SCANNER_STORE_REDIS_NAMESPACE`       | `harbor.scanner.aqua:store` | A namespace for keys in a redis store          |
| `SCANNER_STORE_REDIS_POOL_MAX_ACTIVE` | `5`  | The max number of connections allocated by the pool for a redis store |
| `SCANNER_STORE_REDIS_POOL_MAX_IDLE`   | `5`  | The max number of idle connections in the pool for a redis store      |
| `SCANNER_STORE_REDIS_SCAN_JOB_TTL`    | `1h` | The time to live for persisting scan jobs and associated scan reports |

## Troubleshooting

### Error: failed getting image manifest: 412 Precondition Failed

Currently, there's a limitation of `scannercli` which does not accept Harbor robot account credentials passed by a
Harbor scan job to the adapter service. This effectively means that the Aqua CSP scanner is using the credentials
provided in Aqua CSP management console under the **Integrations** / **Image Registries** section. However, these
credentials do not have enough permissions to bypass deployment security checker when it's enabled in the Harbor
project configuration.
 
![](docs/images/harbor_deployment_security.png)

The only available solution to that problem is disabling deployment security checks in Harbor.

> We're working with the Harbor team on the [enhancement to robot accounts](https://github.com/goharbor/harbor/issues/11574).

## Contributing

Please read [CODE_OF_CONDUCT.md][coc-url] for details on our code of conduct, and the process for submitting pull
requests.

## License

This project is licensed under the [Apache 2.0](LICENSE).

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
[harbor-url]: https://github.com/goharbor/harbor
[harbor-helm-chart]: https://github.com/goharbor/harbor-helm
[image-vulnerability-scanning-proposal]: https://github.com/goharbor/community/blob/master/proposals/pluggable-image-vulnerability-scanning_proposal.md
[k8s-init-containers]: https://kubernetes.io/docs/concepts/workloads/pods/init-containers/
[k8s-volume-emptyDir]: https://kubernetes.io/docs/concepts/storage/volumes/#emptydir
[aqua-docs-scanner-binary]: https://read.aquasec.com/docs/aqua-scanner-executable-binary
[aqua-helm-chart]: https://github.com/aquasecurity/aqua-helm
[coc-url]: https://github.com/aquasecurity/.github/blob/master/CODE_OF_CONDUCT.md
