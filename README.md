[![GitHub release][release-img]][release]
[![GitHub Build Action][build-action-img]][actions]
[![GitHub Release Action][release-action-img]][actions]
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
  - [Docker](#docker)
  - [Configuring Harbor scanner](#configuring-harbor-scanner)
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
   Harbor adapter, e.g. `harbor_scanner`. The adapter does not need full access to Aqua: the `Scanner` role is the only
   permission required for the `scannercli` executable binary which is run by the adapter service on each scan request.
   Therefore, create your `harbor_scanner` user and assign it only the `Scanner` role.

   ![](docs/images/aqua_user_for_harbor.png)
5. It is also highly recommended to create a new user in Harbor for the Aqua CSP scanner, with permission only to pull
   images from Harbor, e.g. `aqua_scanner`. Please remember to add this user as a member of the project in Harbor that
   you intend to scan the images from.

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
    --checkonly \
    --dockerless \
    --user=$SCANNER_AQUA_USERNAME \
    --password=$SCANNER_AQUA_PASSWORD \
    --host=$SCANNER_AQUA_HOST \
    --registry=$SCANNER_AQUA_REGISTRY \
    --robot-username=$HARBOR_ROBOT_ACCOUNT_NAME \
    --robot-password=$HARBOR_ROBOT_ACCOUNT_PASSWORD \
    --no-verify=$SCANNER_CLI_NO_VERIFY \
    --jsonfile /var/lib/scanner/reports/aqua_scan_report_0123456789.json \
    library/mongo:3.4-xenial
```

Finally, the output report is transformed to Harbor's model and displayed in the Harbor interface.

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
$ make docker-build
```

### Running on Kubernetes

> In the following instructions I assume that you installed Harbor >= 1.10 with [Helm chart for Harbor][harbor-helm-chart]
> in the `harbor` namespace, and it's accessible at https://core.harbor.domain.
> ```
> $ helm repo add harbor https://helm.goharbor.io
> $ kubectl create namespace harbor
> $ helm install harbor harbor/harbor --version $HARBOR_CHART_VERSION \
>     --namespace harbor \
>     --set clair.enabled=false
> ```
>
> I also assume that you installed Aqua CSP >= 4.5 with [Aqua Security Helm charts][aqua-helm-chart] in the `aqua`
> namespace, and the management console is accessible at http://csp-console-svc.aqua:8080 from within the cluster.
> ```
> $ helm repo add aqua-helm https://helm.aquasec.com
> $ kubectl create namespace aqua
> $ helm install csp aqua-helm/server --version $AQUA_CHART_VERSION \
>     --namespace aqua \
>     --set imageCredentials.repositoryUriPrefix="registry.aquasec.com" \
>     --set imageCredentials.registry="registry.aquasec.com" \
>     --set imageCredentials.username=$AQUA_REGISTRY_USERNAME \
>     --set imageCredentials.password=$AQUA_REGISTRY_PASSWORD \
>     --set admin.token=$AQUA_ADMIN_TOKEN \
>     --set admin.password=$AQUA_ADMIN_PASSWORD \
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

Harbor can be [installed as a Docker service][harbor-docs-installer] or deployed with [high availability via Helm][harbor-docs-helm].
This section describes how to perform a new installation of the adapter service in both cases.

It's also possible to deploy Harbor on Docker (outside the Kubernetes environment) to work with Aqua CSP on Kubernetes, and you should be able to figure
it out based on the following instructions.

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
   The scanner service should be accessible at https://harbor-scanner-aqua.harbor:8443 from within the cluster.
3. [Connect Harbor to Aqua scanner.](#configuring-harbor-scanner)

### Docker

> I assume that you installed Harbor >= 1.10 with an online or offline installer script in the `$HARBOR_HOME` directory,
> and it's accessible at https://harbor.domain.
>
> I also assume that you installed Aqua CSP >= 4.5, and the management console is accessible at https://aqua.domain.

1. Change directory to `$HARBOR_HOME`:
   ```
   $ cd $HARBOR_HOME
   ```
2. Create the config and data directories for the adapter service:
   ```
   $ mkdir -p ./common/config/aqua-scanner
   $ mkdir -p ./data/aqua-scanner/reports
   $ mkdir -p ./data/aqua-scanner/opt
   ```
3. Generate certificate and private key files:
   ```
   $ mkdir -p ./common/config/aqua-scanner/cert
   $ openssl genrsa -out ./common/config/aqua-scanner/cert/aqua-scanner.key 2048
   $ openssl req -new -x509 \
       -key ./common/config/aqua-scanner/cert/aqua-scanner.key \
       -out ./common/config/aqua-scanner/cert/aqua-scanner.crt \
       -days 365 \
       -subj /CN=aqua-scanner
   ```
4. Create the `env` file to configure the adapter service:
   ```
   $ cat << EOF > ./common/config/aqua-scanner/env
   SCANNER_LOG_LEVEL=info
   SCANNER_API_ADDR=:8443
   SCANNER_API_TLS_KEY=/cert/aqua-scanner.key
   SCANNER_API_TLS_CERTIFICATE=/cert/aqua-scanner.crt
   SCANNER_AQUA_USERNAME=$AQUA_CONSOLE_USERNAME
   SCANNER_AQUA_PASSWORD=$AQUA_CONSOLE_PASSWORD
   SCANNER_AQUA_HOST=https://aqua.domain
   SCANNER_AQUA_REGISTRY=Harbor
   SCANNER_AQUA_REPORTS_DIR=/var/lib/scanner/reports
   SCANNER_STORE_REDIS_URL=redis://redis:6379
   EOF
   ```
5. Download the `scannercli` executable binary
   1. You can download the binary from the [docs][download-scannercli] page and save it to `$HARBOR_HOME/scannercli`
   2. Alternatively you can use the `registry.aquasec.com/scanner` image to copy the `scannercli` binary from the container's file system:
      ```
      $ echo $AQUA_REGISTRY_PASSWORD | docker login registry.aquasec.com \
          -u $AQUA_REGISTRY_USERNAME --password-stdin
      $ docker run --rm --entrypoint "" \
          -v $HARBOR_HOME:/out registry.aquasec.com/scanner:$AQUA_VERSION \
          cp /opt/aquasec/scannercli /out
      ```
6. Create the `docker-compose.override.yml` to install the adapter service:
   ```
   $ cat << EOF > ./docker-compose.override.yml
   version: '2.3'
   services:
     aqua-scanner:
       networks:
         - harbor
       container_name: aqua-scanner
       image: docker.io/aquasec/harbor-scanner-aqua:$HARBOR_SCANNER_AQUA_VERSION
       restart: always
       cap_drop:
         - ALL
       depends_on:
         - redis
       volumes:
         - type: bind
           source: ./scannercli
           target: /usr/local/bin/scannercli
         - type: bind
           source: ./common/config/aqua-scanner/cert
           target: /cert
         - type: bind
           source: ./data/aqua-scanner/reports
           target: /var/lib/scanner/reports
         - type: bind
           source: ./data/aqua-scanner/opt
           target: /opt/aquascans
       logging:
         driver: "syslog"
         options:
           syslog-address: "tcp://127.0.0.1:1514"
           tag: "aqua-scanner"
       env_file:
         ./common/config/aqua-scanner/env
   EOF
   ```
7. For some Docker drivers you might need to explicitly set ownership of config files and data directories to user and
   group which runs the adapter process, i.e. `1000:1000`:
   ```
   $ sudo chown 1000:1000 ./data/aqua-scanner/reports
   $ sudo chown 1000:1000 ./data/aqua-scanner/opt
   $ sudo chown 1000:1000 ./common/config/aqua-scanner/cert/aqua-scanner.key
   $ sudo chown 1000:1000 ./common/config/aqua-scanner/cert/aqua-scanner.key
   $ sudo chmod +x ./scannercli && sudo chown 1000:1000 ./scannercli
   ```
8. Start the adapter service:
   ```
   $ docker-compose up -d
   ```
   The scanner service should be accessible at https://aqua-scanner:8443 from within the `harbor` Docker network.
9. [Connect Harbor to Aqua scanner.](#configuring-harbor-scanner)

### Configuring Harbor scanner

1. Log in to the Harbor interface with an account that has Harbor system administrator privileges.
2. Expand **Administration**, and select **Interrogation Services**.
   ![Scanners config](docs/images/harbor_ui_scanners_config.png)
3. Click the **NEW SCANNER** button.
4. Enter the information to identify the scanner.
   1. A unique name for this scanner instance, to display in the Harbor interface.
   2. The API endpoint of the adapter service

   **NOTE**: For the adapter deployed on Kubernetes the URL is https://harbor-scanner-aqua.harbor:8443.
   For Docker, it's https://aqua-scanner:8443

   ![Add scanner](docs/images/harbor_ui_add_scanner.png)
   3. Optionally select **Skip certificate verification** if the scanner uses a self-signed or untrusted certificate.
5. Click **TEST CONNECTION** to make sure that Harbor can connect successfully to the scanner.
6. If everything is fine click **ADD** to save the configuration and connect Harbor to the scanner.
7. If you configured multiple scanners, you can designate the Aqua CSP scanner as the default one by selecting it and
   clicking **SET AS DEFAULT**.
   ![Set default scanner](docs/images/harbor_ui_default_scanner.png)
   Make sure the **Default** label is displayed next to the **Aqua** scanner's name.

## Configuration

Configuration of the adapter is done via environment variables at startup.

|                  Name                       |  Default |                                 Description                               |
|---------------------------------------------|----------|---------------------------------------------------------------------------|
| `SCANNER_LOG_LEVEL`                         | `info`   | The log level of `trace`, `debug`, `info`, `warn`, `warning`, `error`, `fatal` or `panic`. The standard logger logs entries with that level or anything above it. |
| `SCANNER_API_ADDR`                          | `:8080`  | Binding address for the API HTTP server                                   |
| `SCANNER_API_TLS_CERTIFICATE`               |          | The absolute path to the x509 certificate file                            |
| `SCANNER_API_TLS_KEY`                       |          | The absolute path to the x509 private key file                            |
| `SCANNER_API_READ_TIMEOUT`                  | `15s`    | The maximum duration for reading the entire request, including the body   |
| `SCANNER_API_WRITE_TIMEOUT`                 | `15s`    | The maximum duration before timing out writes of the response             |
| `SCANNER_API_IDLE_TIMEOUT`                  | `60s`    | The maximum amount of time to wait for the next request when keep-alives are enabled |
| `SCANNER_AQUA_USERNAME`                     | N/A      | Aqua management console username (required)                               |
| `SCANNER_AQUA_PASSWORD`                     | N/A      | Aqua management console password (required)                               |
| `SCANNER_AQUA_HOST`                         | `http://csp-console-svc.aqua:8080` | Aqua management console address                 |
| `SCANNER_AQUA_REGISTRY`                     | `Harbor` | The name of the Harbor registry configured in Aqua management console     |
| `SCANNER_AQUA_REPORTS_DIR`                  | `/var/lib/scanner/reports` | Directory to save temporary scan reports                |
| `SCANNER_AQUA_USE_IMAGE_TAG`                | `true`   | The flag to determine whether the image tag or digest is used in the image reference passed to `scannercli` |
| `SCANNER_CLI_NO_VERIFY`                     | `false`  | The flag passed to `scannercli` to skip verifying TLS certificates         |
| `SCANNER_CLI_OVERRIDE_REGISTRY_CREDENTIALS` | `false`  | The flag to enable passing `--robot-username` and `--robot-password` flags to the `scannercli` executable binary |
| `SCANNER_STORE_REDIS_URL`                   | `redis://harbor-harbor-redis:6379` | Redis server URI for a redis store      |
| `SCANNER_STORE_REDIS_NAMESPACE`             | `harbor.scanner.aqua:store` | A namespace for keys in a redis store          |
| `SCANNER_STORE_REDIS_POOL_MAX_ACTIVE`       | `5`      | The max number of connections allocated by the pool for a redis store |
| `SCANNER_STORE_REDIS_POOL_MAX_IDLE`         | `5`      | The max number of idle connections in the pool for a redis store      |
| `SCANNER_STORE_REDIS_SCAN_JOB_TTL`          | `1h`     | The time to live for persisting scan jobs and associated scan reports |

## Troubleshooting

### Error: failed getting image manifest: 412 Precondition Failed

Currently, there's a limitation of `scannercli` in Aqua CSP version < **TBD** which does not accept Harbor robot account
credentials passed by a Harbor scan job to the adapter service. This effectively means that the Aqua CSP scanner is
using the credentials provided in Aqua CSP management console under the **Integrations** / **Image Registries** section.
However, these credentials do not have enough permissions to bypass the deployment security checker when it's enabled in
the Harbor project configuration. In other words, the deployment security checker prevents the Aqua CSP scanner from
pulling an image, which it needs to be able to do in order to scan it.

![](docs/images/harbor_deployment_security.png)

The available solution depends on the version of your Aqua CSP deployment. In `scannercli` version >= **TBD** we've
introduced new `--rebot-username` and `--robot-password` args to respect credentials provided by Harbor.

- For Aqua CSP version < **TBD** you can only disable deployment security checks in the Harbor interface under the
  project configuration.
- For Aqua CSP version >= **TBD** set the value of the `SCANNER_CLI_OVERRIDE_REGISTRY_CREDENTIALS` env to `true`.

## Contributing

Please read [CODE_OF_CONDUCT.md][coc-url] for details on our code of conduct, and the process for submitting pull
requests.

## License

This project is licensed under the [Apache 2.0](LICENSE).

[release-img]: https://img.shields.io/github/release/aquasecurity/harbor-scanner-aqua.svg?logo=github
[release]: https://github.com/aquasecurity/harbor-scanner-aqua/releases
[build-action-img]: https://github.com/aquasecurity/harbor-scanner-aqua/workflows/build/badge.svg
[release-action-img]: https://github.com/aquasecurity/harbor-scanner-aqua/workflows/release/badge.svg
[actions]: https://github.com/aquasecurity/harbor-scanner-aqua/actions
[codecov-img]: https://codecov.io/gh/aquasecurity/harbor-scanner-aqua/branch/master/graph/badge.svg
[codecov]: https://codecov.io/gh/aquasecurity/harbor-scanner-aqua
[report-card-img]: https://goreportcard.com/badge/github.com/aquasecurity/harbor-scanner-aqua
[report-card]: https://goreportcard.com/report/github.com/aquasecurity/harbor-scanner-aqua
[license-img]: https://img.shields.io/github/license/aquasecurity/harbor-scanner-aqua.svg
[license]: https://github.com/aquasecurity/harbor-scanner-aqua/blob/master/LICENSE
[harbor-url]: https://github.com/goharbor/harbor
[harbor-helm-chart]: https://github.com/goharbor/harbor-helm
[harbor-docs-installer]: https://goharbor.io/docs/1.10/install-config/download-installer/
[harbor-docs-helm]: https://goharbor.io/docs/1.10/install-config/harbor-ha-helm/
[image-vulnerability-scanning-proposal]: https://github.com/goharbor/community/blob/master/proposals/pluggable-image-vulnerability-scanning_proposal.md
[k8s-init-containers]: https://kubernetes.io/docs/concepts/workloads/pods/init-containers/
[k8s-volume-emptyDir]: https://kubernetes.io/docs/concepts/storage/volumes/#emptydir
[aqua-docs-scanner-binary]: https://read.aquasec.com/docs/aqua-scanner-executable-binary
[aqua-helm-chart]: https://github.com/aquasecurity/aqua-helm
[download-scannercli]: https://read.aquasec.com/docs/aqua-scanner-command-line#section-obtain-the-scanner-executable-binary
[coc-url]: https://github.com/aquasecurity/.github/blob/master/CODE_OF_CONDUCT.md
