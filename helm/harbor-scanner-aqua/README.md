# Harbor Scanner Aqua

Aqua Enterprise Scanner as a plug-in vulnerability scanner in the Harbor registry.

## TL;DR;

```
$ helm repo add aqua https://helm.aquasec.com
```

### Without TLS

```
$ helm install harbor-scanner-aqua aqua/harbor-scanner-aqua \
    --namespace harbor \
    --set aqua.version=$AQUA_VERSION \
    --set aqua.registry.server=registry.aquasec.com \
    --set aqua.registry.username=$AQUA_REGISTRY_USERNAME \
    --set aqua.registry.password=$AQUA_REGISTRY_PASSWORD \
    --set scanner.aqua.username=$AQUA_CONSOLE_USERNAME \
    --set scanner.aqua.password=$AQUA_CONSOLE_PASSWORD \
    --set scanner.aqua.host=http://csp-console-svc.aqua:8080
```

### With TLS

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
   $ helm install harbor-scanner-aqua aqua/harbor-scanner-aqua \
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

## Introduction

This chart bootstraps a scanner adapter deployment on a [Kubernetes](http://kubernetes.io) cluster using the
[Helm](https://helm.sh) package manager.

## Prerequisites

- Kubernetes 1.12+
- Helm 2.11+ or Helm 3+
- Add Aqua chart repository:
  ```
  $ helm repo add aqua https://helm.aquasec.com
  ```

## Installing the Chart

To install the chart with the release name `my-release`:

```
$ helm install my-release aqua/harbor-scanner-aqua
```

The command deploys scanner adapter on the Kubernetes cluster in the default configuration. The [Parameters](#parameters)
section lists the parameters that can be configured during installation.

> **Tip**: List all releases using `helm list`.

## Uninstalling the Chart

To uninstall/delete the `my-release` deployment:

```
$ helm delete my-release
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

## Parameters

The following table lists the configurable parameters of the scanner adapter chart and their default values.

| Parameter                                            | Description                                                                                                                                                                                                           | Default                            |
|------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------|
| `aqua.version`                                       | The version of Aqua Enterprise that the adapter operates against                                                                                                                                                      | `5.0`                              |
| `aqua.registry.server`                               | Aqua Docker registry server                                                                                                                                                                                           | `registry.aquasec.com`             |
| `aqua.registry.username`                             | Aqua Docker registry username                                                                                                                                                                                         | N/A                                |
| `aqua.registry.password`                             | Aqua Docker registry password                                                                                                                                                                                         | N/A                                |
| `scanner.image.registry`                             | Image registry                                                                                                                                                                                                        | `docker.io`                        |
| `scanner.image.repository`                           | Image name                                                                                                                                                                                                            | `aquasec/harbor-scanner-aqua`      |
| `scanner.image.tag`                                  | Image tag                                                                                                                                                                                                             | `{TAG_NAME}`                       |
| `scanner.image.pullPolicy`                           | Image pull policy                                                                                                                                                                                                     | `IfNotPresent`                     |
| `scanner.logLevel`                                   | The log level of `trace`, `debug`, `info`, `warn`, `warning`, `error`, `fatal` or `panic`. The standard logger logs entries with that level or anything above it                                                      | `info`                             |
| `scanner.aqua.username`                              | Aqua management console username (required)                                                                                                                                                                           | N/A                                |
| `scanner.aqua.password`                              | Aqua management console password (required)                                                                                                                                                                           | N/A                                |
| `scanner.aqua.host`                                  | Aqua management console address                                                                                                                                                                                       | `http://csp-console-svc.aqua:8080` |
| `scanner.aqua.registry`                              | The name of the Harbor registry configured in Aqua management console                                                                                                                                                 | `Harbor`                           |
| `scanner.aqua.scannerCLINoVerify`                    | The flag passed to `scannercli` to skip verifying TLS certificates                                                                                                                                                    | `false`                            |
| `scanner.aqua.scannerCLIShowNegligible`              | The flag passed to `scannercli` to show negligible/unknown severity vulnerabilities                                                                                                                                   | `true`                             |
| `scanner.aqua.scannerCLIOverrideRegistryCredentials` | The flag to enable passing `--robot-username` and `--robot-password` flags to the `scannercli` executable binary                                                                                                      | `false`                            |
| `scanner.aqua.scannerCLIDirectCC`                    | The flag passed to `scannercli` to contact CyberCenter directly (rather than through the Aqua server)                                                                                                                 | `false`                            |
| `scanner.aqua.scannerCLIRegisterImages`              | The flag to determine whether images are registered in Aqua management console: `Never` - skips registration; `Compliant` - registers only compliant images; `Always` - registers compliant and non-compliant images. | `Never`                            |
| `scanner.aqua.reportsDir`                            | Directory to save temporary scan reports                                                                                                                                                                              | `/var/lib/scanner/reports`         |
| `scanner.aqua.useImageTag`                           | The flag to determine whether the image tag or digest is used in the image reference passed to `scannercli`                                                                                                           | `false`                            |
| `scanner.api.tlsEnabled`                             | The flag to enable or disable TLS for HTTP                                                                                                                                                                            | `true`                             |
| `scanner.api.tlsCertificate`                         | The absolute path to the x509 certificate file                                                                                                                                                                        |                                    |
| `scanner.api.tlsKey`                                 | The absolute path to the x509 private key file                                                                                                                                                                        |                                    |
| `scanner.api.readTimeout`                            | The maximum duration for reading the entire request, including the body                                                                                                                                               | `15s`                              |
| `scanner.api.writeTimeout`                           | The maximum duration before timing out writes of the response                                                                                                                                                         | `15s`                              |
| `scanner.api.idleTimeout`                            | The maximum amount of time to wait for the next request when keep-alives are enabled                                                                                                                                  | `60s`                              |
| `scanner.store.redisNamespace`                       | The namespace for keys in the Redis store                                                                                                                                                                             | `harbor.scanner.aqua:store`        |
| `scanner.store.redisScanJobTTL`                      | The time to live for persisting scan jobs and associated scan reports                                                                                                                                                 | `1h`                               |
| `scanner.redis.poolURL`                              | The server URI for the Redis store                                                                                                                                                                                    | `redis://harbor-harbor-redis:6379` |
| `scanner.redis.poolMaxActive`                        | The max number of connections allocated by the pool for the Redis store                                                                                                                                               | `5`                                |
| `scanner.redis.poolMaxIdle`                          | The max number of idle connections in the pool for the Redis store                                                                                                                                                    | `5`                                |
| `scanner.redis.poolpIdleTimeout`                     | The duration after which idle connections to the Redis server are closed. If the value is zero, then idle connections are not closed.                                                                                 | `5m`                               |
| `scanner.redis.poolConnectionTimeout`                | The timeout for connecting to the Redis server                                                                                                                                                                        | `1s`                               |
| `scanner.redis.poolReadTimeout`                      | The timeout for reading a single Redis command reply                                                                                                                                                                  | `1s`                               |
| `scanner.redis.poolWriteTimeout`                     | The timeout for writing a single Redis command                                                                                                                                                                        | `1s`                               |
| `service.type`                                       | Kubernetes service type                                                                                                                                                                                               | `ClusterIP`                        |
| `service.port`                                       | Kubernetes service port                                                                                                                                                                                               | `8080`                             |
| `replicaCount`                                       | The number of scanner adapter Pods to run                                                                                                                                                                             | `1`                                |

The above parameters map to the env variables defined in [harbor-scanner-aqua](https://github.com/aquasecurity/harbor-scanner-aqua#configuration).

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install`.

```
$ helm install my-release aqua/harbor-scanner-aqua \
    --namespace my-namespace \
    --set scanner.aqua.username=$AQUA_CONSOLE_USERNAME \
    --set scanner.aqua.password=$AQUA_CONSOLE_PASSWORD
```
