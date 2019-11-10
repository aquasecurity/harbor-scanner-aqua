[![GitHub release][release-img]][release]
[![Build Actions][build-action-img]][build-action]
[![Codecov][codecov-img]][codecov]
[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]

# Harbor Scanner Adapter for Aqua CSP Scanner

## Configuration

Configuration of the adapter is done via environment variables at startup.

| Name | Default Value | Description |
|------|---------------|-------------|
| `SCANNER_LOG_LEVEL`           | `info`  | The log level of `trace`, `debug`, `info`, `warn`, `warning`, `error`, `fatal` or `panic`. The standard logger logs entries with that level or anything above it. |
| `SCANNER_API_ADDR`            | `:8080` | Binding address for the API HTTP server. |
| `SCANNER_API_TLS_CERTIFICATE` | | The absolute path to the x509 certificate file. |
| `SCANNER_API_TLS_KEY`         | | The absolute path to the x509 private key file. |
| `SCANNER_API_READ_TIMEOUT`    | `15s` | The maximum duration for reading the entire request, including the body. |
| `SCANNER_API_WRITE_TIMEOUT`   | `15s` | The maximum duration before timing out writes of the response. |
| `SCANNER_API_IDLE_TIMEOUT`    | `60s` | The maximum amount of time to wait for the next request when keep-alives are enabled. |

## Deploy to minikube

1. Configure Docker client with Docker Engine in minikube:
   ```
   eval $(minikube docker-env -p harbor)
   ```
2. Build Docker container:
   ```
   make container
   ```
3. Configure adapter to handle TLS traffic:
   1. Generate certificate and private key files:
      ```
      $ openssl genrsa -out tls.key 2048
      $ openssl req -new -x509 \
        -key tls.key \
        -out tls.crt \
        -days 365 \
        -subj /CN=harbor-scanner-aqua
      ```
   2. Create a `tls` secret from the two generated files:
      ```
      $ kubectl create secret tls harbor-scanner-aqua-tls \
        --cert=tls.crt \
        --key=tls.key
      ```
4. Create `harbor-scanner-aqua` deployment and service:
   ```
   kubectl apply -f kube/harbor-scanner-aqua.yaml
   ```
5. If everything is fine you should be able to get scanner's metadata:
   ```
   kubectl port-forward service/harbor-scanner-aqua 8443:8443 &> /dev/null &
   curl -vk https://localhost:8443/api/v1/metadata | jq
   ```

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
