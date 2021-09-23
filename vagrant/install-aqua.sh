#! /bin/bash

if [ -z "$AQUA_REGISTRY_USERNAME" ]; then echo "AQUA_REGISTRY_USERNAME is unset" && exit 1; fi
if [ -z "$AQUA_REGISTRY_PASSWORD" ]; then echo "AQUA_REGISTRY_PASSWORD is unset" && exit 1; fi
if [ -z "$AQUA_VERSION" ]; then echo "AQUA_VERSION is unset" && exit 1; else echo "AQUA_VERSION is set to '$AQUA_VERSION'"; fi

HARBOR_HOME="/opt/harbor"
HARBOR_SCANNER_AQUA_VERSION="0.11.2"

SCANNER_UID=1000
SCANNER_GID=1000

mkdir -p $HARBOR_HOME/common/config/aqua-adapter
mkdir -p /data/aqua-adapter/reports
mkdir -p /data/aqua-adapter/opt
mkdir -p /var/lib/aqua-db/data

chown $SCANNER_UID:$SCANNER_GID /data/aqua-adapter/reports
chown $SCANNER_UID:$SCANNER_GID /data/aqua-adapter/opt

echo $AQUA_REGISTRY_PASSWORD | docker login registry.aquasec.com --username $AQUA_REGISTRY_USERNAME --password-stdin

docker run --rm --entrypoint "" \
  -v $HARBOR_HOME/common/config/aqua-adapter:/out registry.aquasec.com/scanner:$AQUA_VERSION \
  cp /opt/aquasec/scannercli /out

chown $SCANNER_UID:$SCANNER_GID $HARBOR_HOME/common/config/aqua-adapter/scannercli

cat << EOF > $HARBOR_HOME/common/config/aqua-adapter/env
SCANNER_LOG_LEVEL=debug
SCANNER_AQUA_USERNAME=administrator
SCANNER_AQUA_PASSWORD=@Aqua12345
SCANNER_AQUA_HOST=http://aqua-console:8080
SCANNER_AQUA_REGISTRY=Harbor
SCANNER_AQUA_USE_IMAGE_TAG=false
SCANNER_AQUA_REPORTS_DIR=/var/lib/scanner/reports
SCANNER_STORE_REDIS_URL=redis://redis:6379
SCANNER_CLI_OVERRIDE_REGISTRY_CREDENTIALS=false
EOF

cat << EOF > $HARBOR_HOME/docker-compose.override.yml
version: '2.3'
services:
  aqua-adapter:
    networks:
      - harbor
    container_name: aqua-adapter
    # image: docker.io/aquasec/harbor-scanner-aqua:dev
    # image: docker.io/aquasec/harbor-scanner-aqua:$HARBOR_SCANNER_AQUA_VERSION
    image: public.ecr.aws/aquasecurity/harbor-scanner-aqua:$HARBOR_SCANNER_AQUA_VERSION
    restart: always
    cap_drop:
      - ALL
    depends_on:
      - redis
    volumes:
      - type: bind
        source: $HARBOR_HOME/common/config/aqua-adapter/scannercli
        target: /usr/local/bin/scannercli
      - type: bind
        source: /data/aqua-adapter/reports
        target: /var/lib/scanner/reports
      - type: bind
        source: /data/aqua-adapter/opt
        target: /opt/aquascans
    logging:
      driver: "syslog"
      options:
        syslog-address: "tcp://127.0.0.1:1514"
        tag: "aqua-adapter"
    env_file:
      $HARBOR_HOME/common/config/aqua-adapter/env
  aqua-db:
    networks:
      - harbor
    image: registry.aquasec.com/database:$AQUA_VERSION
    container_name: aqua-db
    environment:
      - POSTGRES_PASSWORD=lunatic0
    volumes:
      - /var/lib/aqua-db/data:/var/lib/postgresql/data
  aqua-console:
    networks:
      - harbor
    ports:
      - 9080:8080
    image: registry.aquasec.com/console:$AQUA_VERSION
    container_name: aqua-console
    environment:
      - ADMIN_PASSWORD=@Aqua12345
      - SCALOCK_DBHOST=aqua-db
      - SCALOCK_DBNAME=scalock
      - SCALOCK_DBUSER=postgres
      - SCALOCK_DBPASSWORD=lunatic0
      - SCALOCK_AUDIT_DBHOST=aqua-db
      - SCALOCK_AUDIT_DBNAME=slk_audit
      - SCALOCK_AUDIT_DBUSER=postgres
      - SCALOCK_AUDIT_DBPASSWORD=lunatic0
      - AQUA_DOCKERLESS_SCANNING=1
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    depends_on:
      - aqua-db
  aqua-gateway:
    image: registry.aquasec.com/gateway:$AQUA_VERSION
    container_name: aqua-gateway
    environment:
      - SCALCOK_LOG_LEVEL=DEBUG
      - AQUA_CONSOLE_SECURE_ADDRESS=aqua-console:8443
      - SCALOCK_DBHOST=aqua-db
      - SCALOCK_DBNAME=scalock
      - SCALOCK_DBUSER=postgres
      - SCALOCK_DBPASSWORD=lunatic0
      - SCALOCK_AUDIT_DBHOST=aqua-db
      - SCALOCK_AUDIT_DBNAME=slk_audit
      - SCALOCK_AUDIT_DBUSER=postgres
      - SCALOCK_AUDIT_DBPASSWORD=lunatic0
    networks:
      - harbor
    depends_on:
      - aqua-db
      - aqua-console
EOF

cd /opt/harbor
docker-compose up -d

# Register aqua-adapter as Harbor Interrogation Service.
cat << EOF > /tmp/aqua-adapter.registration.json
{
  "name": "Aqua Enterprise $AQUA_VERSION",
  "url": "http://aqua-adapter:8080"
}
EOF

curl --include \
  --user admin:Harbor12345 \
  --request POST \
  --header "accept: application/json" \
  --header "Content-Type: application/json" \
  --data-binary "@/tmp/aqua-adapter.registration.json" \
  "http://localhost:8080/api/v2.0/scanners"
