#! /bin/bash

if [ -z "$HARBOR_VERSION" ]; then echo "HARBOR_VERSION env is unset"; else echo "HARBOR_VERSION env is set to '$HARBOR_VERSION'"; fi

HARBOR_HOME="/opt/harbor"

# Download the offline Harbor installer.
# We prefer offline installer to avoid DockerHub rate limits.
wget --quiet https://github.com/goharbor/harbor/releases/download/$HARBOR_VERSION/harbor-offline-installer-$HARBOR_VERSION.tgz

# Download the corresponding *.asc file to verify that the package is genuine.
wget --quiet https://github.com/goharbor/harbor/releases/download/$HARBOR_VERSION/harbor-offline-installer-$HARBOR_VERSION.tgz.asc

# Obtain the public key for the *.asc file.
gpg --keyserver hkps://keyserver.ubuntu.com --receive-keys 644FF454C0B4115C

# Verify that the installer package is genuine.
gpg --verbose --keyserver hkps://keyserver.ubuntu.com --verify harbor-offline-installer-$HARBOR_VERSION.tgz.asc

tar -C /opt -xzf harbor-offline-installer-$HARBOR_VERSION.tgz

rm harbor-offline-installer-$HARBOR_VERSION.tgz
rm harbor-offline-installer-$HARBOR_VERSION.tgz.asc
rm $HARBOR_HOME/harbor.yml.tmpl

cp /vagrant/vagrant/harbor.yml $HARBOR_HOME/harbor.yml

cat >> /etc/hosts <<EOF
127.0.0.1  nginx
EOF

# Configure internal TLS communication between Harbor component.
# https://goharbor.io/docs/2.3.0/install-config/configure-internal-tls/
mkdir -p /etc/harbor/pki/internal
docker run --volume /:/hostfs goharbor/prepare:$HARBOR_VERSION gencert -p /etc/harbor/pki/internal

cd /opt/harbor

./install.sh

# echo 'Harbor12345' | docker login --username=admin --password-stdin nginx:8080

# docker image pull nginx:1.16
# docker image tag nginx:1.16 nginx:8080/library/nginx:1.16
# docker image push nginx:8080/library/nginx:1.16
