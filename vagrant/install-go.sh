#! /bin/bash

GO_VERSION="1.18"

wget --quiet https://golang.org/dl/go$GO_VERSION.linux-amd64.tar.gz
tar -C /usr/local -xzf go$GO_VERSION.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> /home/vagrant/.profile

sudo apt-get update
sudo apt-get install --yes build-essential
