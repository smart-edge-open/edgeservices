#!/usr/bin/env bash
cat >/etc/docker/daemon.json <<EOL
{
  "bridge": "virbr0",
  "fixed-cidr": "${1}",
  "dns": ["192.168.122.1", "8.8.8.8"],
  "userland-proxy": false
}
EOL
