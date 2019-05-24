#!/usr/bin/env bash

base_path="/var/lib/appliance/certs/"
while true; do
  found=0
  [ -f ${base_path}/cacerts.pem ] && let found=$found+1
  [ -f ${base_path}/key.pem ] && let found=$found+1
  [ -f ${base_path}/cert.pem ] && let found=$found+1
  [ -f ${base_path}/root.pem ] && let found=$found+1
  [[ $found -eq 4 ]] && break
  sleep 5
done
