```text
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2019 Intel Corporation
```

# Edge DNS Responder

This project provides a standards compliant DNS server that exposes gRPC interfaces for the realtime creation of records.

Feature|Community Edition|Enterprise Edition|
|---|:---:|:---:|
|gRPC Control API|✅|✅|
|Embedded database|✅|✅|
|Embedded Forwarder Cache||✅|
|Nested dynamic Forwarder chains||✅
|IPv6 Listeners||✅|
|IPv6 Record Types||✅|
|Authoritative TXT Record||✅|
|Authoritative SRV Record||✅|
|Dynamic logging levels||✅|
|Logging to syslog||✅|

This Community Edition server implements:

* DNS Authoritative server
* Control via gRPC API on a UNIX domain socket

## Usage

All queries are processed in the following order:

1. Authoritative lookup (default TTL of 10 seconds)
2. Forwarder lookup

The Enterprise Edition allows the dynamic definition of forwarders on a per FQDN basis with hierarchical traversal of forwarders if a given forwarder does not return an answer for the query.

### API Client

See the test [API client](test/control_client.go) for example usage of the control API.

### Logging

By default only major events related to the listeners or databases, as well as control socket API requests, are sent to `STDERR`.

### CLI

You can specify the following options:

|flag|required|default|description|
|---|---|---|---|
|4|NO|anyhost|IPv4 Listen address|
|port|NO|5053|UDP Listen port|
|sock|NO|`/run/edgedns.sock`|Filesystem path for the UNIX gRPC socket|
|db|NO|`/var/lib/edgedns/rrsets.db`|Filesystem path for persistent database file|
|fwdr|NO|8.8.8.8|IPv4 address of the upstream forwarder|

## Configuration

The following operations are available via the gRPC inteface on the UNIX domain socket:

* Set(Create/Update) and Delete operations for an A record

