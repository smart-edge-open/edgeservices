```text
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2019 Intel Corporation
```

# Contribution Guide

Please consider the following criteria before suggesting or implementing any changes:

* This project's goal is to provide the absolute bare _minimum_ set of DNS features, it is expected that a forwarder will be used if more advanced features or controls are required
* Performance is extremely important because this service will impact almost all mobile user traffic
* Zone guards should be implemented by a calling services, this service only provides the responder features

Updating the gRPC inteface

`protoc -I pb --go_out=plugins=grpc:pb pb/resolver.proto`

