```text
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2019 Intel Corporation
```

# Building
1. Export RTE\_SDK variable \
`export RTE_SDK=/opt/dpdk-18.08/`

2. Build NTS \
`make -j$(nproc)`

3. Build container \
`docker-compose build`

4. Start NTS
* Whole compose suite in background: \
`docker-compose start` \
and show logs: \
`docker-compose logs -f`

* Only NTS service in foreground: \
`docker-compose run nts`

5. To stop whole compose suite: \
`docker-compose stop`
