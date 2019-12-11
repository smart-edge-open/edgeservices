```text
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2019 Intel Corporation
```

# app-metadata package
## Package purpose
app-metadata is Go package helper for managing Application's metadata
which are placed on disk and have specific directory structure.

## Expected directory structure
It expects following structure:

```
/path/to/root/metadata/directory/
  |
  |- app-name/
      |
      |- .deployed       - marker indicating that deploy procedure is complete, empty file
      |- .metadata.json  - JSON file with actual metadata
```

## .metadata.json structure

```
{
    "type": "LibvirtDomain"
}
```

### Fields
* `type` - deployment type of application
    * `LibvirtDomain` - application is deployed as Libvirt Domain (VM)
    * `DockerContainer` - application is deployed as Docker Container
