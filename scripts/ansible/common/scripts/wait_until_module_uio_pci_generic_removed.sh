# Copyright 2019 Intel Corporation and Smart-Edge.com, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#!/bin/bash

tries=60  # each 2sec=120sec total

echo "Wait for uio_pci_generic module to be unloaded..."
while [[ $tries -ge 1 ]]; do
  grep -w ^uio_pci_generic /proc/modules 1>/dev/null
  if [[ $? -ne 0 ]]; then
    echo -e "Module unloaded"
    exit 0
  fi
  echo -n .
  sleep 2
  ((tries--))
done
echo -e "Module uio_pci_generic still loaded, raising error!"
echo -e "Please unload uio_pci_generic kernel module!"
exit 1

