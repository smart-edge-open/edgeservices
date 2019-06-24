// Copyright 2019 Intel Corporation and Smart-Edge.com, Inc. All rights reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ini_test

import (
	"testing"

	filet "github.com/Flaque/filet"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var ntsConfigTestFilePath = "/tmp/nts_config_test.cfg"
var ntsConfigTestFileContent = `
[PORT0]
name = FirstPort
description = Description of first port
pci-address = 0000:01:00.0
traffic-type = IP
traffic-direction = upstream
egress-port = 1
route = prio:11,srv_ip:1.1.1.1/11,srv_port:0-80,encap_proto=noencap

[PORT1]
name = SecondPort
pci-address = 0000:01:00.1
traffic-type = mixed
traffic-direction = downstream
egress-port = 0
route = prio:11,ue_ip:1.1.1.1/11,ue_port:100-200,epc_ip:2.2.2.2/22

[PORT2]
name = ThirdPort
pci-address = 0000:02:00.0
traffic-type = LTE
traffic-direction = both
egress-port = 0
route = prio:99,enb_ip:1.1.1.1/11
route = prio:99,epc_ip:2.2.2.2/22

[VM common]
max = 32
number = 2
vhost-dev = /var/lib/nts/qemu/usvhost-1

[NES_SERVER]
ctrl_socket = /var/lib/nts/control-socket

[KNI]
max = 32
`

func TestIni(t *testing.T) {
	defer filet.CleanUp(t)

	filet.File(t, ntsConfigTestFilePath, ntsConfigTestFileContent)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Ini Suite")
}
