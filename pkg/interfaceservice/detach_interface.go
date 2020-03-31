// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package interfaceservice

import (
	"strings"

	pb "github.com/open-ness/edgenode/pkg/interfaceservice/pb"
	"github.com/pkg/errors"
)

// attachPortToOvs attaches given port to kube-ovn's bridge
func detachPortFromOvs(port pb.Port) error {
	name, err := getPortName(port.Pci)

	if err != nil {
		return err
	}

	output, err := Vsctl("del-port", strings.TrimSpace(name))
	if err == nil {
		log.Info("Removed OVS port: ", name)
	} else {
		log.Info(string(output))
		return errors.Wrapf(err, string(output))
	}

	return err
}
