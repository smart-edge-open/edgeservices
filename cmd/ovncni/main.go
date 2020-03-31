// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package main

// This CNI relies on a preconfigured OVN infrastructure.
// Prior to calling ADD request it is required to configure the logical OVN interface with appID used as its ID
// After calling DEL request it is required to remove the logical OVN interface with appID used as its ID
// "github.com/open-ness/edgenode/pkg/ovncni" package provides helper functions that could be used for creating
// and removing the port: CreatePort/DeletePort
//
// Currently this CNI has to be the first one in a chain
//
// IPAM section of this CNI is not used for calling an external IPAM plugin.
// IPAM `type` field has to be set to `ovn`.
// Additional IPAM fields are used to configure containers gateway and additional routes.
// Example IPAM section of the CNI config:
// "ipam": {
//  "type": "ovn",
//  "routes": [ { "dst": "10.3.0.0/16", "gw": "10.16.0.10" }, { "dst": "10.4.0.0/16" } ],
//  "gateway": "10.16.0.1"
// }
//
// dns section of CNI config is not processed but it is included in the response of ADD request
//
// This CNI requires that the following arguments are present in CNI_ARGS environment variable:
// appID      - Unique application id used for identifying the OVN port
// subnetID   - OVN switch name in which the port was created prior to calling the CNI
// It also accepts the following optional arguments in CNI_ARGS environment variable:
// mtu        - Used to set the MTU value of an interface, kernel default is used if not provided
// ovsBr      - OVS bridge to attach the created virtual interface to. Default: br-int
// ovsCtlPath - ovs-vsctl executable path. Default: ovs-vsctl
// nbCtlPath  - ovn-nbctl executable path. Default: ovn-nbctl

import (
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/open-ness/edgenode/pkg/ovncni"
	"github.com/pkg/errors"
)

// cmdAdd is called for ADD requests
func cmdAdd(args *skel.CmdArgs) error {
	c, err := ovncni.GetContext(args)
	if err != nil {
		return errors.Wrap(err, "Failed to parse CNI context")
	}
	return c.Add()
}

// cmdDel is called for DELETE requests
func cmdDel(args *skel.CmdArgs) error {
	c, err := ovncni.GetContext(args)
	if err != nil {
		return errors.Wrap(err, "Failed to parse CNI context")
	}
	return c.Del()
}

// cmdDel is called for CHECK requests
func cmdCheck(args *skel.CmdArgs) error {
	c, err := ovncni.GetContext(args)
	if err != nil {
		return errors.Wrap(err, "Failed to parse CNI context")
	}
	return c.Check()
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("OVN"))
}
