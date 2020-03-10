// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package ovncni

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

// Defaults that can be overwritten by CNI Args
const (
	DefaultOvsBrName  = "br-int"
	defaultOvsCtlPath = "ovs-vsctl"
)

// CNIConfig represents OVNCNI configuration structure
type CNIConfig struct {
	types.NetConf
	IPAM IPAMConfig `json:"ipam"`
}

// IPAMConfig represents IPAM configuration for OVNCNI
// It is used purely for setting the Gateway and Routes
type IPAMConfig struct {
	Type    string        `json:"type"`
	Gateway net.IP        `json:"gateway"`
	Routes  []types.Route `json:"routes,omitempty"`
}

// CNIContext CNI runtime context used for ADD/DEL/CHECK requests
type CNIContext struct {
	Cfg        CNIConfig
	Args       *skel.CmdArgs
	OVNCli     OVNClient
	OvsBrName  string
	HostIfName string
	IfMTU      uint64
	Subnet     string
	OvsCtlPath string
	OVNCtlPath string
	AppID      string
}

// OvsVsctlExec function object wraps system call
var OvsVsctlExec = func(path string, args ...string) (string, error) {
	if path == "" {
		path = defaultOvsCtlPath
	}
	// #nosec G204 - args are controlled by the caller
	raw, err := exec.Command(path, args...).CombinedOutput()
	return strings.Trim(strings.TrimSpace(string(raw)), `"`), err
}

// GetCNIArg searches cniArgs for key and returns key's value
// Expected format is alphanumeric key-value pairs separated by semicolons; for example, "FOO=BAR;ABC=123"
func GetCNIArg(key, cniArgs string) (string, error) {
	// CNI_ARGS: Extra arguments passed in by the user at invocation time.
	args := strings.Split(cniArgs, ";")
	for _, arg := range args {
		if strings.HasPrefix(arg, fmt.Sprintf("%s=", key)) {
			return strings.TrimPrefix(arg, fmt.Sprintf("%s=", key)), nil
		}
	}
	return "", errors.Errorf("%s not found in CNI args: %s", key, cniArgs)
}

func delLinkByName(name string) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return errors.Wrapf(err, "Failed to link %s", name)
	}
	return netlink.LinkDel(l)
}

// GetContext parses args to provide CNIContext structure
func GetContext(args *skel.CmdArgs) (CNIContext, error) {
	c := CNIContext{
		OvsBrName:  DefaultOvsBrName,
		OvsCtlPath: defaultOvsCtlPath,
		OVNCli:     GetOVNClient("", 0),
		Cfg:        CNIConfig{},
		Args:       args,
	}

	v, err := GetCNIArg("ovsBrName", args.Args)
	if err == nil {
		c.OvsBrName = v
	}
	v, err = GetCNIArg("ovsCtlPath", args.Args)
	if err == nil {
		c.OvsCtlPath = v
	}
	v, err = GetCNIArg("nbCtlPath", args.Args)
	if err == nil {
		c.OVNCli = GetOVNClient(v, 0)
	}

	if err = json.Unmarshal(args.StdinData, &c.Cfg); err != nil {
		return c, errors.Wrap(err, "Failed to parse network configuration")
	}
	if c.Cfg.PrevResult != nil {
		// TODO: CNI chaining
		return c, errors.New("OVN-CNI must be called as the first plugin")
	}
	if c.Cfg.IPAM.Type != "ovn" {
		return c, errors.Errorf("Only ovn IPAM is supported, provided: %s", c.Cfg.IPAM.Type)
	}

	c.AppID, err = GetCNIArg("appID", args.Args)
	if err != nil {
		return c, errors.Wrap(err, "Failed to get appID from CNI args")
	}

	c.HostIfName = c.AppID
	// Interface name cannot be longer than 15 characters
	if len(c.AppID) > 15 {
		c.HostIfName = c.AppID[:15]
	}

	c.Subnet, err = GetCNIArg("subnetID", args.Args)
	if err != nil {
		return c, errors.Wrap(err, "Failed to get subnetID from CNI args")
	}

	// If MTU is set to 0 the default parent value will be used
	m, err := GetCNIArg("mtu", args.Args)
	if err == nil {
		c.IfMTU, err = strconv.ParseUint(m, 10, 16)
		if err != nil {
			return c, errors.Wrap(err, "Failed to parse provided MTU")
		}
	}

	return c, nil
}

func (c *CNIContext) getCNIResult(p *LPort) current.Result {
	res := current.Result{CNIVersion: c.Cfg.CNIVersion}

	res.Interfaces = []*current.Interface{{
		Name:    c.Args.IfName,
		Mac:     p.MAC.String(),
		Sandbox: c.Args.Netns,
	}}
	ver := "6"
	if p.IP.To4() != nil {
		ver = "4"
	}
	res.IPs = []*current.IPConfig{{
		Interface: current.Int(0),
		Version:   ver,
		Address:   net.IPNet{p.IP, p.Net.Mask},
		Gateway:   c.Cfg.IPAM.Gateway,
	}}
	for i := 0; i < len(c.Cfg.IPAM.Routes); i++ {
		res.Routes = append(res.Routes, &c.Cfg.IPAM.Routes[i])
	}

	// DNS has to be handled during container creation
	res.DNS = c.Cfg.DNS
	return res
}

func (c *CNIContext) configIf(res *current.Result, p *LPort) error {
	n, err := ns.GetNS(c.Args.Netns)
	if err != nil {
		return errors.Wrapf(err, "Failed to open netns %q", c.Args.Netns)
	}

	defer n.Close()

	var contLink netlink.Link

	err = n.Do(func(hostNS ns.NetNS) error {
		_, _, err1 := ip.SetupVethWithName(c.Args.IfName, c.HostIfName, int(c.IfMTU), hostNS)
		if err1 != nil {
			return errors.Wrapf(err1, "Failed to setup VEth pair for: %s", c.Args.IfName)
		}
		contLink, err1 = netlink.LinkByName(c.Args.IfName)
		if err1 != nil {
			return errors.Wrapf(err1, "Failed to find %s", c.Args.IfName)
		}
		if err1 = netlink.LinkSetHardwareAddr(contLink, p.MAC); err1 != nil {
			return errors.Wrapf(err1, "Failed to set MAC address for %s", c.Args.IfName)
		}
		return ipam.ConfigureIface(c.Args.IfName, res)
	})
	if err != nil {
		_ = delLinkByName(c.HostIfName)
		return errors.Wrapf(err, "Failed to configure interface: %s", c.Args.IfName)
	}

	out, err := OvsVsctlExec(c.OvsCtlPath, "--may-exist", "add-port", c.OvsBrName, c.HostIfName, "--",
		"set", "interface", c.HostIfName,
		fmt.Sprintf("external_ids:attached_mac=%s", p.MAC),
		fmt.Sprintf("external_ids:iface-id=%s", p.ID))
	if err != nil {
		_ = delLinkByName(c.HostIfName)
		return errors.Wrapf(err, "Failed to add %s to OVS bridge: %s because: %s", c.HostIfName, c.OvsBrName, out)
	}

	return nil
}

// Add is called for ADD CNI requests
// NOTE: OVN port has to be already created for Add to succeed.
//       This package provides the following helper function to create an OVN port:
//       func CreatePort(lSwitch, id, ip string) (LPort, error)
func (c *CNIContext) Add() error {
	p, err := c.OVNCli.GetPort(c.Subnet, c.AppID)
	if err != nil {
		return errors.Wrapf(err, "Failed to find OVN port(%s)", c.AppID)
	}
	cniRes := c.getCNIResult(&p)

	if err := c.configIf(&cniRes, &p); err != nil {
		return errors.Wrapf(err, "Failed to configure interface %s", c.Args.IfName)
	}

	return types.PrintResult(&cniRes, c.Cfg.CNIVersion)
}

// Del is called for DELETE CNI requests
// NOTE: OVN port has to be removed after calling CNI DELETE.
//       This package provides the following helper function to delete an OVN port:
//       func DeletePort(id string) error
func (c *CNIContext) Del() error {

	out, err := OvsVsctlExec(c.OvsCtlPath, "--if-exists", "--with-iface", "del-port", c.OvsBrName, c.HostIfName)
	if err != nil {
		return errors.Wrapf(err, "Failed to remove %s from OVS bridge: %s because: %s", c.HostIfName, c.OvsBrName, out)
	}
	if err := delLinkByName(c.HostIfName); err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); !ok {
			return errors.Wrapf(err, "Failed to remove link %s", c.HostIfName)
		}
	}

	return nil
}

// Check is called for CHECK CNI requests
func (c *CNIContext) Check() error {
	_, err := c.OVNCli.GetPort(c.Subnet, c.AppID)
	if err != nil {
		return errors.Wrapf(err, "Failed to find OVN port(%s)", c.AppID)
	}

	id, err := OvsVsctlExec(c.OvsCtlPath, "get", "interface", c.HostIfName, "external-ids:iface-id")
	if err != nil {
		return errors.Wrapf(err, "Failed to find OVS port for %s", c.AppID)
	}
	if id != c.AppID {
		return errors.Errorf("Interface ID(%s) does not match AppID(%s)", id, c.AppID)
	}
	return nil
}
