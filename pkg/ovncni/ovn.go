// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package ovncni

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/pkg/errors"
)

var defaultNbCtlPath = "ovn-nbctl"
var defaultNbCtlTimeout = 10

// TODO: Load these variables from ENV
var clusterRouter = "cluster-router"
var nodeSwitch = "node-switch"

// NbCtlCommand function object wraps system call
var NbCtlCommand = func(path string, timeout int, args ...string) (string, error) {
	args = append([]string{fmt.Sprintf("--timeout=%d", timeout)}, args...)
	// #nosec G204 - args are controlled by the caller
	cmd := exec.Command(path, args...)
	cmd.Env = os.Environ()
	raw, err := cmd.CombinedOutput()

	return strings.Trim(strings.TrimSpace(string(raw)), `"`), err
}

// LPort represents a logical switch port in OVN
type LPort struct {
	ID  string
	MAC net.HardwareAddr
	IP  net.IP
	Net *net.IPNet
}

// OVNClient wraps ovn-nbctl calls to manage ports
type OVNClient struct {
	nbCtlPath string
	timeout   int
}

// GetOVNClient create OVN client
func GetOVNClient(nbCtlPath string, timeout int) OVNClient {
	c := OVNClient{
		nbCtlPath: defaultNbCtlPath,
		timeout:   defaultNbCtlTimeout,
	}
	if nbCtlPath != "" {
		c.nbCtlPath = nbCtlPath
	}
	if timeout != 0 {
		c.timeout = timeout
	}
	return c
}

// GetNbCtlPath returns system path to executable
func (c *OVNClient) GetNbCtlPath() string {
	return c.nbCtlPath
}

// GetPort retrieves a logical switch port from OVN
func (c *OVNClient) GetPort(lSwitch, id string) (LPort, error) {
	p := LPort{}
	// Wait and read dynamic_addresses for provided id
	out, err := NbCtlCommand(c.nbCtlPath, c.timeout,
		"wait-until", "logical_switch_port", id, "dynamic_addresses!=[]", "--",
		"get", "logical_switch_port", id, "dynamic-addresses")
	if err != nil {
		return p, errors.Wrapf(err, "Failed to get a dynamic port(%s): %s", id, out)
	}

	// 00:00:00:00:00:00 0.0.0.0
	data := strings.Split(out, " ")
	if len(data) != 2 {
		return p, errors.Errorf("Failed to get OVN port addresses(%s) from: (%s)", id, out)
	}

	mac, err := net.ParseMAC(data[0])
	if err != nil {
		return p, errors.Errorf("Failed to parse MAC address of OVN port(%s) from: (%s)", id, data[0])
	}
	ip := net.ParseIP(data[1])
	if ip == nil {
		return p, errors.Errorf("Failed to parse IP address of OVN port(%s) from: (%s)", id, data[1])
	}

	out, err = NbCtlCommand(c.nbCtlPath, c.timeout,
		"get", "logical_switch", lSwitch, "other_config:subnet")
	if err != nil {
		return p, errors.Wrapf(err, "Failed to get a the subnet OVN switch(%s): %s", lSwitch, out)
	}
	_, cidr, err := net.ParseCIDR(out)
	if err != nil {
		return p, errors.Wrapf(err, "Failed to parse subnet of OVN switch(%s)", lSwitch)
	}

	p.ID = id
	p.IP = ip
	p.Net = cidr
	p.MAC = mac

	return p, nil
}

// CreatePort creates a logical (id) port in OVN (lSwitch)
// ip parameter is optional and a 'dynamic' value will be used if it is empty
func (c *OVNClient) CreatePort(lSwitch, id, ip string) (LPort, error) {
	p := LPort{}

	if lSwitch == "" || id == "" {
		return p, errors.Errorf("At least one required parameter is empty lSwitch:%s|id:%s", lSwitch, id)
	}

	if ip == "" {
		out, err := NbCtlCommand(c.nbCtlPath, c.timeout,
			"lsp-add", lSwitch, id, "--",
			"set", "logical_switch_port", id, "addresses=dynamic")
		if err != nil {
			return p, errors.Wrapf(err, "Failed to create a dynamic port(%s): %s", id, out)
		}

	} else {
		out, err := NbCtlCommand(c.nbCtlPath, c.timeout, "lsp-add", lSwitch, id, "--",
			"lsp-set-addresses", id, "dynamic", ip)
		if err != nil {
			return p, errors.Wrapf(err, "Failed to create a dynamic port(%s): %s", id, out)
		}
	}
	p, err := c.GetPort(lSwitch, id)
	if err != nil {
		return p, errors.Wrapf(err, "Failed to get port(%s)", id)
	}

	if out, err := NbCtlCommand(c.nbCtlPath, c.timeout,
		"lsp-set-port-security", id, fmt.Sprintf("%s %s", p.MAC, p.Net)); err != nil {
		return p, errors.Wrapf(err, "Failed to set port security(%s): %s", id, out)
	}

	// Link DHCP options
	out, err := NbCtlCommand(c.nbCtlPath, c.timeout, "-f", "csv", "--no-headings",
		"find", "dhcp_options", fmt.Sprintf("cidr=%s", p.Net))
	if err != nil {
		return p, errors.Wrapf(err, "Failed to get DHCP option(%s): %s", p.Net, out)
	}
	if len(out) == 0 {
		return p, errors.Errorf("Failed to get DHCP option(%s): no output", p.Net)
	}

	optID := strings.Split(out, ",")[0]
	out, err = NbCtlCommand(c.nbCtlPath, c.timeout, "lsp-set-dhcpv4-options", id, optID)
	if err != nil {
		return p, errors.Wrapf(err, "Failed to set DHCP option(%s): %s", id, out)
	}
	// Create routing
	// Node port name is equal to HOST_HOSTNAME variable
	pn := os.Getenv("HOST_HOSTNAME")
	if len(pn) == 0 {
		return p, errors.Errorf("Failed to read ENV var: HOST_HOSTNAME")
	}
	np, err := c.GetPort(nodeSwitch, pn)
	if err != nil {
		return p, errors.Wrapf(err, "Failed to get port(%s)", pn)
	}
	out, err = NbCtlCommand(c.nbCtlPath, c.timeout,
		"--policy=src-ip", "lr-route-add", clusterRouter, p.IP.String(), np.IP.String())
	if err != nil {
		return p, errors.Wrapf(err, "Failed to set port routing(%s): %s", id, out)
	}
	return p, err
}

// DeletePort deletes a logical port from OVN
func (c *OVNClient) DeletePort(id string) error {
	// Remove routing
	out, err := NbCtlCommand(c.nbCtlPath, c.timeout,
		"wait-until", "logical_switch_port", id, "dynamic_addresses!=[]", "--",
		"get", "logical_switch_port", id, "dynamic-addresses")
	if err != nil {
		return errors.Wrapf(err, "Failed to get a dynamic port(%s)", id)
	}

	// 00:00:00:00:00:00 0.0.0.0
	data := strings.Split(out, " ")
	if len(data) != 2 {
		return errors.Errorf("Failed to get OVN port addresses(%s) from: (%s)", id, out)
	}

	ip := net.ParseIP(data[1])
	if ip == nil {
		return errors.Errorf("Failed to parse IP address of OVN port(%s) from: (%s)", id, data[1])
	}

	out, err = NbCtlCommand(c.nbCtlPath, c.timeout, "--if-exists", "lr-route-del", clusterRouter, ip.String())
	if err != nil {
		return errors.Wrapf(err, "Failed to remove port routing(%s) : %s", id, out)
	}

	if delOut, err := NbCtlCommand(c.nbCtlPath, c.timeout, "--if-exists", "lsp-del", id); err != nil {
		return errors.Wrapf(err, "Failed to delete port(%s): %s", id, delOut)
	}
	return nil
}
