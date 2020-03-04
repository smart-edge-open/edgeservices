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

var nbCtlCommand = func(path string, timeout int, args ...string) (string, error) {
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
	IP  net.IPNet
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

// GetPort retrieves a logical switch port from OVN
func (c *OVNClient) GetPort(lSwitch, id string) (LPort, error) {
	p := LPort{}
	// Wait and read dynamic_addresses for provided id
	out, err := nbCtlCommand(c.nbCtlPath, c.timeout,
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

	out, err = nbCtlCommand(c.nbCtlPath, c.timeout,
		"get", "logical_switch", lSwitch, "other_config:subnet")
	if err != nil {
		return p, errors.Wrapf(err, "Failed to get a the subnet OVN switch(%s): %s", lSwitch, out)
	}
	_, cidr, err := net.ParseCIDR(out)
	if err != nil {
		return p, errors.Wrapf(err, "Failed to parse subnet of OVN switch(%s)", lSwitch)
	}

	p.ID = id
	p.IP = net.IPNet{IP: ip, Mask: cidr.Mask}
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
		out, err := nbCtlCommand(c.nbCtlPath, c.timeout,
			"lsp-add", lSwitch, id, "--",
			"set", "logical_switch_port", id, "addresses=dynamic")
		if err != nil {
			return p, errors.Wrapf(err, "Failed to create a dynamic port(%s): %s", id, out)
		}

	} else {
		out, err := nbCtlCommand(c.nbCtlPath, c.timeout, "lsp-add", lSwitch, id, "--",
			"lsp-set-addresses", id, "dynamic", ip)
		if err != nil {
			return p, errors.Wrapf(err, "Failed to create a dynamic port(%s): %s", id, out)
		}
	}
	p, err := c.GetPort(lSwitch, id)
	if err == nil {
		out, err1 := nbCtlCommand(c.nbCtlPath, c.timeout,
			"lsp-set-port-security", id, fmt.Sprintf("%s %s/%s", p.MAC, p.IP.IP, p.IP.Mask))
		if err1 != nil {
			return p, errors.Wrapf(err1, "Failed to set port security(%s): %s", id, out)
		}
	}
	return p, err
}

// DeletePort deletes a logical port from OVN
func (c *OVNClient) DeletePort(id string) error {
	if out, err := nbCtlCommand(c.nbCtlPath, c.timeout, "lsp-del", id); err != nil {
		return errors.Wrapf(err, "Failed to delete port(%s): %s", id, out)
	}
	return nil
}
