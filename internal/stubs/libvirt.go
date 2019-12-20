// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package stubs

import (
	libvirt "github.com/libvirt/libvirt-go"
	wrapp "github.com/open-ness/edgenode/internal/wrappers"
)

// ConnStub stores LibvirtConnectStub
var ConnStub LibvirtConnectStub

// DomStub stores LibvirtDomainStub
var DomStub LibvirtDomainStub

// NetStub stores LibvirtNetworkStub
var NetStub LibvirtNetworkStub

// CreateLibvirtConnectionStub returns stub implementing ConnectInterface
func CreateLibvirtConnectionStub(uri string) (wrapp.ConnectInterface, error) {
	return &ConnStub, ConnStub.ConnCreateErr
}

// LibvirtConnectStub struct implementation
type LibvirtConnectStub struct {
	ConnCreateErr    error
	ConnCloseErr     error
	ConnCloseResult  int
	ConnDomDefXML    LibvirtDomainStub
	ConnDomDefXMLErr error
	DomByName        LibvirtDomainStub
	DomByNameErr     error
	DomListAll       []wrapp.DomainInterface
	DomListAllErr    error
	NetByName        LibvirtNetworkStub
	NetByNameErr     error
}

// Close implements stub for corresponding method from ConnectInterface
func (c *LibvirtConnectStub) Close() (int, error) {
	return c.ConnCloseResult, c.ConnCloseErr
}

// LookupDomainByName implements stub for corresponding method from
// ConnectInterface
func (c *LibvirtConnectStub) LookupDomainByName(id string) (
	wrapp.DomainInterface, error) {
	return &c.DomByName, c.DomByNameErr
}

// ListAllDomains implements stub for corresponding method from ConnectInterface
func (c *LibvirtConnectStub) ListAllDomains(
	flag libvirt.ConnectListAllDomainsFlags) ([]wrapp.DomainInterface, error) {
	return c.DomListAll, c.DomListAllErr
}

// LookupNetworkByName implements stub for corresponding method from
// ConnectInterface
func (c *LibvirtConnectStub) LookupNetworkByName(name string) (
	wrapp.NetworkInterface, error) {
	return &c.NetByName, c.NetByNameErr
}

// DomainDefineXML implements stub for corresponding method from
// ConnectInterface
func (c *LibvirtConnectStub) DomainDefineXML(xmlConfig string) (
	wrapp.DomainInterface, error) {
	return &c.ConnDomDefXML, c.ConnDomDefXMLErr
}

// LibvirtDomainStub struct implementation
type LibvirtDomainStub struct {
	DomFreeErr     error
	DomState       libvirt.DomainState
	DomStateReason int
	DomStateErr    error
	DomName        string
	DomNameErr     error
	DomXMLDesc     string
	DomXMLErr      error
	DomCreateErr   error
	DomDestroyErr  error
	DomRebootErr   error
	DomShutdownErr error
	DomUndefineErr error
}

// Free implements stub for corresponding method from DomainInterface
func (d *LibvirtDomainStub) Free() error {
	return d.DomFreeErr
}

// GetState implements stub for corresponding method from DomainInterface
func (d *LibvirtDomainStub) GetState() (libvirt.DomainState, int, error) {
	return d.DomState, d.DomStateReason, d.DomStateErr
}

// GetName implements stub for corresponding method from DomainInterface
func (d *LibvirtDomainStub) GetName() (string, error) {
	return d.DomName, d.DomNameErr
}

// GetXMLDesc implements stub for corresponding method from DomainInterface
func (d *LibvirtDomainStub) GetXMLDesc(flags libvirt.DomainXMLFlags) (string,
	error) {
	return d.DomXMLDesc, d.DomXMLErr
}

// Create implements stub for corresponding method from DomainInterface
func (d *LibvirtDomainStub) Create() error {
	return d.DomCreateErr
}

// Destroy implements stub for corresponding method from DomainInterface
func (d *LibvirtDomainStub) Destroy() error {
	return d.DomDestroyErr
}

// Reboot implements stub for corresponding method from DomainInterface
func (d *LibvirtDomainStub) Reboot(flags libvirt.DomainRebootFlagValues) error {
	return d.DomRebootErr
}

// Shutdown implements stub for corresponding method from DomainInterface
func (d *LibvirtDomainStub) Shutdown() error {
	return d.DomShutdownErr
}

// Undefine implements stub for corresponding method from DomainInterface
func (d *LibvirtDomainStub) Undefine() error {
	return d.DomUndefineErr
}

// LibvirtNetworkStub struct implementation
type LibvirtNetworkStub struct {
	NetDHCPLease []libvirt.NetworkDHCPLease
	NetErr       error
}

// GetDHCPLeases implements stub for corresponding method from NetworkInterface
func (n *LibvirtNetworkStub) GetDHCPLeases() ([]libvirt.NetworkDHCPLease,
	error) {
	return n.NetDHCPLease, n.NetErr
}
