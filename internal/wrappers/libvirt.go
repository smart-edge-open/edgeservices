// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package wrappers

import (
	libvirt "github.com/libvirt/libvirt-go"
)

type connectWrapper struct {
	conn *libvirt.Connect
}
type domainWrapper struct {
	dom *libvirt.Domain
}

type networkWrapper struct {
	net *libvirt.Network
}

// ConnectInterface for libvirt.Connect
type ConnectInterface interface {
	Close() (int, error)
	LookupDomainByName(string) (DomainInterface, error)
	ListAllDomains(libvirt.ConnectListAllDomainsFlags) ([]DomainInterface,
		error)
	LookupNetworkByName(string) (NetworkInterface, error)
	DomainDefineXML(string) (DomainInterface, error)
}

// DomainInterface for libvirt.Domain
type DomainInterface interface {
	Free() error
	GetState() (libvirt.DomainState, int, error)
	GetName() (string, error)
	GetXMLDesc(libvirt.DomainXMLFlags) (string, error)
	Create() error
	Destroy() error
	Reboot(libvirt.DomainRebootFlagValues) error
	Shutdown() error
	Undefine() error
}

// NetworkInterface for libvirt.Network
type NetworkInterface interface {
	GetDHCPLeases() ([]libvirt.NetworkDHCPLease, error)
}

// NewConnect returns wrapper for libvirt.Connect
func NewConnect(uri string) (ConnectInterface, error) {
	c, err := libvirt.NewConnect(uri)
	return &connectWrapper{c}, err
}

// Close wrapper for (*Connect) from libvirt-go
func (c *connectWrapper) Close() (int, error) {
	return c.conn.Close()
}

// LookupDomainByName wrapper for (*Connect) from libvirt-go
func (c *connectWrapper) LookupDomainByName(id string) (DomainInterface,
	error) {
	d, err := c.conn.LookupDomainByName(id)
	return &domainWrapper{d}, err
}

// ListAllDomains wrapper for (*Connect) from libvirt-go
func (c *connectWrapper) ListAllDomains(
	flag libvirt.ConnectListAllDomainsFlags) ([]DomainInterface, error) {
	d, err := c.conn.ListAllDomains(flag)
	var ret []DomainInterface
	for _, libvirtDom := range d {
		ret = append(ret, &domainWrapper{&libvirtDom})
	}
	return ret, err
}

// LookupNetworkByName wrapper for (*Connect) from libvirt-go
func (c *connectWrapper) LookupNetworkByName(name string) (
	NetworkInterface, error) {
	n, err := c.conn.LookupNetworkByName(name)
	return &networkWrapper{n}, err
}

// DomainDefineXML wrapper for (*Connect) from libvirt-go
func (c *connectWrapper) DomainDefineXML(xmlConfig string) (
	DomainInterface, error) {
	d, err := c.conn.DomainDefineXML(xmlConfig)
	return &domainWrapper{d}, err
}

// GetDHCPLeases wrapper for (*Network) from libvirt-go
func (n *networkWrapper) GetDHCPLeases() ([]libvirt.NetworkDHCPLease, error) {
	return n.net.GetDHCPLeases()
}

// Free wrapper for (*Network) from libvirt-go
func (d *domainWrapper) Free() error {
	return d.dom.Free()
}

// GetState wrapper for (*Domain) from libvirt-go
func (d *domainWrapper) GetState() (libvirt.DomainState, int, error) {
	return d.dom.GetState()
}

// GetName wrapper for (*Domain) from libvirt-go
func (d *domainWrapper) GetName() (string, error) {
	return d.dom.GetName()
}

// GetXMLDesc wrapper for (*Domain) from libvirt-go
func (d *domainWrapper) GetXMLDesc(flags libvirt.DomainXMLFlags) (string,
	error) {
	return d.dom.GetXMLDesc(flags)
}

// Create wrapper for (*Domain) from libvirt-go
func (d *domainWrapper) Create() error {
	return d.dom.Create()
}

// Destroy wrapper for (*Domain) from libvirt-go
func (d *domainWrapper) Destroy() error {
	return d.dom.Destroy()
}

// Reboot wrapper for (*Domain) from libvirt-go
func (d *domainWrapper) Reboot(flags libvirt.DomainRebootFlagValues) error {
	return d.dom.Reboot(flags)
}

// Shutdown wrapper for (*Domain) from libvirt-go
func (d *domainWrapper) Shutdown() error {
	return d.dom.Shutdown()
}

// Undefine wrapper for (*Domain) from libvirt-go
func (d *domainWrapper) Undefine() error {
	return d.dom.Undefine()
}
