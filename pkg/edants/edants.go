// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

// Package edants is a wrapper on NTS C library functions. As it uses a lot of external
// library functions calls there is no way to test it in any reasonable way.
// This file should be excluded from code coverage calculations.
package edants

/*
#cgo CFLAGS: -I${SRCDIR}/../../internal/nts/eda_libs/libnes_api
#cgo CFLAGS: -I${SRCDIR}/../../internal/nts/eda_libs/libnes_sq
#cgo LDFLAGS: -L${SRCDIR}/../../internal/nts/eda_libs/build -ledanes_api
#cgo LDFLAGS: -L${SRCDIR}/../../internal/nts/eda_libs/build -ledanes_sq
#include <stdint.h>
#include <stdlib.h>
#include <libnes_api.h>
*/
import "C"

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net"
	"unsafe"
)

// NtsConnection represents nts connection
type NtsConnection struct {
	cConnection C.nes_remote_t
}

// NtsDeviceStats represents nts device status
type NtsDeviceStats struct {
	ReceivedPackets  uint64
	SentPackets      uint64
	DroppedPacketsTX uint64
	DroppedPacketsHW uint64
	ReceivedBytes    uint64
	SentBytes        uint64
	DroppedBytesTX   uint64
	IPFragment       uint64
}

// NtsDevice represent nts device
type NtsDevice struct {
	Name    string
	Index   uint16
	MacAddr net.HardwareAddr
	Stats   NtsDeviceStats
}

// NewNtsConnection creates a new nts connection
func NewNtsConnection() (*NtsConnection, error) {

	conn := new(NtsConnection)
	conn.cConnection = C.nes_remote_t{}

	cConnP := &(conn.cConnection)
	res := int(C.nes_conn_init(cConnP, nil, 0))

	if res != 0 {
		return nil, errors.New("Connection failed")
	}

	return conn, nil
}

// Disconnect disconnect a connection
func (conn *NtsConnection) Disconnect() error {

	cConnP := &(conn.cConnection)
	res := int(C.nes_conn_close(cConnP))

	if res != 0 {
		return errors.New("Unable to disconnect")
	}

	return nil
}

// RouteAdd adds a route
func (conn *NtsConnection) RouteAdd(macAddr net.HardwareAddr,
	lookupKeys string) error {

	cMacAddr := C.struct_ether_addr{}
	cLookupKeys := C.CString(lookupKeys)
	defer C.free(unsafe.Pointer(cLookupKeys))

	for i := 0; i < C.ETHER_ADDR_LEN; i++ {
		cMacAddr.ether_addr_octet[i] = (C.uint8_t)(macAddr[i])
	}

	cConnP := &(conn.cConnection)
	res := int(C.nes_route_add(cConnP, cMacAddr, cLookupKeys, 0))

	if res != 0 {
		return errors.New("Unable to add the route")
	}

	return nil
}

// RouteRemove removes a route
func (conn *NtsConnection) RouteRemove(lookupKeys string) error {

	cLookupKeys := C.CString(lookupKeys)
	defer C.free(unsafe.Pointer(cLookupKeys))

	cConnP := &(conn.cConnection)
	res := int(C.nes_route_remove(cConnP, cLookupKeys))

	if res != 0 {
		return errors.New("Unable to remove the route")
	}

	return nil
}

// GetDevices gets a list of devices
func (conn *NtsConnection) GetDevices() ([]NtsDevice, error) {

	cConnP := &(conn.cConnection)
	devList := C.nes_stats_all_dev(cConnP)

	if devList == nil {
		return nil, errors.New("Unable to retrieve the stats")
	}

	var goDevices []NtsDevice
	var cDevice *C.nes_api_dev_t
	for current := devList.head; current != nil; current = current.next {
		cDevice = (*C.nes_api_dev_t)(current.data)

		Device := NtsDevice{
			Name:  C.GoString(&cDevice.name[0]),
			Index: (uint16)(cDevice.index),
			Stats: NtsDeviceStats{
				ReceivedPackets:  (uint64)(cDevice.stats.rcv_cnt),
				SentPackets:      (uint64)(cDevice.stats.snd_cnt),
				DroppedPacketsTX: (uint64)(cDevice.stats.drp_cnt_1),
				DroppedPacketsHW: (uint64)(cDevice.stats.drp_cnt_2),
				ReceivedBytes:    (uint64)(cDevice.stats.rcv_bytes),
				SentBytes:        (uint64)(cDevice.stats.snd_bytes),
				DroppedBytesTX:   (uint64)(cDevice.stats.drp_bytes_1),
				IPFragment:       (uint64)(cDevice.stats.ip_fragment),
			},
		}

		var buf bytes.Buffer
		for i := 0; i < C.ETHER_ADDR_LEN; i++ {
			b := []byte{*((*uint8)(&cDevice.macaddr.ether_addr_octet[i]))}
			buf.WriteString(hex.EncodeToString(b))
			if i < (C.ETHER_ADDR_LEN - 1) {
				buf.WriteString(":")
			}
		}
		macAddrString := buf.String()
		macHrdwAddr, err := net.ParseMAC(macAddrString)
		if err != nil {
			return nil, errors.New("Mac Address conversion failed")
		}

		Device.MacAddr = macHrdwAddr
		goDevices = append(goDevices, Device)
	}
	C.nes_sq_dtor(devList)
	return goDevices, nil
}
