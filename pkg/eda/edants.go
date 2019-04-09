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

package eda

/*
#cgo CFLAGS: -I${SRCDIR}/../../internal/nts/eda_libs/libnes_api
#cgo CFLAGS: -I${SRCDIR}/../../internal/nts/eda_libs/libnes_sq
#cgo LDFLAGS: -L${SRCDIR}/../../internal/nts/eda_libs/build -lnes_api
#cgo LDFLAGS: -L${SRCDIR}/../../internal/nts/eda_libs/build -lnes_sq
#include <stdint.h>
#include <stdlib.h>
#include <libnes_api.h>
*/
import "C"

import (
	"errors"
	"net"
	"unsafe"
)

type NtsConnection struct {
	cConnection C.nes_remote_t
}

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

func (conn *NtsConnection) Close() error {

	cConnP := &(conn.cConnection)
	res := int(C.nes_conn_close(cConnP))

	if res != 0 {
		return errors.New("Unable to disconnect")
	}

	return nil
}

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
