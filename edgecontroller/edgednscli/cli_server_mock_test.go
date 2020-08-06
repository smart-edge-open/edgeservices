// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cli_test

import (
	"context"
	"fmt"
	"net"
	"path/filepath"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/otcshare/edgecontroller/edgednscli/pb"
	"google.golang.org/grpc"
)

// ControlServerPKI defines PKI paths to enable encrypted GRPC server
type ControlServerPKI struct {
	Crt string
	Key string
	CA  string
}

// ControlServer implements the ControlServer API
type ControlServer struct {
	Address    string
	PKI        *ControlServerPKI
	server     *grpc.Server
	setRequest *hostRecordSet
	delRequest *recordSet
}

type hostRecordSet struct {
	recordType string
	fqdn       string
	addresses  []string
}
type recordSet struct {
	recordType string
	fqdn       string
}

func (cs *ControlServer) StartServer() error {
	fmt.Println("Starting IP API at: ", cs.Address)

	tc, err := readTestPKICredentials(filepath.Clean(cs.PKI.Crt),
		filepath.Clean(cs.PKI.Key),
		filepath.Clean(cs.PKI.CA))
	if err != nil {
		return fmt.Errorf("failed to read pki: %v", err)
	}

	lis, err := net.Listen("tcp", cs.Address)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}

	cs.server = grpc.NewServer(grpc.Creds(*tc))
	pb.RegisterControlServer(cs.server, cs)
	go func() {
		if err := cs.server.Serve(lis); err != nil {
			fmt.Printf("API listener exited unexpectedly: %s", err)
		}
	}()
	return nil
}

// GracefulStop shuts down connetions and removes the Unix domain socket
func (cs *ControlServer) GracefulStop() error {
	cs.server.GracefulStop()
	return nil
}

// SetAuthoritativeHost is a mock representation of regular server part of
// 'SetAuthoritativeHost' API function. It sets fileds of a internal struct
// 'setRequestl' which can be used to examine the correctness of cli messages
// inside of UT.
func (cs *ControlServer) SetAuthoritativeHost(ctx context.Context,
	rr *pb.HostRecordSet) (*empty.Empty, error) {

	var addressesStr []string
	for _, i := range rr.Addresses {
		addressesStr = append(addressesStr, net.IP(i).String())
	}

	cs.setRequest = &hostRecordSet{
		recordType: pb.RType_name[int32(rr.RecordType)],
		fqdn:       rr.Fqdn,
		addresses:  addressesStr}

	fmt.Printf("[Test Server] SetAuthoritativeHost: %s %s %v",
		cs.setRequest.recordType, cs.setRequest.fqdn, cs.setRequest.addresses)

	return &empty.Empty{}, nil
}

// DeleteAuthoritative is a mock representation of regular server part of
// 'DeleteAuthoritative' API function. It sets fileds of a internal struct
// 'delRequest' which can be used to examine the correctness of cli messages
// inside of UT.
func (cs *ControlServer) DeleteAuthoritative(ctx context.Context,
	rr *pb.RecordSet) (*empty.Empty, error) {

	cs.delRequest = &recordSet{
		recordType: pb.RType_name[int32(rr.RecordType)],
		fqdn:       rr.Fqdn}

	fmt.Printf("[Test Server] DeleteAuthoritative: [%s %s]",
		cs.delRequest.recordType, cs.delRequest.fqdn)

	return &empty.Empty{}, nil
}
