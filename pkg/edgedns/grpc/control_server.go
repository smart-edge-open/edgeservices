// Copyright 2019 Smart-Edge.com, Inc. All rights reserved.
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

package grpc

import (
	"context"
	"fmt"
	"net"

	edgedns "github.com/smartedgemec/appliance-ce/pkg/edgedns"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/smartedgemec/appliance-ce/pkg/edgedns/pb"
	"google.golang.org/grpc"
)

// ControlServer implements the ControlServer API
type ControlServer struct {
	Sock    string
	server  *grpc.Server
	storage edgedns.Storage
}

// Start listens on a Unix domain socket
func (cs *ControlServer) Start(stg edgedns.Storage) error {
	cs.storage = stg

	fmt.Printf("Starting API at %s\n", cs.Sock)
	lis, err := net.Listen("unix", cs.Sock)
	if err != nil {
		return fmt.Errorf("Failed to start API listener: %v", err)
	}
	cs.server = grpc.NewServer()
	pb.RegisterControlServer(cs.server, cs)
	go func() {
		if err := cs.server.Serve(lis); err != nil {
			fmt.Printf("API listener exited unexpectedly: %s\n", err)
		}
	}()
	return nil
}

// GracefulStop shuts down connetions and removes the Unix domain socket
func (cs *ControlServer) GracefulStop() error {
	cs.server.GracefulStop()
	return nil
}

// SetAuthoritativeHost sets a Authoritative or Forwarder address
// for a given domain
func (cs *ControlServer) SetAuthoritativeHost(ctx context.Context,
	rr *pb.HostRecordSet) (*empty.Empty, error) {

	fmt.Printf("[API] SetAuthoritativeHost: %s (%d)\n",
		rr.Fqdn, len(rr.Addresses))
	if rr.RecordType != pb.RType_A {
		return &empty.Empty{}, status.Error(codes.Unimplemented,
			"only A records are supported")
	}
	err := cs.storage.SetHostRRSet(uint16(rr.RecordType),
		[]byte(rr.Fqdn),
		rr.Addresses)
	if err != nil {
		fmt.Printf("Failed to set authoritative record: %s\n", err)
		return &empty.Empty{}, status.Error(codes.Internal,
			"unknown internal DB error occurred")
	}
	return &empty.Empty{}, nil
}

// DeleteAuthoritative deletes the Resource Record
// for a given Query type and domain
func (cs *ControlServer) DeleteAuthoritative(ctx context.Context,
	rr *pb.RecordSet) (*empty.Empty, error) {

	fmt.Printf("[API] DeleteAuthoritative: %s\n", rr.Fqdn)
	if rr.RecordType == pb.RType_None {
		return &empty.Empty{}, status.Error(codes.InvalidArgument,
			"you must specify a record type")
	}
	if err := cs.storage.DelRRSet(uint16(rr.RecordType),
		[]byte(rr.Fqdn)); err != nil {

		fmt.Printf("Failed to delete authoritative record: %s\n", err)
		return &empty.Empty{}, status.Error(codes.Internal,
			"unknown internal DB error occurred")
	}
	return &empty.Empty{}, nil
}
