// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

package main_test

import (
	"context"
	"fmt"
	"net"
	"path/filepath"

	"github.com/golang/protobuf/ptypes/empty"
	pb "github.com/otcshare/edgecontroller/pb/interfaceservice"
	"google.golang.org/grpc"
)

type InterfaceServiceServer struct {
	Endpoint string
	server   *grpc.Server

	attachReturnErr error
	detachReturnErr error

	getReturnNi  *pb.Ports
	getReturnErr error
}

func (is *InterfaceServiceServer) StartServer() error {
	fmt.Println("Starting IP API at: ", is.Endpoint)

	tc, err := readTestPKICredentials(filepath.Clean("./certs/s_cert.pem"),
		filepath.Clean("./certs/s_key.pem"),
		filepath.Clean("./certs/cacerts.pem"))
	if err != nil {
		return fmt.Errorf("failed to read pki: %v", err)
	}

	lis, err := net.Listen("tcp", is.Endpoint)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}

	is.server = grpc.NewServer(grpc.Creds(*tc))
	pb.RegisterInterfaceServiceServer(is.server, is)
	go func() {
		if err := is.server.Serve(lis); err != nil {
			fmt.Printf("API listener exited unexpectedly: %s", err)
		}
	}()
	return nil
}

// GracefulStop shuts down connetions and removes the Unix domain socket
func (is *InterfaceServiceServer) GracefulStop() error {
	is.server.GracefulStop()
	return nil
}

func (is *InterfaceServiceServer) Attach(context.Context, *pb.Ports) (*empty.Empty, error) {
	fmt.Println("@@@ 'Attach' from GRPC server @@@")
	return &empty.Empty{}, is.attachReturnErr
}

func (is *InterfaceServiceServer) Detach(context.Context, *pb.Ports) (*empty.Empty, error) {
	fmt.Println("@@@ 'Detach' from GRPC server @@@")
	return &empty.Empty{}, is.detachReturnErr
}

func (is *InterfaceServiceServer) Get(context.Context, *empty.Empty) (*pb.Ports, error) {
	fmt.Println("@@@ 'Get' from GRPC server @@@")
	return is.getReturnNi, is.getReturnErr
}
