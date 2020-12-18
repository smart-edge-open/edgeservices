// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"

	edgedns "github.com/open-ness/edgenode/pkg/edgedns"

	"github.com/golang/protobuf/ptypes/empty"
	logger "github.com/open-ness/common/log"
	"github.com/open-ness/edgenode/pkg/edgedns/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

var log = logger.DefaultLogger.WithField("grpc", nil)

// ControlServerPKI defines PKI paths to enable encrypted GRPC server
type ControlServerPKI struct {
	Crt string
	Key string
	Ca  string
}

// ControlServer implements the ControlServer API
type ControlServer struct {
	Sock    string
	Address string
	PKI     *ControlServerPKI
	server  *grpc.Server
	storage edgedns.Storage
}

func readPKI(crtPath, keyPath,
	caPath string) (*credentials.TransportCredentials, error) {

	srvCert, err := tls.LoadX509KeyPair(crtPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("Failed load server key pair: %v", err)
	}

	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile(filepath.Clean(caPath))
	if err != nil {
		return nil, fmt.Errorf("Failed read ca certificates: %v", err)
	}

	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		log.Errf("Failed appends CA certs from %s", caPath)
		return nil, fmt.Errorf("Failed appends CA certs from %s", caPath)
	}

	creds := credentials.NewTLS(&tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{srvCert},
		ClientCAs:    certPool,
	})

	return &creds, nil
}

func (cs *ControlServer) startIPServer(stg edgedns.Storage) error {
	log.Infof("Starting IP API at %s", cs.Address)
	tc, err := readPKI(filepath.Clean(cs.PKI.Crt),
		filepath.Clean(cs.PKI.Key),
		filepath.Clean(cs.PKI.Ca))
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
			log.Errf("API listener exited unexpectedly: %s", err)
		}
	}()
	return nil
}

func (cs *ControlServer) startSocketServer(stg edgedns.Storage) error {
	log.Infof("Starting socket API at %s", cs.Sock)
	lis, err := net.Listen("unix", cs.Sock)
	if err != nil {
		return fmt.Errorf("Failed to start API listener: %v", err)
	}

	cs.server = grpc.NewServer()
	pb.RegisterControlServer(cs.server, cs)
	go func() {
		if err := cs.server.Serve(lis); err != nil {
			log.Errf("API listener exited unexpectedly: %s", err)
		}
	}()
	return nil
}

// Start listens on a Unix domain socket only if address is empty.
// If IP address is provided socket file path is ignored and
// server starts to listen on IP address.
func (cs *ControlServer) Start(stg edgedns.Storage) error {
	cs.storage = stg

	if cs.Address != "" {
		return cs.startIPServer(stg)
	}
	return cs.startSocketServer(stg)
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

	log.Infof("[API] SetAuthoritativeHost: %s (%d)",
		rr.Fqdn, len(rr.Addresses))
	if rr.RecordType != pb.RType_A {
		return &empty.Empty{}, status.Error(codes.Unimplemented,
			"only A records are supported")
	}
	err := cs.storage.SetHostRRSet(uint16(rr.RecordType),
		[]byte(rr.Fqdn),
		rr.Addresses)
	if err != nil {
		log.Errf("Failed to set authoritative record: %s", err)
		return &empty.Empty{}, status.Error(codes.Internal,
			"unknown internal DB error occurred")
	}
	return &empty.Empty{}, nil
}

// DeleteAuthoritative deletes the Resource Record
// for a given Query type and domain
func (cs *ControlServer) DeleteAuthoritative(ctx context.Context,
	rr *pb.RecordSet) (*empty.Empty, error) {

	log.Infof("[API] DeleteAuthoritative: %s", rr.Fqdn)
	if rr.RecordType == pb.RType_None {
		return &empty.Empty{}, status.Error(codes.InvalidArgument,
			"you must specify a record type")
	}
	if err := cs.storage.DelRRSet(uint16(rr.RecordType),
		[]byte(rr.Fqdn)); err != nil {

		log.Errf("Failed to delete authoritative record: %s", err)
		return &empty.Empty{}, status.Error(codes.Internal,
			"unknown internal DB error occurred")
	}
	return &empty.Empty{}, nil
}
