// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package ela

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	edgednspb "github.com/open-ness/edgenode/pkg/edgedns/pb"
	elapb "github.com/open-ness/edgenode/pkg/ela/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// EdgeDNSSocket string name for Edge DNS Socket
var EdgeDNSSocket = "/run/edgedns.sock"

// DNSServiceServer struct implementing ela.pb.go interface
type DNSServiceServer struct {
}

// SetA proxy function to call SetAuthoritativeHost in Edgednssvr
func (s DNSServiceServer) SetA(ctx context.Context,
	input *elapb.DNSARecordSet) (*empty.Empty, error) {
	log.Infof("DNSService SetA: %v", *input)
	out := new(empty.Empty)
	hr, err := transform2HostRecord(input)
	if err != nil {
		log.Errf("DNSService SetA: setting record failed because: %v", err)
		return nil, err
	}
	err = set(ctx, &hr)
	if err != nil {
		log.Errf("DNSService SetA: setting record failed because: %v", err)
		return nil, err
	}
	return out, nil
}

// DeleteA proxy function to call DeleteAuthoritative in Edgednssvr
func (s DNSServiceServer) DeleteA(ctx context.Context,
	input *elapb.DNSARecordSet) (*empty.Empty, error) {
	log.Infof("DNSService DeleteA: %v", *input)
	out := new(empty.Empty)
	var rr = transform2Record(input)
	err := del(ctx, &rr)
	if err != nil {
		log.Errf("DNSService DeleteA: deleting record failed because: %v",
			err)
		return nil, err
	}
	return out, nil
}

// SetForwarders TBD
func (s DNSServiceServer) SetForwarders(ctx context.Context,
	input *elapb.DNSForwarders) (*empty.Empty, error) {
	return &empty.Empty{},
		status.Error(codes.Unimplemented, "not implemented")
}

// DeleteForwarders TBD
func (s DNSServiceServer) DeleteForwarders(ctx context.Context,
	input *elapb.DNSForwarders) (*empty.Empty, error) {
	return &empty.Empty{},
		status.Error(codes.Unimplemented, "not implemented")
}

// DNSClient describes a dns client
type DNSClient struct {
	cn *grpc.ClientConn
	cc edgednspb.ControlClient
}

// Starting client to Edgednssvr
func startClient() (*DNSClient, error) {
	fi, err := os.Stat(EdgeDNSSocket)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		return nil, status.Errorf(codes.FailedPrecondition,
			"Invalid API socket: %s", EdgeDNSSocket)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, "unix://"+EdgeDNSSocket,
		grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return nil,
			status.Errorf(codes.FailedPrecondition,
				"Failed to connect to server: %v", err)
	}

	return &DNSClient{cn: conn, cc: edgednspb.NewControlClient(conn)}, nil
}

func set(ctx context.Context, hr *edgednspb.HostRecordSet) error {
	client, err := startClient()
	if err != nil {
		return err
	}
	defer func() {
		if err1 := client.cn.Close(); err1 != nil {
			log.Errf("Failed to close client connection: %v", err1)
		}
	}()

	if _, err := client.cc.SetAuthoritativeHost(ctx, hr); err != nil {
		return status.Errorf(codes.FailedPrecondition,
			"Failed to register host record: %v", err)
	}
	return nil
}

func del(ctx context.Context, rr *edgednspb.RecordSet) error {
	client, err := startClient()
	if err != nil {
		return err
	}
	defer func() {
		if err1 := client.cn.Close(); err1 != nil {
			log.Errf("Failed to close client connection: %v", err1)
		}
	}()

	if _, err := client.cc.DeleteAuthoritative(ctx, rr); err != nil {
		return status.Errorf(codes.FailedPrecondition,
			"Failed to delete host record: %v", err)
	}
	return nil
}

func transform2HostRecord(
	inputRecord *elapb.DNSARecordSet) (edgednspb.HostRecordSet, error) {
	array := inputRecord.Values
	var outputByteSlice [][]byte
	for _, ipString := range array {
		ip := net.ParseIP(ipString)
		if ip == nil {
			log.Errf(`DNSService record transformation: wrong IP address`)
			return edgednspb.HostRecordSet{},
				fmt.Errorf("wrong IP address provided")
		}
		outputByteSlice = append(outputByteSlice, ip)
	}
	return edgednspb.HostRecordSet{RecordType: 1, Fqdn: inputRecord.Name,
		Addresses: outputByteSlice}, nil
}

func transform2Record(inputRecord *elapb.DNSARecordSet) edgednspb.RecordSet {
	return edgednspb.RecordSet{RecordType: 1, Fqdn: inputRecord.Name}
}
