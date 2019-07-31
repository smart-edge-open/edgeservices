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

package ela_test

import (
	"context"
	"net"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	edgednspb "github.com/otcshare/edgenode/pkg/edgedns/pb"
	"github.com/otcshare/edgenode/pkg/ela"
	elapb "github.com/otcshare/edgenode/pkg/ela/pb"

	"github.com/otcshare/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type fakeDNSServer struct {
	s *grpc.Server
}

func (fs *fakeDNSServer) SetAuthoritativeHost(ctx context.Context,
	rr *edgednspb.HostRecordSet) (*empty.Empty, error) {
	return &empty.Empty{}, nil
}

func (fs *fakeDNSServer) DeleteAuthoritative(ctx context.Context,
	rr *edgednspb.RecordSet) (*empty.Empty, error) {
	return &empty.Empty{}, nil
}

func (fs *fakeDNSServer) startFakeDNSServer(socket string) error {
	lis, err := net.Listen("unix", socket)
	if err != nil {
		return status.Errorf(codes.NotFound,
			"Failed to start API listener with socket %s: %v", socket, err)
	}
	fs.s = grpc.NewServer()
	edgednspb.RegisterControlServer(fs.s, fs)

	go func() {
		if err := fs.s.Serve(lis); err != nil {
			log.Errf("grpcServer.Serve error: %v", err)
		}
	}()

	return nil
}

var _ = Describe("DnsService gRPC Server", func() {

	fs := fakeDNSServer{}
	BeforeEach(func() {
		fakeSocket := "edgedns_test.sock"
		ela.EdgeDNSSocket = fakeSocket
		err := fs.startFakeDNSServer(fakeSocket)
		if err != nil {
			log.Errf("Failed to start fake server: %v", err)
		}
	})

	AfterEach(func() {
		fs.s.GracefulStop()
	})

	When("SetA is called", func() {
		Context("with correct arguments", func() {
			It("responds with no error", func() {
				conn, err := grpc.Dial(elaTestEndpoint,
					grpc.WithTransportCredentials(transportCreds))
				Expect(err).NotTo(HaveOccurred())
				defer conn.Close()

				client := elapb.NewDNSServiceClient(conn)
				setCtx, setCancel := context.WithTimeout(context.Background(),
					3*time.Second)
				defer setCancel()

				// Call SetA() with valid param assert that no error occurs
				// (request is passed to fakeDNSServer fake)
				rs := &elapb.DNSARecordSet{Name: "www.google.com",
					Values: []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}}
				_, err = client.SetA(setCtx, rs, grpc.WaitForReady(true))
				Expect(err).ShouldNot(HaveOccurred())
			})
		})
		Context("with wrong arguments", func() {
			It("responds with error", func() {
				conn, err := grpc.Dial(elaTestEndpoint,
					grpc.WithTransportCredentials(transportCreds))
				Expect(err).NotTo(HaveOccurred())
				defer conn.Close()

				client := elapb.NewDNSServiceClient(conn)
				setCtx, setCancel := context.WithTimeout(context.Background(),
					3*time.Second)
				defer setCancel()

				// Call SetA() with invalid param assert that an error occurs
				// (request is passed to fakeDNSServer fake)
				rs := &elapb.DNSARecordSet{Name: "www.google.com",
					Values: []string{"127.0.0"}}
				_, err = client.SetA(setCtx, rs, grpc.WaitForReady(true))
				Expect(err).Should(HaveOccurred())
			})
		})
	})

	When("DeleteA is called", func() {
		Context("with correct arguments", func() {
			It("responds with no error", func() {
				conn, err := grpc.Dial(elaTestEndpoint,
					grpc.WithTransportCredentials(transportCreds))
				Expect(err).NotTo(HaveOccurred())
				defer conn.Close()

				client := elapb.NewDNSServiceClient(conn)
				setCtx, setCancel := context.WithTimeout(context.Background(),
					3*time.Second)
				defer setCancel()

				// Call DeleteA() with valid param assert that no error occurs
				// (request is passed to fakeDNSServer fake)
				rs := &elapb.DNSARecordSet{Name: "www.google.com",
					Values: []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}}
				_, err = client.DeleteA(setCtx, rs, grpc.WaitForReady(true))
				Expect(err).ShouldNot(HaveOccurred())
			})
		})
	})
})
