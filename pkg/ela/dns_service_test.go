// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package ela_test

import (
	"context"
	"net"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	edgednspb "github.com/open-ness/edgenode/pkg/edgedns/pb"
	"github.com/open-ness/edgenode/pkg/ela"
	elapb "github.com/open-ness/edgenode/pkg/ela/pb"

	"github.com/open-ness/common/log"
	"github.com/open-ness/common/proxy/progutil"
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

				lis, err := net.Listen("tcp", ela.Config.ControllerEndpoint)
				Expect(err).ShouldNot(HaveOccurred())
				prefaceLis := progutil.NewPrefaceListener(lis)
				defer prefaceLis.Close()

				prefaceLis.RegisterHost("127.0.0.1")
				go prefaceLis.Accept() // we only expect 1 connection

				// OP-1742: ContextDialler not supported by Gateway
				//nolint:staticcheck
				conn, err := grpc.Dial("127.0.0.1",
					grpc.WithTransportCredentials(transportCreds),
					grpc.WithDialer(prefaceLis.DialEla))
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
				lis, err := net.Listen("tcp", ela.Config.ControllerEndpoint)
				Expect(err).ShouldNot(HaveOccurred())
				prefaceLis := progutil.NewPrefaceListener(lis)
				defer prefaceLis.Close()

				prefaceLis.RegisterHost("127.0.0.1")
				go prefaceLis.Accept() // we only expect 1 connection

				// OP-1742: ContextDialler not supported by Gateway
				//nolint:staticcheck
				conn, err := grpc.Dial("127.0.0.1",
					grpc.WithTransportCredentials(transportCreds),
					grpc.WithDialer(prefaceLis.DialEla))
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

				lis, err := net.Listen("tcp", ela.Config.ControllerEndpoint)
				Expect(err).ShouldNot(HaveOccurred())
				prefaceLis := progutil.NewPrefaceListener(lis)
				defer prefaceLis.Close()

				prefaceLis.RegisterHost("127.0.0.1")
				go prefaceLis.Accept() // we only expect 1 connection

				// OP-1742: ContextDialler not supported by Gateway
				//nolint:staticcheck
				conn, err := grpc.Dial("127.0.0.1",
					grpc.WithTransportCredentials(transportCreds),
					grpc.WithDialer(prefaceLis.DialEla))
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
	When("SetForwarders is called", func() {
		Context("with correct arguments", func() {
			It("responds with not implemented error", func() {
				lis, err := net.Listen("tcp", ela.Config.ControllerEndpoint)
				Expect(err).ShouldNot(HaveOccurred())
				prefaceLis := progutil.NewPrefaceListener(lis)
				defer prefaceLis.Close()

				prefaceLis.RegisterHost("127.0.0.1")
				go prefaceLis.Accept() // we only expect 1 connection

				// OP-1742: ContextDialler not supported by Gateway
				//nolint:staticcheck
				conn, err := grpc.Dial("127.0.0.1",
					grpc.WithTransportCredentials(transportCreds),
					grpc.WithDialer(prefaceLis.DialEla))
				Expect(err).NotTo(HaveOccurred())
				defer conn.Close()

				client := elapb.NewDNSServiceClient(conn)
				setCtx, setCancel := context.WithTimeout(context.Background(),
					3*time.Second)
				defer setCancel()

				_, err = client.SetForwarders(setCtx, &elapb.DNSForwarders{})

				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("not implemented"))
			})
		})
	})
	When("DeleteForwarders is called", func() {
		Context("with correct arguments", func() {
			It("responds with not implemented error", func() {
				lis, err := net.Listen("tcp", ela.Config.ControllerEndpoint)
				Expect(err).ShouldNot(HaveOccurred())
				prefaceLis := progutil.NewPrefaceListener(lis)
				defer prefaceLis.Close()

				prefaceLis.RegisterHost("127.0.0.1")
				go prefaceLis.Accept() // we only expect 1 connection

				// OP-1742: ContextDialler not supported by Gateway
				//nolint:staticcheck

				conn, err := grpc.Dial("127.0.0.1",
					grpc.WithTransportCredentials(transportCreds),
					grpc.WithDialer(prefaceLis.DialEla))
				Expect(err).NotTo(HaveOccurred())
				defer conn.Close()

				client := elapb.NewDNSServiceClient(conn)
				setCtx, setCancel := context.WithTimeout(context.Background(),
					3*time.Second)
				defer setCancel()

				_, err = client.DeleteForwarders(setCtx, &elapb.DNSForwarders{})

				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("not implemented"))
			})
		})
	})
})
