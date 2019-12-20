// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package ela_test

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/open-ness/common/proxy/progutil"
	"github.com/open-ness/edgenode/pkg/ela"
	pb "github.com/open-ness/edgenode/pkg/ela/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var fakeDialEDASet = func(context.Context,
	*pb.TrafficPolicy, string) (*empty.Empty, error) {

	return &empty.Empty{}, status.Error(codes.OK, "")
}

var (
	sampleMACAddress    = "AA:BB:CC:DD:EE:FF"
	fakeMACAddress      = sampleMACAddress
	fakeMACAddressError error
)

type fakeMACAddressProvider struct{}

func (*fakeMACAddressProvider) GetMacAddress(context.Context,
	string) (string, error) {

	return fakeMACAddress, fakeMACAddressError
}

var _ = Describe("Application Policy gRPC Server", func() {

	BeforeEach(func() {
		fakeMACAddress = sampleMACAddress
		fakeMACAddressError = nil
	})

	When("Starts", func() {
		It("is callable", func() {
			ela.DialEDASet = fakeDialEDASet
			ela.MACFetcher = &fakeMACAddressProvider{}

			lis, err := net.Listen("tcp", ela.Config.ControllerEndpoint)
			Expect(err).ShouldNot(HaveOccurred())
			prefaceLis := progutil.NewPrefaceListener(lis)
			defer prefaceLis.Close()

			prefaceLis.RegisterHost("127.0.0.1")
			go prefaceLis.Accept() // we only expect 1 connection

			// Then connecting to it from this thread
			// OP-1742: ContextDialler not supported by Gateway
			//nolint:staticcheck
			conn, err := grpc.Dial("127.0.0.1",
				grpc.WithTransportCredentials(transportCreds), grpc.WithDialer(prefaceLis.DialEla))
			Expect(err).NotTo(HaveOccurred())
			defer conn.Close()

			client := pb.NewApplicationPolicyServiceClient(conn)
			setCtx, setCancel := context.WithTimeout(context.Background(),
				3*time.Second)
			defer setCancel()

			// Call Set() with valid param
			// assert that no error occurs (request is passed to EDA fake)
			tp := &pb.TrafficPolicy{Id: "001"}
			tp.TrafficRules = append(tp.TrafficRules, &pb.TrafficRule{
				Destination: &pb.TrafficSelector{
					Ip: &pb.IPFilter{Address: "0.0.0.0", Mask: 0}},
				Target: &pb.TrafficTarget{}})

			_, err = client.Set(setCtx, tp, grpc.WaitForReady(true))
			Expect(err).ShouldNot(HaveOccurred())
		})
	})
})

var _ = Describe("Application Policy Server Implementation", func() {
	ela.DialEDASet = fakeDialEDASet
	ela.MACFetcher = &fakeMACAddressProvider{}
	service := ela.ApplicationPolicyServiceServerImpl{}

	BeforeEach(func() {
		fakeMACAddress = sampleMACAddress
		fakeMACAddressError = nil
	})

	AfterEach(func() {
		fakeMACAddress = sampleMACAddress
		fakeMACAddressError = nil
	})

	When("Set() is called with invalid TrafficPolicy", func() {
		It("returns error", func() {

			_, err := service.Set(context.Background(), &pb.TrafficPolicy{})

			Expect(err).Should(HaveOccurred())

			st, ok := status.FromError(err)
			Expect(ok).To(BeTrue())
			Expect(st.Code()).To(Equal(codes.InvalidArgument))
		})
	})

	When("Set() is called with valid TrafficPolicy", func() {
		It("passes request to EDA", func() {

			tp := &pb.TrafficPolicy{Id: "001"}
			tp.TrafficRules = append(tp.TrafficRules, &pb.TrafficRule{
				Destination: &pb.TrafficSelector{
					Ip: &pb.IPFilter{Address: "0.0.0.0", Mask: 0}},
				Target: &pb.TrafficTarget{}})

			_, err := service.Set(context.Background(), tp)

			Expect(err).ShouldNot(HaveOccurred())
		})
	})
	When("Set() is called where GetMacAddress returns error", func() {
		It("Set() fails with NotFound code", func() {
			fakeMACAddressError = errors.New("MAC address error")
			tp := &pb.TrafficPolicy{Id: "001"}
			tp.TrafficRules = append(tp.TrafficRules, &pb.TrafficRule{
				Destination: &pb.TrafficSelector{
					Ip: &pb.IPFilter{Address: "0.0.0.0", Mask: 0}},
				Target: &pb.TrafficTarget{}})

			_, err := service.Set(context.Background(), tp)

			Expect(err).Should(HaveOccurred())

			st, ok := status.FromError(err)
			Expect(ok).To(BeTrue())
			Expect(st.Code()).To(Equal(codes.NotFound))
		})
	})
	When("Set() is called with invalid MAC address", func() {
		It("Set() fails with NotFound code", func() {
			fakeMACAddress = "This is dummy MACaddress"
			tp := &pb.TrafficPolicy{Id: "001"}
			tp.TrafficRules = append(tp.TrafficRules, &pb.TrafficRule{
				Destination: &pb.TrafficSelector{
					Ip: &pb.IPFilter{Address: "0.0.0.0", Mask: 0}},
				Target: &pb.TrafficTarget{}})

			_, err := service.Set(context.Background(), tp)

			Expect(err).Should(HaveOccurred())

			st, ok := status.FromError(err)
			Expect(ok).To(BeTrue())
			Expect(st.Code()).To(Equal(codes.NotFound))
		})
	})
})
