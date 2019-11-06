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
	"errors"
	"net"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/otcshare/common/proxy/progutil"
	"github.com/otcshare/edgenode/pkg/ela"
	pb "github.com/otcshare/edgenode/pkg/ela/pb"
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
	fakeMACAddress      = "AA:BB:CC:DD:EE:FF"
	fakeMACAddressError error
)

type fakeMACAddressProvider struct{}

func (*fakeMACAddressProvider) GetMacAddress(context.Context,
	string) (string, error) {

	return fakeMACAddress, fakeMACAddressError
}

var _ = Describe("Application Policy gRPC Server", func() {

	BeforeEach(func() {
		fakeMACAddress = "AA:BB:CC:DD:EE:FF"
		fakeMACAddressError = nil
	})

	When("Starts", func() {
		It("is callable", func() {
			ela.DialEDASet = fakeDialEDASet
			ela.MACFetcher = &fakeMACAddressProvider{}

			lis, err := net.Listen("tcp", ela.Config.ControllerEndpoint)
			prefaceLis := progutil.NewPrefaceListener(lis)
			defer prefaceLis.Close()
			go prefaceLis.Accept() // we only expect 1 connection

			// Then connecting to it from this thread
			// OP-1742: ContextDialler not supported by Gateway
			//nolint:staticcheck
			conn, err := grpc.Dial("",
				grpc.WithTransportCredentials(transportCreds),
				grpc.WithDialer(prefaceLis.DialEla))
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
		fakeMACAddress = "AA:BB:CC:DD:EE:FF"
		fakeMACAddressError = nil
	})

	AfterEach(func() {
		fakeMACAddress = "AA:BB:CC:DD:EE:FF"
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
