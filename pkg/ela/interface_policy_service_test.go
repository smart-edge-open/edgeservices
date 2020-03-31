// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package ela_test

import (
	"context"
	"net"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"

	"github.com/open-ness/common/proxy/progutil"
	"github.com/open-ness/edgenode/pkg/ela"
	pb "github.com/open-ness/edgenode/pkg/ela/pb"
)

var _ = Describe("gRPC InterfacePolicyService", func() {

	BeforeEach(func() {
		ela.InterfaceConfigurationData.TrafficPolicies = make(map[string]*pb.TrafficPolicy)
	})

	Context("Set method", func() {
		Specify("will store received TrafficPolicy", func() {
			By("dialing to ELA and calling InterfacePolicyService's Set method")

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
				grpc.WithTransportCredentials(transportCreds),
				grpc.WithDialer(prefaceLis.DialEla))
			Expect(err).NotTo(HaveOccurred())
			defer conn.Close()

			client := pb.NewInterfacePolicyServiceClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(),
				3*time.Second)
			defer cancel()

			expectedTp := &pb.TrafficPolicy{
				Id: "0000:00:00.1",
				TrafficRules: []*pb.TrafficRule{{
					Description: "dummy desc",
					Priority:    15,
					Source: &pb.TrafficSelector{
						Ip: &pb.IPFilter{
							Address: "1.1.1.1",
							Mask:    32,
						}},
					Target: &pb.TrafficTarget{},
				}}}

			_, err = client.Set(ctx, expectedTp, grpc.WaitForReady(true))
			Expect(err).ShouldNot(HaveOccurred())
			Expect(ela.InterfaceConfigurationData).ToNot(BeNil())
			Expect(ela.InterfaceConfigurationData.TrafficPolicies).
				ToNot(BeNil())
			Expect(ela.InterfaceConfigurationData.TrafficPolicies).
				To(HaveLen(1))

			tp, ok := ela.InterfaceConfigurationData.
				TrafficPolicies["0000:00:00.1"]

			Expect(ok).To(BeTrue())

			Expect(tp.Id).To(Equal(expectedTp.Id))
			Expect(tp.TrafficRules).To(HaveLen(len(expectedTp.TrafficRules)))

			tr := tp.TrafficRules[0]
			expTr := expectedTp.TrafficRules[0]
			Expect(tr.Description).To(Equal(expTr.Description))
			Expect(tr.Priority).To(Equal(expTr.Priority))
			Expect(tr.Source).ToNot(BeNil())
			Expect(tr.Source.Ip).ToNot(BeNil())
			Expect(tr.Source.Ip.Address).To(Equal(expTr.Source.Ip.Address))
			Expect(tr.Source.Ip.Mask).To(Equal(expTr.Source.Ip.Mask))
		})
		When("received TrafficPolicy with EMPTY Id", func() {
			It("will fail", func() {

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
					grpc.WithTransportCredentials(transportCreds),
					grpc.WithDialer(prefaceLis.DialEla))
				Expect(err).NotTo(HaveOccurred())
				defer conn.Close()

				client := pb.NewInterfacePolicyServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					3*time.Second)
				defer cancel()

				expectedTp := &pb.TrafficPolicy{
					Id: "",
					TrafficRules: []*pb.TrafficRule{{
						Description: "dummy desc",
						Priority:    15,
						Source: &pb.TrafficSelector{
							Ip: &pb.IPFilter{
								Address: "1.1.1.1",
								Mask:    32,
							}},
						Target: &pb.TrafficTarget{},
					}}}

				_, err = client.Set(ctx, expectedTp, grpc.WaitForReady(true))

				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("TrafficPolicy.Id is empty"))
				Expect(ela.InterfaceConfigurationData).ToNot(BeNil())
				Expect(ela.InterfaceConfigurationData.TrafficPolicies).
					ToNot(BeNil())
				Expect(ela.InterfaceConfigurationData.TrafficPolicies).
					To(HaveLen(0))

				_, ok := ela.InterfaceConfigurationData.
					TrafficPolicies[""]

				Expect(ok).To(BeFalse())
			})
		})
		When("received EMPTY TrafficPolicy", func() {
			It("will fail", func() {

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
					grpc.WithTransportCredentials(transportCreds),
					grpc.WithDialer(prefaceLis.DialEla))
				Expect(err).NotTo(HaveOccurred())
				defer conn.Close()

				client := pb.NewInterfacePolicyServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					3*time.Second)
				defer cancel()

				expectedTp := &pb.TrafficPolicy{}

				_, err = client.Set(ctx, expectedTp, grpc.WaitForReady(true))

				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("is empty"))
				Expect(ela.InterfaceConfigurationData).ToNot(BeNil())
				Expect(ela.InterfaceConfigurationData.TrafficPolicies).
					ToNot(BeNil())
				Expect(ela.InterfaceConfigurationData.TrafficPolicies).
					To(HaveLen(0))
			})
		})
	})
})
