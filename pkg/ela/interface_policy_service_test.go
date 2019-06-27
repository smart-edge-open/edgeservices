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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"

	"github.com/smartedgemec/appliance-ce/pkg/ela"
	pb "github.com/smartedgemec/appliance-ce/pkg/ela/pb"
)

var _ = Describe("gRPC InterfacePolicyService", func() {
	Context("Set method", func() {
		Specify("will store received TrafficPolicy", func() {
			By("dialing to ELA and calling InterfacePolicyService's Set method")
			conn, err := grpc.Dial(elaTestEndpoint,
				grpc.WithTransportCredentials(transportCreds))
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
	})
})
