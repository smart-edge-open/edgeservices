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

package kubeovn_test

import (
	"context"
	"time"

	pb "github.com/open-ness/edgenode/pkg/ela/pb"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ = When("kube-ovn mode is enabled", func() {
	Describe("ApplicationPolicyService", func() {
		It("should not be available", func() {
			conn, err := grpc.Dial(elaTestEndpoint,
				grpc.WithTransportCredentials(transportCreds))
			Expect(err).NotTo(HaveOccurred())
			defer conn.Close()

			client := pb.NewApplicationPolicyServiceClient(conn)
			setCtx, setCancel := context.WithTimeout(context.Background(),
				3*time.Second)
			defer setCancel()

			// Call ApplicationPolicyService/Set() with valid param
			tp := &pb.TrafficPolicy{Id: "001"}

			_, err = client.Set(setCtx, tp, grpc.WaitForReady(true))
			Expect(err).Should(HaveOccurred())

			st, ok := status.FromError(err)
			Expect(ok).To(BeTrue())
			Expect(st.Message()).To(Equal("unknown service" +
				" openness.ela.ApplicationPolicyService"))
			Expect(st.Code()).To(Equal(codes.Unimplemented))
		})
	})
})
