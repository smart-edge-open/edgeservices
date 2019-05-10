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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"

	"context"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/smartedgemec/appliance-ce/pkg/ela"
	"github.com/smartedgemec/appliance-ce/pkg/ela/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ = Describe("gRPC InterfaceService", func() {
	expectedNetworkInterfaces := []*pb.NetworkInterface{
		{
			Id:                "0000:00:00.0",
			Driver:            pb.NetworkInterface_USERSPACE,
			Type:              pb.NetworkInterface_UPSTREAM,
			MacAddress:        "AA:BB:CC:DD:EE:FF",
			FallbackInterface: "0000:00:00.1",
		},
		{
			Id:                "0000:00:00.1",
			Driver:            pb.NetworkInterface_KERNEL,
			Type:              pb.NetworkInterface_NONE,
			MacAddress:        "00:11:22:33:44:55",
			FallbackInterface: "0000:00:01.2",
		},
	}

	BeforeEach(func() {
		ela.GetInterfaces = func() (*pb.NetworkInterfaces, error) {
			return &pb.NetworkInterfaces{
					NetworkInterfaces: expectedNetworkInterfaces},
				nil
		}
	})

	Describe("GetAll method", func() {
		Specify("will respond", func() {
			conn, err := grpc.Dial(elaTestEndpoint, grpc.WithInsecure())
			Expect(err).NotTo(HaveOccurred())
			defer conn.Close()

			client := pb.NewInterfaceServiceClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(),
				3*time.Second)
			defer cancel()

			ifs, err := client.GetAll(ctx, &empty.Empty{},
				grpc.WaitForReady(true))
			Expect(err).ShouldNot(HaveOccurred())

			Expect(ifs).ToNot(BeNil())
			Expect(ifs.NetworkInterfaces).To(HaveLen(2))

			ni := ifs.NetworkInterfaces[0]
			Expect(ni).ToNot(BeNil())
			Expect(ni.Id).To(Equal(expectedNetworkInterfaces[0].Id))
			Expect(ni.Driver).To(Equal(expectedNetworkInterfaces[0].Driver))
			Expect(ni.Type).To(Equal(expectedNetworkInterfaces[0].Type))
			Expect(ni.MacAddress).
				To(Equal(expectedNetworkInterfaces[0].MacAddress))
			Expect(ni.FallbackInterface).
				To(Equal(expectedNetworkInterfaces[0].FallbackInterface))
		})
	})

	Describe("Get method", func() {
		get := func(id string) (*pb.NetworkInterface, error) {
			conn, err := grpc.Dial(ela.Config.Endpoint, grpc.WithInsecure())
			Expect(err).NotTo(HaveOccurred())
			defer conn.Close()

			client := pb.NewInterfaceServiceClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(),
				3*time.Second)
			defer cancel()

			return client.Get(ctx, &pb.InterfaceID{Id: id},
				grpc.WaitForReady(true))
		}

		Context("called with Id corresponding to existing interface", func() {
			Specify("will return that interface", func() {
				ni, err := get("0000:00:00.1")

				Expect(err).ShouldNot(HaveOccurred())

				Expect(ni).ToNot(BeNil())
				Expect(ni.Id).To(Equal(expectedNetworkInterfaces[1].Id))
				Expect(ni.Driver).To(Equal(expectedNetworkInterfaces[1].Driver))
				Expect(ni.Type).To(Equal(expectedNetworkInterfaces[1].Type))
				Expect(ni.MacAddress).
					To(Equal(expectedNetworkInterfaces[1].MacAddress))
				Expect(ni.FallbackInterface).
					To(Equal(expectedNetworkInterfaces[1].FallbackInterface))
			})
		})

		Context("called with Id pointing to not existing interface", func() {
			Specify("will return error", func() {
				ni, err := get("0000:02:02.0")

				Expect(ni).To(BeNil())
				Expect(err).To(HaveOccurred())

				st, ok := status.FromError(err)
				Expect(ok).To(BeTrue())
				Expect(st.Message()).To(Equal("interface not found"))
				Expect(st.Code()).To(Equal(codes.NotFound))
			})
		})

		Context("called with empty Id", func() {
			Specify("will return error", func() {
				ni, err := get("")

				Expect(ni).To(BeNil())
				Expect(err).To(HaveOccurred())

				st, ok := status.FromError(err)
				Expect(ok).To(BeTrue())
				Expect(st.Message()).To(Equal("empty id"))
				Expect(st.Code()).To(Equal(codes.InvalidArgument))
			})
		})

		Context("called with Id", func() {
			Context("failed to obtain interfaces", func() {
				Specify("will return error", func() {
					ela.GetInterfaces = func() (*pb.NetworkInterfaces, error) {
						return nil, errors.New("failure")
					}

					ni, err := get("0000:00:00.0")

					Expect(ni).To(BeNil())
					Expect(err).To(HaveOccurred())

					st, ok := status.FromError(err)
					Expect(ok).To(BeTrue())
					Expect(st.Message()).To(Equal("failed to obtain " +
						"network interfaces: failure"))
					Expect(st.Code()).To(Equal(codes.Unknown))
				})
			})
		})
	})
})
