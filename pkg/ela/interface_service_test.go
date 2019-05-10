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

	"context"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/smartedgemec/appliance-ce/pkg/ela"
	"github.com/smartedgemec/appliance-ce/pkg/ela/pb"
	"github.com/smartedgemec/log"
	"google.golang.org/grpc"
)

var _ = Describe("gRPC InterfaceService", func() {
	Context("GetAll method", func() {
		Specify("will respond", func() {
			By("mocking a network interface provider")
			ela.GetInterfaces = func() (*pb.NetworkInterfaces, error) {
				ifs := &pb.NetworkInterfaces{}
				ifs.NetworkInterfaces = make([]*pb.NetworkInterface, 0)
				ifs.NetworkInterfaces = append(ifs.NetworkInterfaces,
					&pb.NetworkInterface{
						Id:                "0000:00:00.0",
						Driver:            pb.NetworkInterface_USERSPACE,
						Type:              pb.NetworkInterface_UPSTREAM,
						MacAddress:        "AA:BB:CC:DD:EE:FF",
						FallbackInterface: "0000:00:00.1",
					})

				return ifs, nil
			}

			By("starting ELA's gRPC server in separate goroutine")
			srvErrChan := make(chan error)
			srvCtx, srvCancel := context.WithCancel(context.Background())
			go func() {
				err := ela.Run(srvCtx, "ela.json")
				if err != nil {
					log.Errf("ela.Run exited with error: %+v", err)
				}
				srvErrChan <- err
			}()
			defer func() {
				srvCancel()
				<-srvErrChan
			}()

			By("dialing to ELA and calling InterfaceService's GetAll method")
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
			Expect(ifs.NetworkInterfaces).To(HaveLen(1))
			ni := ifs.NetworkInterfaces[0]
			Expect(ni).ToNot(BeNil())
			Expect(ni.Id).To(Equal("0000:00:00.0"))
			Expect(ni.Driver).To(Equal(pb.NetworkInterface_USERSPACE))
			Expect(ni.Type).To(Equal(pb.NetworkInterface_UPSTREAM))
			Expect(ni.MacAddress).To(Equal("AA:BB:CC:DD:EE:FF"))
			Expect(ni.FallbackInterface).To(Equal("0000:00:00.1"))
		})
	})
})
