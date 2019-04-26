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

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/smartedgemec/appliance-ce/pkg/ela"
	"github.com/smartedgemec/appliance-ce/pkg/ela/pb"
	"github.com/smartedgemec/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var fakeDialEDASet = func(context.Context,
	*pb.TrafficPolicy) (*empty.Empty, error) {

	return &empty.Empty{}, status.Error(codes.OK, "")
}

type fakeMACAddressProvider struct{}

func (*fakeMACAddressProvider) GetMacAddress(context.Context,
	string) (string, error) {

	return "AA:BB:CC:DD:EE:FF", nil
}

var _ = Describe("Application Policy gRPC Server", func() {
	When("Starts", func() {
		It("is callable", func() {
			ela.DialEDASet = fakeDialEDASet
			ela.MACFetcher = &fakeMACAddressProvider{}

			srvCtx, srvCancel := context.WithCancel(context.Background())
			go func() {
				err := ela.Run(srvCtx, "ela.json")
				if err != nil {
					log.Errf("ela.Run exited with error: %#v", err)
				}
			}()
			defer srvCancel()

			// Wait for loading config and serving gRPC
			time.Sleep(10 * time.Millisecond)

			conn, err := grpc.Dial(ela.Config.Endpoint, grpc.WithInsecure())
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

	When("Set() is called with invalid TrafficPolicy", func() {
		It("returns error", func() {

			_, err := service.Set(context.Background(), &pb.TrafficPolicy{})

			Expect(err).Should(HaveOccurred())

			st, ok := status.FromError(err)
			Expect(ok).To(BeTrue())
			Expect(st.Code()).To(Equal(codes.InvalidArgument))
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
	})
})

var _ = Describe("Traffic rules are verified.", func() {
	Describe("Address and mask are verified: ", func() {
		When("Mask is 0", func() {
			It("Address should be empty or 0.0.0.0", func() {
				Expect(ela.VerifyAddressMask("", 0)).Should(BeNil())
				Expect(ela.VerifyAddressMask("0.0.0.0", 0)).Should(BeNil())
				Expect(ela.VerifyAddressMask("1.1.1.1", 0)).
					Should(MatchError("Invalid IP/Mask: " +
						"For Mask=0 only empty or 0.0.0.0 addresses are valid"))
			})
		})

		When("Mask is not 0", func() {
			It("Address should be valid IPv4", func() {
				Expect(ela.VerifyAddressMask("", 24)).
					Should(MatchError("Invalid IP/Mask: " +
						"For empty IP only Mask=0 is valid"))
				Expect(ela.VerifyAddressMask("1.1.1.1", 24)).Should(BeNil())
				Expect(ela.VerifyAddressMask("1.1.1.322", 24)).
					Should(MatchError("Invalid IP/Mask: " +
						"Given IP is not a valid IPv4 address"))
				Expect(ela.VerifyAddressMask("FE12::1234", 24)).
					Should(MatchError("Invalid IP/Mask: " +
						"Given IP is not a valid IPv4 address"))
			})
		})
	})

	Describe("IP filter is verified:", func() {
		When("Begin port is greater than end port", func() {
			It("returns an error", func() {
				filter := &pb.IPFilter{
					Address:   "",
					Mask:      0,
					BeginPort: 2,
					EndPort:   1,
				}
				Expect(ela.VerifyIPFilter(filter)).
					Should(
						MatchError("IPFilter: BeginPort greater than EndPort"))
			})
		})
		When("Protocol is set", func() {
			It("returns an error", func() {
				filter := &pb.IPFilter{
					Address:   "",
					Mask:      0,
					BeginPort: 0,
					EndPort:   1,
					Protocol:  "tcp",
				}
				Expect(ela.VerifyIPFilter(filter)).
					Should(
						MatchError("IPFilter: Protocol field is not supported"))
			})
		})

		When("Address and mask is incorrect", func() {
			It("returns an error", func() {
				filter := &pb.IPFilter{Address: "FE12::1234", Mask: 24}
				Expect(ela.VerifyIPFilter(filter)).
					Should(
						MatchError("IPFilter: " +
							"Invalid IP/Mask: " +
							"Given IP is not a valid IPv4 address"))
			})
		})

		When("All parameters are correct", func() {
			It("returns a nil", func() {
				filter := &pb.IPFilter{
					Address:   "1.1.1.1",
					Mask:      24,
					BeginPort: 10000,
					EndPort:   10000}
				Expect(ela.VerifyIPFilter(filter)).Should(BeNil())
			})
		})
	})

	Describe("GTP filter is verified:", func() {

		When("Address and mask is incorrect", func() {
			It("returns an error", func() {
				filter := &pb.GTPFilter{Address: "FE12::1234", Mask: 24}
				Expect(ela.VerifyGTPFilter(filter)).
					Should(
						MatchError("GTPFilter: " +
							"Invalid IP/Mask: " +
							"Given IP is not a valid IPv4 address"))
			})
		})

		When("Imsis is given", func() {
			It("returns an error", func() {
				filter := &pb.GTPFilter{Address: "1.1.1.1", Mask: 24}
				filter.Imsis = append(filter.Imsis, "310150123456789")
				Expect(ela.VerifyGTPFilter(filter)).
					Should(
						MatchError("GTPFilter: Imsis is not supported"))
			})
		})

		When("All parameters are correct", func() {
			It("returns a nil", func() {
				filter := &pb.GTPFilter{Address: "1.1.1.1", Mask: 24}
				Expect(ela.VerifyGTPFilter(filter)).Should(BeNil())
			})
		})

	})

	Describe("Traffic selector is verified:", func() {
		When("MAC address is set", func() {
			It("returns an error", func() {
				ts := &pb.TrafficSelector{Macs: &pb.MACFilter{}}

				Expect(ela.VerifyTrafficSelector(ts)).
					Should(MatchError(
						"TrafficSelector.Mac is set but not supported"))
			})
		})

		When("Neither IP nor Gtp filters are set", func() {
			It("returns an error", func() {
				ts := &pb.TrafficSelector{}

				Expect(ela.VerifyTrafficSelector(ts)).
					Should(MatchError(
						"TrafficSelector: Neither Ip nor Gtp is set"))
			})
		})

		When("IP filter is set but incorrect", func() {
			It("returns an error", func() {
				ts := &pb.TrafficSelector{Ip: &pb.IPFilter{
					Address: "1.1.1.1", Mask: 33}}

				Expect(ela.VerifyTrafficSelector(ts)).
					Should(MatchError(
						"TrafficSelector.Ip: " +
							"IPFilter: " +
							"Invalid IP/Mask: Mask should be between 0 and 32"))
			})
		})

		When("Gtp filter is set but incorrect", func() {
			It("returns an error", func() {
				ts := &pb.TrafficSelector{Gtp: &pb.GTPFilter{
					Address: "1.1.1.1", Mask: 33}}

				Expect(ela.VerifyTrafficSelector(ts)).
					Should(MatchError(
						"TrafficSelector.Gtp: " +
							"GTPFilter: " +
							"Invalid IP/Mask: Mask should be between 0 and 32"))
			})
		})

		When("All fields are OK", func() {
			It("returns a nil", func() {
				ts := &pb.TrafficSelector{Gtp: &pb.GTPFilter{
					Address: "1.1.1.1", Mask: 32}}
				Expect(ela.VerifyTrafficSelector(ts)).Should(BeNil())
			})
		})
	})

	Describe("MAC is verified:", func() {

		Context("MAC is invalid", func() {
			When("is empty", func() {
				It("returns an error", func() {
					Expect(ela.VerifyMACAddress("")).
						Should(MatchError("invalid MAC address"))
				})
			})

			When("contains dot or dash", func() {
				It("returns an error", func() {
					Expect(ela.VerifyMACAddress("AABB.CCDD.EEFF")).
						Should(MatchError("MAC Address: Wrong delimiter, " +
							"only : is supported"))
					Expect(ela.VerifyMACAddress("AA-BB-CC-DD-EE-FF")).
						Should(MatchError("MAC Address: Wrong delimiter, " +
							"only : is supported"))
				})
			})

			When("is longer than 6 bytes", func() {
				It("returns an error", func() {
					Expect(ela.VerifyMACAddress("AA:BB:CC:DD:EE:FF:11:22")).
						Should(MatchError("MAC Address: Wrong length - " +
							"only 6 bytes are supported"))
				})
			})
		})

		When("MAC is valid", func() {
			It("returns a nil", func() {
				Expect(ela.VerifyMACAddress("AA:BB:CC:DD:EE:FF")).
					Should(BeNil())
			})
		})
	})

	Describe("Traffic target is verified:", func() {
		When("target parameter is nil", func() {
			It("returns an error", func() {
				Expect(ela.VerifyTrafficTarget(nil)).
					Should(MatchError("TrafficTarget is nil"))
			})
		})

		When("action is different than ACCEPT", func() {
			It("returns an error", func() {
				tt := &pb.TrafficTarget{Action: pb.TrafficTarget_REJECT}
				Expect(ela.VerifyTrafficTarget(tt)).
					Should(MatchError("TrafficTarget.Action: " +
						"Action not supported: REJECT"))

				tt.Action = pb.TrafficTarget_DROP
				Expect(ela.VerifyTrafficTarget(tt)).
					Should(MatchError("TrafficTarget.Action: " +
						"Action not supported: DROP"))
			})
		})

		When("IP modifier is present", func() {
			It("returns an error", func() {
				tt := &pb.TrafficTarget{Ip: &pb.IPModifier{}}
				Expect(ela.VerifyTrafficTarget(tt)).
					Should(MatchError("TrafficTarget.Ip: " +
						"modifier is not supported"))
			})
		})

		When("All params are OK", func() {
			It("returns a nil", func() {
				tt := &pb.TrafficTarget{Action: pb.TrafficTarget_ACCEPT}
				Expect(ela.VerifyTrafficTarget(tt)).Should(BeNil())
			})
		})

	})

	Describe("Traffic rule is verified:", func() {
		When("Neither source nor destination selectors are set", func() {
			It("return an error", func() {
				tr := &pb.TrafficRule{}
				Expect(ela.VerifyTrafficRule(tr)).Should(MatchError(
					"TrafficRule: " +
						"Both source and destination selectors are nil"))
			})
		})

		When("Source selector is set but invalid", func() {
			It("return an error", func() {
				tr := &pb.TrafficRule{
					Source: &pb.TrafficSelector{Macs: &pb.MACFilter{}},
				}
				Expect(ela.VerifyTrafficRule(tr)).
					Should(MatchError("TrafficRule.Source: " +
						"TrafficSelector.Mac is set but not supported"))
			})
		})

		When("Destination selector is set but invalid", func() {
			It("return an error", func() {
				tr := &pb.TrafficRule{
					Destination: &pb.TrafficSelector{
						Macs: &pb.MACFilter{}}}
				Expect(ela.VerifyTrafficRule(tr)).
					Should(MatchError("TrafficRule.Destination: " +
						"TrafficSelector.Mac is set but not supported"))
			})
		})

		When("Target is invalid", func() {
			It("return an error", func() {
				tr := &pb.TrafficRule{
					Destination: &pb.TrafficSelector{
						Ip: &pb.IPFilter{Address: "0.0.0.0", Mask: 0}},
				}
				Expect(ela.VerifyTrafficRule(tr)).Should(
					MatchError("TrafficRule.Target: TrafficTarget is nil"))
			})
		})

		When("All params are ok", func() {
			It("return a nil", func() {
				tr := &pb.TrafficRule{
					Destination: &pb.TrafficSelector{
						Ip: &pb.IPFilter{Address: "0.0.0.0", Mask: 0}},
					Target: &pb.TrafficTarget{}}
				Expect(ela.VerifyTrafficRule(tr)).Should(BeNil())
			})
		})
	})

	Describe("TrafficPolicy is verified.", func() {
		When("TrafficPolicy is null", func() {
			It("returns an error", func() {
				Expect(ela.VerifyTrafficPolicy(nil)).
					Should(MatchError("TrafficPolicy is nil"))
			})
		})

		When("TrafficPolicy Id is empty", func() {
			It("returns an error", func() {
				tp := &pb.TrafficPolicy{Id: ""}
				Expect(ela.VerifyTrafficPolicy(tp)).
					Should(MatchError("TrafficPolicy.Id is empty"))
			})
		})

		When("TrafficPolicy's rule is incorrect", func() {
			It("returns an error", func() {
				tp := &pb.TrafficPolicy{Id: "001"}
				tp.TrafficRules = append(tp.TrafficRules, &pb.TrafficRule{})
				Expect(ela.VerifyTrafficPolicy(tp)).Should(
					MatchError("TrafficPolicy.TrafficRule[0] is invalid: " +
						"TrafficRule: " +
						"Both source and destination selectors are nil"))
			})
		})
	})
})
