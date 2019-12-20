// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package ini_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/open-ness/edgenode/pkg/ela/ini"
	pb "github.com/open-ness/edgenode/pkg/ela/pb"
)

var _ = Describe("Route string", func() {
	Context("is valid", func() {
		var tr *pb.TrafficRule

		BeforeEach(func() {
			route := "prio:15,ue_ip:1.1.1.1/21,srv_ip:2.2.2.2/22," +
				"enb_ip:3.3.3.3/23,epc_ip:4.4.4.4/24,ue_port:11-22,srv_port:50"

			var err error
			tr, err = TrafficRuleStringToProto(route)
			Expect(err).ToNot(HaveOccurred())
		})

		Context("is parsed into TrafficRule", func() {
			When("eu_ip is parsed", func() {
				It("should set source IPFilter", func() {
					Expect(tr.Source).ToNot(BeNil())
					Expect(tr.Source.Ip).ToNot(BeNil())
					Expect(tr.Source.Ip.Address).To(Equal("1.1.1.1"))
					Expect(tr.Source.Ip.Mask).To(Equal(uint32(21)))
					Expect(tr.Source.Ip.BeginPort).To(Equal(uint32(11)))
					Expect(tr.Source.Ip.EndPort).To(Equal(uint32(22)))
				})
			})

			When("srv_ip is parsed", func() {
				It("should set destination IPFilter", func() {
					Expect(tr.Destination).ToNot(BeNil())
					Expect(tr.Destination.Ip).ToNot(BeNil())
					Expect(tr.Destination.Ip.Address).To(Equal("2.2.2.2"))
					Expect(tr.Destination.Ip.Mask).To(Equal(uint32(22)))
					Expect(tr.Destination.Ip.BeginPort).To(Equal(uint32(50)))
					Expect(tr.Destination.Ip.EndPort).To(Equal(uint32(0)))
				})
			})

			When("enb_ip is parsed", func() {
				It("should set source GTP filter", func() {
					Expect(tr.Source).ToNot(BeNil())
					Expect(tr.Source.Gtp).ToNot(BeNil())
					Expect(tr.Source.Gtp.Address).To(Equal("3.3.3.3"))
					Expect(tr.Source.Gtp.Mask).To(Equal(uint32(23)))
				})
			})

			When("epc_ip is parsed", func() {
				It("should set destination GTP filter", func() {
					Expect(tr.Destination).ToNot(BeNil())
					Expect(tr.Destination.Gtp).ToNot(BeNil())
					Expect(tr.Destination.Gtp.Address).To(Equal("4.4.4.4"))
					Expect(tr.Destination.Gtp.Mask).To(Equal(uint32(24)))
				})
			})
		})
	})

	Context("contains unknown key", func() {
		It("will return an error", func() {
			_, err := TrafficRuleStringToProto("dummy_field:0")
			Expect(err).To(MatchError("parser not found for 'dummy_field'"))
		})
	})

	Context("contains unparsable value", func() {
		It("will return an error", func() {
			_, err := TrafficRuleStringToProto("prio:A")
			Expect(err.Error()).
				To(Equal("failed to parse prio's value:'A': " +
					"failed to parse 'A' to uint"))
		})
	})
})

var _ = Describe("Traffic rule", func() {
	var route string

	BeforeEach(func() {
		tr := pb.TrafficRule{
			Priority: 5,
			Source: &pb.TrafficSelector{
				Ip: &pb.IPFilter{
					Address:   "1.1.1.1",
					Mask:      21,
					BeginPort: 11,
					EndPort:   21,
				},
				Gtp: &pb.GTPFilter{
					Address: "3.3.3.3",
					Mask:    23,
				},
			},
			Destination: &pb.TrafficSelector{
				Ip: &pb.IPFilter{
					Address:   "2.2.2.2",
					Mask:      22,
					BeginPort: 100,
					EndPort:   100,
				},
				Gtp: &pb.GTPFilter{
					Address: "4.4.4.4",
					Mask:    24,
				},
			},
		}

		var err error
		route, err = TrafficRuleProtoToString(&tr)
		Expect(err).ToNot(HaveOccurred())
	})

	Context("is converted to string", func() {
		It("contains proper priority", func() {
			Expect(route).To(ContainSubstring("prio:5,"))
		})

		It("contains proper eNB IP", func() {
			Expect(route).To(ContainSubstring(",enb_ip:3.3.3.3/23,"))
		})

		It("contains proper EPC IP", func() {
			Expect(route).To(ContainSubstring(",epc_ip:4.4.4.4/24,"))
		})

		It("contains proper UE IP", func() {
			Expect(route).To(ContainSubstring(",ue_ip:1.1.1.1/21,"))
		})

		It("contains proper UE port", func() {
			Expect(route).To(ContainSubstring(",ue_port:11-21,"))
		})

		It("contains proper SRV IP", func() {
			Expect(route).To(ContainSubstring(",srv_ip:2.2.2.2/22,"))
		})

		It("contains proper SRV port", func() {
			Expect(route).To(ContainSubstring(",srv_port:100-100"))
		})
	})

	Context("without GTP filters", func() {
		tr := pb.TrafficRule{
			Priority: 5,
			Source: &pb.TrafficSelector{
				Ip: &pb.IPFilter{
					Address:   "1.1.1.1",
					Mask:      21,
					BeginPort: 11,
					EndPort:   21,
				},
			},
		}

		It("should contain encap_proto", func() {
			route, err := TrafficRuleProtoToString(&tr)
			Expect(err).ToNot(HaveOccurred())
			Expect(route).To(ContainSubstring(",encap_proto:noencap"))
		})
	})
})
