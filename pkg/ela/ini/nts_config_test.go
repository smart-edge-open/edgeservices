// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package ini_test

import (
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"io/ioutil"

	. "github.com/open-ness/edgenode/pkg/ela/ini"
	pb "github.com/open-ness/edgenode/pkg/ela/pb"
)

var _ = Describe("NtsConfig", func() {
	Context("is loaded from file", func() {
		var nts *NtsConfig

		BeforeEach(func() {
			var err error
			nts, err = NtsConfigFromFile(ntsConfigTestFilePath)

			Expect(err).ShouldNot(HaveOccurred())
			Expect(nts).ShouldNot(BeNil())
		})

		Context("NTS SERVER", func() {
			Specify("is loaded properly", func() {
				Expect(nts.NtsServer.ControlSocket).
					To(Equal("/var/lib/nts/control-socket"))
			})
		})

		Context("VM common", func() {
			Specify("is loaded properly", func() {
				Expect(nts.VMCommon.Max).To(Equal(32))
				Expect(nts.VMCommon.Number).To(Equal(2))
				Expect(nts.VMCommon.VHostDev).
					To(Equal("/var/lib/nts/qemu/usvhost-1"))
			})
		})

		Context("KNI", func() {
			Specify("is loaded properly", func() {
				Expect(nts.KNI.Max).To(Equal(32))
			})
		})

		Context("Ports", func() {
			Specify("are loaded properly", func() {
				Expect(len(nts.Ports)).To(Equal(3))
				p1 := nts.Ports[0]
				Expect(p1.Name).To(Equal("FirstPort"))
				Expect(p1.Description).To(Equal("Description of first port"))
				Expect(p1.PciAddress).To(Equal("0000:01:00.0"))
				Expect(p1.TrafficType).To(Equal(IP))
				Expect(p1.TrafficDirection).To(Equal(Upstream))
				Expect(p1.EgressPort).To(Equal(1))
				Expect(p1.EgressPortID).To(Equal("0000:01:00.1"))
				Expect(p1.Routes).To(HaveLen(1))

				p2 := nts.Ports[1]
				Expect(p2.Name).To(Equal("SecondPort"))
				Expect(p2.PciAddress).To(Equal("0000:01:00.1"))
				Expect(p2.TrafficType).To(Equal(Mixed))
				Expect(p2.TrafficDirection).To(Equal(Downstream))
				Expect(p2.EgressPort).To(Equal(0))
				Expect(p2.EgressPortID).To(Equal("0000:01:00.0"))
				Expect(p2.Routes).To(HaveLen(1))

				p3 := nts.Ports[2]
				Expect(p3.Name).To(Equal("ThirdPort"))
				Expect(p3.PciAddress).To(Equal("0000:02:00.0"))
				Expect(p3.TrafficType).To(Equal(LTE))
				Expect(p3.TrafficDirection).To(Equal(Both))
				Expect(p3.EgressPort).To(Equal(0))
				Expect(p2.EgressPortID).To(Equal("0000:01:00.0"))
				Expect(p3.Routes).To(HaveLen(2))
			})
		})

		Context("and saved", func() {
			It("should be exactly the same", func() {
				buf, err := nts.WriteToBuffer()

				Expect(err).ShouldNot(HaveOccurred())
				Expect(buf).ShouldNot(BeNil())

				serializedConfig := strings.TrimSpace(buf.String())
				ntsConfigTestFileContent, err := ioutil.ReadFile(
					"testdata/nts.cfg")
				Expect(err).ShouldNot(HaveOccurred())
				Expect(serializedConfig).
					Should(Equal(strings.TrimSpace(
						string(ntsConfigTestFileContent))))
			})
		})
	})

	Context("after receiving requestes to SET", func() {
		When("is updated", func() {
			nts := &NtsConfig{
				Ports: []Port{
					{
						LBPMAC:           "AA:BB:CC:DD:EE:FF",
						TrafficDirection: Upstream,
						PciAddress:       "0000:01:00.0",
						EgressPortID:     "0000:00:00.1",
					},
					{
						LBPMAC:           "FF:EE:DD:CC:BB:AA",
						TrafficDirection: LBP,
						EgressPortID:     "0000:01:00.0",
						PciAddress:       "0000:00:00.1",
					},
				},
			}
			nts.Update()

			It("shall have correct LBPMACs and EgressPorts", func() {
				Expect(nts.Ports).To(HaveLen(2))

				Expect(nts.Ports[0].LBPMAC).To(BeEmpty())
				Expect(nts.Ports[0].EgressPort).To(Equal(1))
				Expect(nts.Ports[1].LBPMAC).To(Equal("FF:EE:DD:CC:BB:AA"))
				Expect(nts.Ports[1].EgressPort).To(Equal(0))
			})
		})
	})

	Context("Slice of ports is edited", func() {
		When("new port is added", func() {
			It("is placed at the end of slice", func() {
				nts := &NtsConfig{
					Ports: []Port{
						{PciAddress: "1"},
						{PciAddress: "2"},
						{PciAddress: "3"},
					},
				}

				nts.AddNewPort(Port{PciAddress: "4"})

				Expect(nts.Ports).To(HaveLen(4))
				Expect(nts.Ports[3].PciAddress).To(Equal("4"))
			})
		})

		When("port is removed from middle", func() {
			It("is placed at the end of slice", func() {
				nts := &NtsConfig{
					Ports: []Port{
						{PciAddress: "1"},
						{PciAddress: "2"},
						{PciAddress: "3"},
					},
				}

				nts.RemovePort("2")

				Expect(nts.Ports).To(HaveLen(2))
				Expect(nts.Ports[1].PciAddress).To(Equal("3"))
			})
		})
	})
})

var _ = Describe("NTS Port", func() {
	ni := &pb.NetworkInterface{
		Id:                "0000:01:00.0",
		Description:       "NetworkInterface desc",
		Driver:            pb.NetworkInterface_USERSPACE,
		Type:              pb.NetworkInterface_UPSTREAM,
		MacAddress:        "AA:BB:CC:DD:EE:FF",
		FallbackInterface: "0000:02:00.1",
	}

	tp := &pb.TrafficPolicy{
		TrafficRules: []*pb.TrafficRule{
			{
				Priority: 13,
				Source: &pb.TrafficSelector{
					Ip: &pb.IPFilter{
						Address:   "192.168.1.1",
						Mask:      24,
						BeginPort: 10,
						EndPort:   100,
					}},
				Target: &pb.TrafficTarget{
					Mac: &pb.MACModifier{
						MacAddress: "FF:EE:DD:CC:BB:AA",
					},
				},
			},
		}}

	Context("from NetworkInterface", func() {
		Specify("should be partially set", func() {
			p := &Port{}
			err := p.UpdateFromNetworkInterface(ni)

			Expect(err).ShouldNot(HaveOccurred())
			Expect(p.Name).To(Equal(ni.Id))
			Expect(p.PciAddress).To(Equal(ni.Id))
			Expect(p.Description).To(Equal(ni.Description))
			Expect(p.TrafficDirection).To(Equal(Upstream))
			Expect(p.EgressPortID).To(Equal(ni.FallbackInterface))
			Expect(p.MAC).To(Equal(ni.MacAddress))
		})
	})

	Context("from TrafficPolicy", func() {
		Specify("should be partially set", func() {
			p := &Port{}
			err := p.UpdateFromTrafficPolicy(tp)

			Expect(err).ShouldNot(HaveOccurred())
			Expect(p.LBPMAC).To(Equal("FF:EE:DD:CC:BB:AA"))
			Expect(p.TrafficType).To(Equal(IP))
			Expect(p.Routes).To(Not(BeEmpty()))
		})
	})

	Context("to NetworkInterface", func() {
		Specify("should be valid", func() {
			p := &Port{
				Name:             "0000:03:00.1",
				PciAddress:       "0000:03:00.1",
				TrafficDirection: Downstream,
				EgressPortID:     "0000:01:00.0",
				Description:      "Desc",
				MAC:              "AA:CC:BB:DD:FF:EE",
			}

			ni, err := p.GetNetworkInterface()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(ni.Id).To(Equal(p.Name))
			Expect(ni.FallbackInterface).To(Equal(p.EgressPortID))
			Expect(ni.Type).To(Equal(pb.NetworkInterface_DOWNSTREAM))
			Expect(ni.Description).To(Equal(p.Description))
			Expect(ni.MacAddress).To(Equal(p.MAC))
		})
	})
})
