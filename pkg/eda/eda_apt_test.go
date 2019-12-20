// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eda_test

import (
	"context"
	"net"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/open-ness/common/log"
	"github.com/open-ness/edgenode/pkg/eda"
	pb "github.com/open-ness/edgenode/pkg/ela/pb"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/status"
)

func TestEdgeDataPlaneAgent(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Edge Data Plane Agent  suite")
}

var correctTR = &pb.TrafficRule{
	Description: "Sample Traffic Rule 1",
	Priority:    99,
	Source: &pb.TrafficSelector{
		Gtp: &pb.GTPFilter{
			Address: "192.168.219.179",
			Mask:    32,
		},
	},
	Destination: &pb.TrafficSelector{
		Description: "",
		Ip: &pb.IPFilter{
			Address: "10.30.40.2",
			Mask:    32,
		},
	},
	Target: &pb.TrafficTarget{
		Action: pb.TrafficTarget_ACCEPT,
		Mac:    &pb.MACModifier{MacAddress: "AA:BB:CC:DD:EE:FF"},
	},
}

var correctFailsRemoveTR = &pb.TrafficRule{
	Description: "Sample Traffic Rule 2",
	Priority:    99,
	Source: &pb.TrafficSelector{
		Gtp: &pb.GTPFilter{
			Address: "192.168.219.178",
			Mask:    32,
		},
	},
	Destination: &pb.TrafficSelector{
		Description: "",
		Ip: &pb.IPFilter{
			Address: "10.30.40.2",
			Mask:    32,
		},
	},
	Target: &pb.TrafficTarget{
		Action: pb.TrafficTarget_ACCEPT,
		Mac:    &pb.MACModifier{MacAddress: "AA:BB:CC:DD:EE:FF"},
	},
}

var missingMacTR = &pb.TrafficRule{
	Description: "Sample Traffic Rule 3",
	Priority:    99,
	Source: &pb.TrafficSelector{
		Gtp: &pb.GTPFilter{
			Address: "192.168.219.179",
			Mask:    32,
		},
	},
	Destination: &pb.TrafficSelector{
		Description: "",
		Ip: &pb.IPFilter{
			Address: "10.30.40.2",
			Mask:    32,
		},
	},
	Target: &pb.TrafficTarget{
		Action: pb.TrafficTarget_ACCEPT,
	},
}

var emptyAddrFieldsTR = &pb.TrafficRule{
	Description: "Sample Traffic Rule 4",
	Priority:    99,
	Source: &pb.TrafficSelector{
		Gtp: &pb.GTPFilter{
			Address: "",
			Mask:    32,
		},
	},
	Destination: &pb.TrafficSelector{
		Description: "",
		Ip: &pb.IPFilter{
			Address: "",
			Mask:    32,
		},
	},
	Target: &pb.TrafficTarget{
		Action: pb.TrafficTarget_ACCEPT,
		Mac:    &pb.MACModifier{MacAddress: "AA:BB:CC:DD:EE:FF"},
	},
}

type fakeNtsConnection struct{}

func fakeNewNtsConnection() (*fakeNtsConnection, error) {
	return new(fakeNtsConnection), nil
}

func (fakeNtsConnection) Disconnect() error {
	return nil
}

func (fakeNtsConnection) RouteAdd(macAddr net.HardwareAddr,
	lookupKeys string) error {

	if lookupKeys == "prio:99,enb_ip:/32,srv_ip:/32" {
		return status.Errorf(codes.Unknown,
			"Failed to add traffic route to NTS")
	}

	return nil
}

func (fakeNtsConnection) RouteRemove(lookupKeys string) error {

	if lookupKeys != "prio:99,enb_ip:192.168.219.179/32,srv_ip:10.30.40.2/32" {
		return errors.New("Failed to remove traffic route from NTS")
	}

	return nil
}

var fakeNewConnFn = func() (eda.NtsConnectionInt, error) {

	return fakeNewNtsConnection()
}

func waitTillConfigIsLoaded() {
	timeout := time.After(50 * time.Millisecond)
	tick := time.Tick(5 * time.Millisecond)

	for {
		select {
		case <-timeout:
			Fail("Loading of EDA's config file timed out")
		case <-tick:
			if eda.Config.Endpoint != "" {
				return
			}
		}
	}
}

func waitTillConnIsEnded(conn *grpc.ClientConn) {
	timeout := time.After(50 * time.Millisecond)
	tick := time.Tick(5 * time.Millisecond)

	for {
		select {
		case <-timeout:
			Fail("Waiting for connection shutdown timed out")
		case <-tick:
			if conn.GetState() == connectivity.Shutdown {
				return
			}
		}
	}
}

var _ = Describe("EDA gRPC Set() request handling", func() {
	eda.NewConnFn = fakeNewConnFn

	var (
		conn      *grpc.ClientConn
		err       error
		srvCtx    context.Context
		srvCancel context.CancelFunc
		cliCtx    context.Context
		cliCancel context.CancelFunc
		client    pb.ApplicationPolicyServiceClient
	)

	Describe("Run EDA", func() {
		It("With wrong config path", func() {
			srvCtx, srvCancel = context.WithCancel(context.Background())
			_ = srvCancel
			err = eda.Run(srvCtx, "fake_config_path.json")
			Expect(err).NotTo(BeNil())
		})
	})

	BeforeEach(func() {
		srvCtx, srvCancel = context.WithCancel(context.Background())
		_ = srvCancel
		go func() {
			err = eda.Run(srvCtx, "testdata/conf.json")
			if err != nil {
				log.Errf("Run() exited with error: %#v", err)
			}
		}()

		waitTillConfigIsLoaded()

		conn, err = grpc.Dial(eda.Config.Endpoint, grpc.WithInsecure())
		Expect(err).NotTo(HaveOccurred())

		client = pb.NewApplicationPolicyServiceClient(conn)
		cliCtx, cliCancel = context.WithTimeout(context.Background(),
			3*time.Second)
		_ = cliCancel

	})

	AfterEach(func() {

		cliCancel()
		conn.Close()
		srvCancel()
		waitTillConnIsEnded(conn)
	})

	Describe("Two Set requests to add and remove traffic policy ", func() {
		It("returns no error", func() {

			// Handle Set request (received from ELA)
			// to add a valid  traffic policy.
			// Assert that the request returns no error
			tp := &pb.TrafficPolicy{Id: "001"}
			tp.TrafficRules = append(tp.TrafficRules, correctTR)
			_, err = client.Set(cliCtx, tp)
			Expect(err).ShouldNot(HaveOccurred())

			// Handle Set request (received from ELA)
			// to remove an existing traffic policy.
			// Assert that the request returns no error
			tp = &pb.TrafficPolicy{Id: "001"}
			_, err = client.Set(cliCtx, tp)
			Expect(err).ShouldNot(HaveOccurred())

		})

	})

	Describe("SET request to add a traffic policy with two "+
		"traffic rules", func() {
		It("returns error on incorrect traffic rule", func() {
			// Handle Set request (received from ELA)
			// to add a traffic policy with two traffic rules:
			// one correct and one having no IP addresses.
			// Assert that request returns an error

			tp := &pb.TrafficPolicy{Id: "001"}
			tp.TrafficRules = append(tp.TrafficRules, correctTR)
			tp.TrafficRules = append(tp.TrafficRules, emptyAddrFieldsTR)
			_, err = client.Set(cliCtx, tp)
			Expect(err).Should(HaveOccurred())
			st, ok := status.FromError(err)
			Expect(ok).To(BeTrue())
			Expect(st.Code()).To(Equal(codes.Unknown))

		})
	})

	Describe("SET request to add a traffic policy with two "+
		"traffic rules", func() {
		It("returns error on attempt to add a traffic rule missing"+
			" the MAC address ",
			func() {

				// Handle Set request (received from ELA)
				// to add a traffic policy with two traffic rules:
				// one correct and one missing mac address
				// Assert that this Set request returns an error

				tp := &pb.TrafficPolicy{Id: "001"}
				tp.TrafficRules = append(tp.TrafficRules, correctTR)
				tp.TrafficRules = append(tp.TrafficRules, missingMacTR)
				_, err = client.Set(cliCtx, tp)
				Expect(err).Should(HaveOccurred())
				st, ok := status.FromError(err)
				Expect(ok).To(BeTrue())
				Expect(st.Code()).To(Equal(codes.InvalidArgument))

			})
	})

	Describe("SET request to add a traffic policy with two "+
		"traffic rules", func() {
		It("returns no error", func() {

			// Handle Set request (received from ELA)
			// to add a traffic policy with two traffic rules:
			// both are correct,
			// Next, override the traffic policy (remove and add)
			// Removing correctFailsRemoveTR should fail,
			// but Set request ends with no errors
			// Assert that this Set request returns no error

			tp := &pb.TrafficPolicy{Id: "001"}
			tp.TrafficRules = append(tp.TrafficRules, correctTR)
			tp.TrafficRules = append(tp.TrafficRules, correctFailsRemoveTR)
			_, err = client.Set(cliCtx, tp)
			Expect(err).ShouldNot(HaveOccurred())
			_, err = client.Set(cliCtx, tp)
			Expect(err).ShouldNot(HaveOccurred())

		})
	})

	Describe("SET request to add a traffic policy with two "+
		"traffic rules, then Set request to remove it", func() {
		It("returns no error",
			func() {

				// Handle Set request (received from ELA)
				// to add a traffic policy with four traffic rules:
				// all are correct, but one should fail its removing
				// Another Set request sent to remove
				// the traffic rules from NTS
				// Removing rule fails for correctFailsRemoveTR
				// but Set request ends with no error
				// Assert that this Set request returns no error

				tp := &pb.TrafficPolicy{Id: "001"}
				tp.TrafficRules = append(tp.TrafficRules, correctTR)
				tp.TrafficRules = append(tp.TrafficRules, correctFailsRemoveTR)
				tp.TrafficRules = append(tp.TrafficRules, correctTR)
				tp.TrafficRules = append(tp.TrafficRules, correctTR)
				_, err = client.Set(cliCtx, tp)
				Expect(err).ShouldNot(HaveOccurred())
				tp = &pb.TrafficPolicy{Id: "001"}
				_, err = client.Set(cliCtx, tp)
				Expect(err).ShouldNot(HaveOccurred())

			})
	})

	Describe("Set requests with empty taffic policy", func() {
		It("returns no error", func() {

			// Handle Set request (received from ELA)
			// to remove a traffic policy that does not exist
			// in EDA memory
			// Assert that the request returns no error
			tp := &pb.TrafficPolicy{Id: "001"}
			_, err = client.Set(cliCtx, tp)
			Expect(err).ShouldNot(HaveOccurred())

		})

	})

	Describe("SET request to remove traffic policy", func() {
		It("returns no error", func() {
			// Handle Set request (received from ELA)
			// to add Traffic Policy
			// Override the existing traffic policy
			// by calling another Set request
			// assert the requests return no errors

			tp := &pb.TrafficPolicy{Id: "001"}
			tp.TrafficRules = append(tp.TrafficRules, correctTR)
			_, err = client.Set(cliCtx, tp)
			Expect(err).ShouldNot(HaveOccurred())
			_, err = client.Set(cliCtx, tp)
			Expect(err).ShouldNot(HaveOccurred())

		})

	})
	Describe("Set requests with empty taffic policy pointer", func() {
		It("returns error", func() {

			// Handle Set request (received from ELA)
			// to add a valid  traffic policy.
			// Assert that the request returns error
			tp := &pb.TrafficPolicy{Id: ""}
			_, err = client.Set(cliCtx, tp)
			Expect(err).Should(HaveOccurred())

		})

	})

})
