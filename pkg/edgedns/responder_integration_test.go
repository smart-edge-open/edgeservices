// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation
package edgedns_test

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/config"
	. "github.com/onsi/gomega"
	client "github.com/open-ness/edgenode/pkg/edgedns/test"
)

// Send a DNS query to the test server
func query(d string, t uint16) (msg *dns.Msg, err error) {
	ns := fmt.Sprintf("127.0.0.1:%d", eport+config.GinkgoConfig.ParallelNode)
	dnsClient := new(dns.Client)
	q := new(dns.Msg)
	q.SetQuestion(d, t)

	msg, _, err = dnsClient.Exchange(q, ns)
	return msg, err
}

// Extract IP addresses as string values from a DNS response
func parseAnswers(m *dns.Msg) ([]string, error) {
	q := m.Question[0]
	var addrs []string
	switch q.Qtype {
	case dns.TypeA:
		for _, i := range m.Answer {
			ans, ok := i.(*dns.A)
			if !ok {
				return nil, fmt.Errorf("IPv4 Answer is not an A record")
			}
			addrs = append(addrs, ans.A.String())
		}
	default:
		return nil, fmt.Errorf("Unknown type: %s", q.String())
	}

	return addrs, nil
}

var _ = Describe("Responder", func() {

	var apiClient *client.ControlClient
	var msg *dns.Msg
	var err error

	BeforeEach(func() {
		sock := fmt.Sprintf("dns_%d.sock", config.GinkgoConfig.ParallelNode)
		apiClient = client.NewControlClient(&sock)
		dnsServer.SetDefaultForwarder("")
	})

	It("Sets authoritative A records", func() {
		Expect(apiClient.Connect()).To(Succeed())
		defer apiClient.Close()

		addrsIn := []string{"1.2.6.7", "3.4.5.6", "7.8.4.1"}

		Expect(apiClient.SetA("baz.foo.com", addrsIn)).To(Succeed())

		msg, err = query("baz.foo.com.", dns.TypeA)
		Expect(err).NotTo(HaveOccurred())

		var addrsOut []string
		addrsOut, err = parseAnswers(msg)
		Expect(err).NotTo(HaveOccurred())
		Expect(addrsOut).Should(HaveLen(3))

		Expect(addrsOut).Should(ConsistOf(addrsIn))
	})

	It("Deletes authoritative A records", func() {
		Expect(apiClient.Connect()).To(Succeed())
		defer apiClient.Close()

		Expect(apiClient.SetA("baz.bar.foo.com",
			[]string{"42.24.42"})).To(Succeed())

		msg, err = query("baz.bar.foo.com.", dns.TypeA)
		Expect(err).NotTo(HaveOccurred())
		Expect(msg.Rcode).Should(Equal(dns.RcodeSuccess))

		Expect(apiClient.DeleteA("baz.bar.foo.com")).To(Succeed())

		msg, err = query("baz.bar.foo.com.", dns.TypeA)
		Expect(err).NotTo(HaveOccurred())
		Expect(msg.Rcode).Should(Equal(dns.RcodeServerFailure))
	})

	It("Ramdomizes query results", func() {
		Expect(apiClient.Connect()).To(Succeed())
		defer apiClient.Close()

		addrsIn := []string{"1.42.6.7", "3.42.5.6", "7.8.42.1"}

		Expect(apiClient.SetA("rnd.foo.com", addrsIn)).To(Succeed())

		var rcnt int
		for j := 1; j < 6; j++ {
			msg, err = query("rnd.foo.com.", dns.TypeA)
			Expect(err).NotTo(HaveOccurred())

			var addrsOut []string
			addrsOut, err = parseAnswers(msg)
			Expect(err).NotTo(HaveOccurred())

			Expect(addrsOut).Should(HaveLen(3))

			for i, v := range addrsOut {
				if v != addrsIn[i] {
					rcnt++
				}
			}
		}
		fmt.Printf("Queries radomized %d times\n", rcnt)
		Expect(rcnt).Should(BeNumerically(">", 2))
	})

	It("Returns SERVFAIL for unanswerable queries", func() {
		msg, err = query("oblivion.dev.null.", dns.TypeA)
		Expect(err).NotTo(HaveOccurred())
		Expect(msg.Rcode).Should(Equal(dns.RcodeServerFailure))
	})

	It("Does not allow multiple questions in a query", func() {
		ns := fmt.Sprintf("127.0.0.1:%d",
			eport+config.GinkgoConfig.ParallelNode)
		dnsClient := new(dns.Client)

		m := new(dns.Msg)
		m.Question = []dns.Question{
			{
				Name:   "a.b.c.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET},
			{
				Name:   "e.f.g.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET},
		}

		resp, _, err := dnsClient.Exchange(m, ns)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Rcode).Should(Equal(dns.RcodeFormatError))
	})

	It("Only allows queries", func() {
		ns := fmt.Sprintf("127.0.0.1:%d",
			eport+config.GinkgoConfig.ParallelNode)
		dnsClient := new(dns.Client)

		m := new(dns.Msg)
		m.SetNotify("example.org.")
		soa, _ := dns.NewRR("example.org. IN SOA sns.dns.icann.org." +
			"noc.dns.icann.org. 2018112827 7200 3600 1209600 3600")
		m.Answer = []dns.RR{soa}

		resp, _, err := dnsClient.Exchange(m, ns)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Rcode).Should(Equal(dns.RcodeRefused))

	})

	It("Delegates non-authoritative queries", func() {
		// get regular dns IP
		commandGetCurrentDNS :=
			"nmcli dev show | grep DNS | grep -m 1 -E -o \"([0-9]{1,3}[\\.])" +
				"{3}[0-9]{1,3}\""

		currentDNS, err := exec.Command("bash", "-c",
			commandGetCurrentDNS).Output()
		Expect(err).NotTo(HaveOccurred())
		currentDNSstr := strings.TrimSuffix(string(currentDNS), "\n")

		dnsServer.SetDefaultForwarder(currentDNSstr)
		msg, err := query("google.com.", dns.TypeA)
		Expect(err).NotTo(HaveOccurred())
		Expect(msg.Answer).NotTo(BeEmpty())
	})
})
