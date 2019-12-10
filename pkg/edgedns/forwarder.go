// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package edgedns

import (
	"fmt"

	"github.com/miekg/dns"
)

// Send existing query to specified nameserver
func forwardRequest(q *dns.Msg, ns string) (*dns.Msg, error) {

	if len(ns) == 0 {
		return nil, fmt.Errorf("Missing forwarder address")
	}

	c := new(dns.Client)
	qn := q.Question[0].Name
	log.Debugf("[FORWARDER] Forwarding %s to %s", qn, ns)
	m, rtt, err := c.Exchange(q, ns+":53")

	if err != nil {
		return nil, fmt.Errorf("%s unable to resolve: %s: %s", ns, qn, err)
	}

	log.Debugf("[FORWARDER] Upstream query time: %v", rtt)
	return m, nil
}
