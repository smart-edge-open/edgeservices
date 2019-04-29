// Copyright 2019 Smart-Edge.com, Inc. All rights reserved.
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
