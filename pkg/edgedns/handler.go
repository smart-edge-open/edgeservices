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
	"math/rand"
	"time"

	"github.com/miekg/dns"
)

func (r *Responder) handleDNSRequest(w dns.ResponseWriter, q *dns.Msg) {
	var m *dns.Msg
	var err error

	switch q.Opcode {
	case dns.OpcodeQuery:
		fmt.Printf("[RESOLVER] Lookup %s\n", q.Question[0].Name)

		// Authoritative lookup
		var rrs *[]dns.RR
		rrs, err = r.storage.GetRRSet(q.Question[0].Name, q.Question[0].Qtype)
		if err == nil {
			shuffle(*rrs)
			m = new(dns.Msg)
			m.SetReply(q)
			m.Authoritative = true
			m.Answer = *rrs
		} else {
			// Forwarder lookup
			m, err = forwardRequest(q, r.cfg.forwarder)
			if err != nil {
				fmt.Printf("[RESOLVER] Failed to find answer: %s\n", err)
				m = new(dns.Msg)
				m.SetReply(q)
				m.SetRcode(q, dns.RcodeServerFailure)
			}
		}
	default:
		fmt.Printf("[RESOLVER] Received unsupported DNS Opcode %s",
			dns.OpcodeToString[q.Opcode])
		m = new(dns.Msg)
		m.SetRcode(q, dns.RcodeRefused)
	}
	err = w.WriteMsg(m)
	if err != nil {
		fmt.Printf("[RESOLVER] Failed to reply to client: %s", err)
	}
}

// Shuffle the order of byte arrays, allowing DNS answers to be randomized
func shuffle(rrs []dns.RR) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for n := len(rrs); n > 1; n-- {
		randIndex := r.Intn(n)
		rrs[n-1], rrs[randIndex] = rrs[randIndex], rrs[n-1]
	}
}
