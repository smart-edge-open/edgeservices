// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package edgedns

import (
	"math/rand"
	"time"

	"github.com/miekg/dns"
)

func (r *Responder) handleDNSRequest(w dns.ResponseWriter, q *dns.Msg) {
	var m *dns.Msg
	var err error

	switch q.Opcode {
	case dns.OpcodeQuery:
		log.Debugf("[RESOLVER] Lookup %s", q.Question[0].Name)

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
				log.Errf("[RESOLVER] Failed to find answer: %s", err)
				m = new(dns.Msg)
				m.SetReply(q)
				m.SetRcode(q, dns.RcodeServerFailure)
			}
		}
	default:
		log.Noticef("[RESOLVER] Received unsupported DNS Opcode %s",
			dns.OpcodeToString[q.Opcode])
		m = new(dns.Msg)
		m.SetRcode(q, dns.RcodeRefused)
	}
	err = w.WriteMsg(m)
	if err != nil {
		log.Errf("[RESOLVER] Failed to reply to client: %s", err)
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
