// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package edgedns

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/miekg/dns"
	logger "github.com/open-ness/common/log"
)

var log = logger.DefaultLogger.WithField("edgedns", nil)

// Storage is a backend persistence for all records
type Storage interface {
	Start() error
	Stop() error

	// SetHostRRSet Creates or updates all resource records for a given FQDN
	// 				and resource record type
	//
	// rrtype 		Resource Record Type (A or AAAA)
	// fqdn			Fully Qualified Domain Name
	// addrs		One or more IP addresses for the FQDN
	SetHostRRSet(rrtype uint16, fqdn []byte, addrs [][]byte) error

	// GetRRSet returns all resources records for an FQDN and resource type
	GetRRSet(name string, rrtype uint16) (*[]dns.RR, error)

	// DelRRSet removes a RR set for a given FQDN and resource type
	DelRRSet(rrtype uint16, fqdn []byte) error
}

// ControlServer provides an API to administer the runtime state
// of the Responder records
type ControlServer interface {
	Start(stg Storage) error
	GracefulStop() error
}

// Config contains all runtime configuration parameters
type Config struct {
	Addr4     string
	Port      int
	forwarder string
}

// Responder handles all DNS queries
type Responder struct {
	Sig     chan os.Signal // Shutdown signals
	cfg     Config
	server4 *dns.Server
	storage Storage
	control ControlServer
}

// NewResponder returns a new DNS Responder (Server)
func NewResponder(cfg Config, stg Storage, ctl ControlServer) *Responder {
	return &Responder{
		Sig:     make(chan os.Signal),
		cfg:     cfg,
		storage: stg,
		control: ctl,
	}
}

// Start will register and start all services
func (r *Responder) Start() error {
	log.Infof("Starting Edge DNS Server")

	// Start DB backend
	err := r.storage.Start()
	if err != nil {
		return fmt.Errorf("Unable to start DB: %s", err)
	}

	// Start gRPC API
	err = r.control.Start(r.storage)
	if err != nil {
		return err
	}

	// HandleFunc uses DefaultMsgAcceptFunc,
	// which checks the request and will reject if:
	//
	// * isn't a request (don't respond in that case).
	// * opcode isn't OpcodeQuery or OpcodeNotify
	// * Zero bit isn't zero
	// * has more than 1 question in the question section
	// * has more than 1 RR in the Answer section
	// * has more than 0 RRs in the Authority section
	// * has more than 2 RRs in the Additional section
	dns.HandleFunc(".", r.handleDNSRequest) // responder

	// Start DNS Listeners
	r.startListeners()
	return nil
}

func (r *Responder) startListeners() {

	if len(r.cfg.Addr4) > 0 {
		log.Infof("Starting IPv4 DNS Listener at %s:%d",
			r.cfg.Addr4, r.cfg.Port)
		r.server4 = &dns.Server{Addr: r.cfg.Addr4 + ":" +
			strconv.Itoa(r.cfg.Port), Net: "udp"}
		go func() {
			if err := r.server4.ListenAndServe(); err != nil {
				log.Errf("IPv4 listener error: %s", err)
				r.Sig <- syscall.SIGCHLD
			}
		}()
	}

	if len(r.cfg.Addr4) == 0 {
		log.Infoln("Starting DNS Listener on all addresses")
		r.server4 = &dns.Server{Addr: ":" +
			strconv.Itoa(r.cfg.Port), Net: "udp"}
		go func() {
			if err := r.server4.ListenAndServe(); err != nil {
				log.Errf("Any-address listener error: %s", err)
				r.Sig <- syscall.SIGCHLD
			}
		}()
	}
}

// Stop all listeners
func (r *Responder) Stop() {
	log.Debugln("Edge DNS Server shutdown started")

	if r.server4 != nil {
		log.Debugln("Stopping IPv4 Responder")
		if err := r.server4.Shutdown(); err != nil {
			log.Errf("IPv4 listener shutdown error: %s", err)
		}
	}

	log.Debugln("Stopping API")
	if err := r.control.GracefulStop(); err != nil {
		log.Errf("Control Server Shutdown error: %s", err)
	}

	log.Debugln("Stopping DB")
	if err := r.storage.Stop(); err != nil {
		log.Errf("DB Shutdown error: %s", err)
	}

	log.Infoln("Edge DNS Server stopped")
}

// SetDefaultForwarder allows the default forwarder to be changed
func (r *Responder) SetDefaultForwarder(fwdr string) {
	r.cfg.forwarder = fwdr
}
