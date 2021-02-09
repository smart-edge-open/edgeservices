// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package storage

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"

	logger "github.com/open-ness/common/log"
)

var log = logger.DefaultLogger.WithField("storage", nil)

// BoltDB implements the Storage interface
type BoltDB struct {
	Filename string
	instance *bolt.DB
}

// rrSet Resource Records representing the values for a given type
type rrSet struct {
	Rrtype  uint16   // dns.Rrtype
	Answers [][]byte // All answers for a query type
}

const (
	// TTL is the default Time To Live in seconds for authoritative responses
	TTL uint32 = 10

	// "."
	dot = byte(46)

	// Master represents a master (Authoritative) record
	Master uint16 = iota
)

// DB Buckets
var bkts = map[uint16]map[uint16][]byte{
	Master: {
		dns.TypeA: {65, 68, 68, 82, 52}, // ADDR4
	},
}

// encode data from a struct
func (rrs *rrSet) encode() ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(&rrs)
	if err != nil {
		log.Errf("Encoding error: %s", err)
		return nil, err
	}
	return buf.Bytes(), nil
}

// decode the record into a struct
func decode(data []byte) (*rrSet, error) {
	var rrs *rrSet
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&rrs)
	if err != nil {
		log.Errf("Decoding error: %s", err)
		return nil, err
	}
	return rrs, nil
}

// Start will open the DB file for IO
func (db *BoltDB) Start() error {
	log.Infof("Starting DB from %s", db.Filename)

	var err error
	db.instance, err = bolt.Open(db.Filename, 0660, nil)
	if err != nil {
		return err
	}

	// Create buckets if they do not exist
	err = db.instance.Batch(func(tx *bolt.Tx) error {
		for _, i := range bkts {
			for _, j := range i {
				_, err = tx.CreateBucketIfNotExists(j)
				log.Infof("[DB][%s] Ready", j)
				if err != nil {
					return fmt.Errorf("Bucket initialization error: %s", err)
				}
			}
		}
		return nil
	})
	return err
}

// Stop will close the DB file from IO
func (db *BoltDB) Stop() error {
	if db.instance != nil {
		if err := db.instance.Close(); err != nil {
			log.Errf("DB Shutdown error: %s", err)
			return err
		}
		return nil
	}
	return errors.New("DB already stopped")
}

// SetHostRRSet creates a resource record
func (db *BoltDB) SetHostRRSet(rrtype uint16,
	fqdn []byte, addrs [][]byte) error {

	if rrtype != dns.TypeA {
		return fmt.Errorf("Invalid resource record type (%s),"+
			"only type A supported", dns.TypeToString[rrtype])
	}

	// Make fully qualified
	if !bytes.HasSuffix(fqdn, []byte{dot}) {
		fqdn = append(fqdn, dot)
	}

	err := db.instance.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bkts[Master][rrtype])
		if b == nil {
			return fmt.Errorf("Unable to find bucket for %s",
				bkts[Master][rrtype])
		}

		for i, j := range addrs {
			log.Debugf("[DB][%s] %d %s: %s",
				bkts[Master][rrtype], i+1, fqdn, net.IP(j).String())
		}

		rrs := &rrSet{
			Rrtype:  rrtype,
			Answers: addrs,
		}

		blob, err := rrs.encode()
		if err == nil {
			err = b.Put(fqdn, blob)
		}
		return err
	})
	return err
}

// DelRRSet removes a RR set for a given FQDN and resource type
func (db *BoltDB) DelRRSet(rrtype uint16, fqdn []byte) error {

	// Make fully qualified
	if !bytes.HasSuffix(fqdn, []byte{dot}) {
		fqdn = append(fqdn, dot)
	}

	if _, ok := bkts[Master][rrtype]; ok {
		if err := db.instance.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket(bkts[Master][rrtype])
			if b == nil {
				return fmt.Errorf("Unable to find bucket for %s",
					bkts[Master][rrtype])
			}
			return b.Delete(fqdn)
		}); err != nil {
			return fmt.Errorf("Delete %s: %s", fqdn, err)
		}
		log.Debugf("[DB][%s] Delete %s", bkts[Master][rrtype], fqdn)
		return nil
	}
	return fmt.Errorf("Invalid query type: %s", dns.TypeToString[rrtype])
}

// GetRRSet returns all resources records for an FQDN and resource type
func (db *BoltDB) GetRRSet(name string, rrtype uint16) (*[]dns.RR, error) {
	// Look for Authoritative Answer

	rrs := []dns.RR{}
	ans, err := db.getAuthoritative(name, rrtype)
	if err == nil {
		for _, i := range ans.Answers {
			rr, err := rrForType(name, rrtype, i)
			if err != nil {
				return nil, err
			}
			rrs = append(rrs, rr)
		}
		return &rrs, nil
	}

	return nil, fmt.Errorf("No records found")

}

// getAuthoritative returns authoritative records
func (db *BoltDB) getAuthoritative(name string, rrtype uint16) (*rrSet, error) {
	var v []byte

	fqdn := []byte(name)

	_ = db.instance.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bkts[Master][rrtype])
		if b == nil {
			return fmt.Errorf("Unable to find bucket for %s",
				bkts[Master][rrtype])
		}

		if r := b.Get(fqdn); r != nil {
			v = append(v, r...)
		}
		return nil
	})

	if len(v) != 0 {
		rrs, err := decode(v)
		if err != nil {
			return nil, fmt.Errorf("Failed to decode for %s: %s", fqdn, err)
		}

		log.Debugf("[DB][%s] HIT %s", bkts[Master][rrtype], fqdn)
		return rrs, nil
	}

	return nil, errors.New("No authoritative records found")
}

func rrForType(name string, rrtype uint16, ans []byte) (dns.RR, error) {
	switch rrtype {
	case dns.TypeA:
		r := new(dns.A)
		r.Hdr = dns.RR_Header{
			Name:   name,
			Rrtype: rrtype,
			Class:  dns.ClassINET,
			Ttl:    TTL,
		}
		r.A = net.IP(ans)
		return r, nil
	}
	return nil, fmt.Errorf("Uknown resource for Query type: %d", rrtype)
}
