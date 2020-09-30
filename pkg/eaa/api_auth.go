// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa

import (
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
)

type contextKey string

// RequestCredentials handles PKI for an application
func RequestCredentials(w http.ResponseWriter, r *http.Request) {
	var (
		identity    AuthIdentity
		credentials AuthCredentials
	)

	eaaCtx := r.Context().Value(contextKey("appliance-ctx")).(*Context)

	const fName = "/Auth RequestCredentials "

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	err := json.NewDecoder(r.Body).Decode(&identity)
	if err != nil {
		log.Errf(fName+"decode failed: %v", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	host, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Errf(fName+"Cannot retrieve IP from RemoteAddr: %v [%v:%v] %v",
			r.RemoteAddr, host, port, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	cert, err := SignCSR(identity.Csr, eaaCtx)
	if err != nil {
		log.Errf(fName+"failed: %v", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	signedCertBlock := pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if signedCertBlock == nil {
		log.Err(fName + "/failed to enode signed cert")
		return
	}
	rcaBlock := pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE",
			Bytes: eaaCtx.certsEaaCa.rca.x509Cert.Raw})
	if rcaBlock == nil {
		log.Err(fName + "failed to enode rca cert")
		return
	}

	credentials.ID = cert.Subject.CommonName
	credentials.Certificate = string(signedCertBlock)
	credentials.CaChain = []string{string(rcaBlock)}
	credentials.CaPool = []string{string(rcaBlock)}

	encoder := json.NewEncoder(w)
	err = encoder.Encode(credentials)
	if err != nil {
		log.Errf(fName+"encoding output to JSON failed: %s",
			err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Info(fName + " request from CN: " + credentials.ID + ", from IP: " +
		host + " properly handled")
}
