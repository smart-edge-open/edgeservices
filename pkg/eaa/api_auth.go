// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"time"

	pb "github.com/open-ness/edgenode/pkg/eva/internal_pb"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
)

type contextKey string

func validateAppIP(ipAddress string, validationEndpoint string) (bool, error) {

	// Dial to EVA to get Edge Application ID and use it for validation
	conn, err := grpc.Dial(validationEndpoint, grpc.WithInsecure())
	if err != nil {
		return false, errors.Wrapf(err,
			"Failed to create a connection to %s", validationEndpoint)
	}
	defer func() {
		if err1 := conn.Close(); err1 != nil {
			log.Errf("Failed to close connection: %v", err1)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(),
		3*time.Second)
	defer cancel()

	client := pb.NewIPApplicationLookupServiceClient(conn)
	requestBody := pb.IPApplicationLookupInfo{
		IpAddress: ipAddress,
	}

	lookupResult, err := client.GetApplicationByIP(ctx, &requestBody,
		grpc.WaitForReady(true))
	if err != nil {
		return false, errors.Wrap(err, "Cannot get App ID from EVA")
	}

	return lookupResult.AppID != "", nil
}

// RequestCredentials handles PKI for an application
func RequestCredentials(w http.ResponseWriter, r *http.Request) {
	var (
		identity    AuthIdentity
		credentials AuthCredentials
	)

	eaaCtx := r.Context().Value(contextKey("appliance-ctx")).(*eaaContext)

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

	if eaaCtx.cfg.ValidationEndpoint != "" {
		isIPValid, err1 := validateAppIP(host, eaaCtx.cfg.ValidationEndpoint)
		if err1 != nil {
			log.Errf(fName+"IP address validation failed: %v", err1)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if !isIPValid {
			log.Info(fName + "IP address invalid")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
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
