// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"time"

	edgednspb "github.com/otcshare/edgecontroller/edgednscli/pb"
	"google.golang.org/grpc/credentials"

	"google.golang.org/grpc"
)

// PKIPaths defines paths to files needed to create encrypted grpc connection
type PKIPaths struct {
	CrtPath            string
	KeyPath            string
	CAPath             string
	ServerNameOverride string
}

// AppFlags defines config flags set during sturtup of app
type AppFlags struct {
	Address string
	Set     string
	Del     string
	PKI     *PKIPaths
}

// dnsClient describes a dns client
type dnsClient struct {
	cn *grpc.ClientConn
	cc edgednspb.ControlClient
}

// hostRecordSetStr is an internal type to help to unmarshal JSON file
// to hostRecordSet
type hostRecordSetStr struct {
	recordSetStr
	Addresses []string `json:"addresses"`
}

// recordSetStr is an internal type to help to unmarshal JSON file
// to RecordSet
type recordSetStr struct {
	RecordType string `json:"record_type,omitempty"`
	FQDN       string `json:"fqdn"`
}

const grpcDialTimeoutSec = 1

func readPKI(cfg *AppFlags) (*credentials.TransportCredentials, error) {

	ca, err := ioutil.ReadFile(cfg.PKI.CAPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read CA certificate: %v", err)
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		fmt.Printf("Append certs failed from %s", cfg.PKI.CAPath)
		return nil, fmt.Errorf("Append certs failed from %s",
			cfg.PKI.CAPath)
	}

	srvCert, err := tls.LoadX509KeyPair(cfg.PKI.CrtPath, cfg.PKI.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to load server key pair: %v", err)
	}

	creds := credentials.NewTLS(&tls.Config{
		ServerName:   cfg.PKI.ServerNameOverride,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{srvCert},
		RootCAs:      certPool,
	})

	return &creds, nil
}

func startClient(cfg *AppFlags) (*dnsClient, error) {

	ctx, cancel := context.WithTimeout(context.Background(),
		time.Second*grpcDialTimeoutSec)
	defer cancel()

	tc, err := readPKI(cfg)
	if err != nil {
		return nil, fmt.Errorf("PKI failure: %v", err)
	}

	fmt.Printf("Connecting to EdgeDNS server(%s)", cfg.Address)

	conn, err := grpc.DialContext(ctx, cfg.Address,
		grpc.WithTransportCredentials(*tc), grpc.WithBlock())
	if err != nil {
		return nil, fmt.Errorf("Failed to grpc dial: %v", err)
	}

	return &dnsClient{cn: conn, cc: edgednspb.NewControlClient(conn)}, nil
}

func set(ctx context.Context, cfg *AppFlags,
	hr *edgednspb.HostRecordSet) error {

	client, err := startClient(cfg)
	if err != nil {
		return fmt.Errorf("Failed to start a client: %v", err)
	}
	defer func() {
		if err1 := client.cn.Close(); err1 != nil {
			fmt.Printf("Failed to close client connection: %v", err1)
		}
	}()

	if _, err := client.cc.SetAuthoritativeHost(ctx, hr); err != nil {
		return fmt.Errorf("Failed to send SetAuthoritativeHost: %v", err)
	}

	fmt.Printf(
		"Successfully set authoritative host: [%v, %s, %v]",
		hr.RecordType, hr.Fqdn, hr.Addresses)
	return nil
}

func del(ctx context.Context, cfg *AppFlags, rr *edgednspb.RecordSet) error {

	client, err := startClient(cfg)
	if err != nil {
		return err
	}
	defer func() {
		if err1 := client.cn.Close(); err1 != nil {
			fmt.Printf("Failed to close client connection: %v", err1)
		}
	}()

	if _, err := client.cc.DeleteAuthoritative(ctx, rr); err != nil {
		return fmt.Errorf("Failed to send DeleteAuthoritative: %v", err)
	}

	fmt.Printf("Successfully deleted authoritative host: [%v, %s]",
		rr.RecordType, rr.Fqdn)
	return nil
}

func readFilePath(filePath string) ([]byte, error) {

	_, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("Failed to find file %s: %v", filePath, err)
	}

	jsonFile, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read file %s: %v", filePath, err)
	}

	return jsonFile, nil
}

func parseAddresses(addresses []string) ([][]byte, error) {
	var outputByteSlice [][]byte
	for _, ipString := range addresses {
		ip := net.ParseIP(ipString)
		if ip == nil {
			return outputByteSlice,
				fmt.Errorf("Wrong IP address provided: %s", ipString)
		}
		outputByteSlice = append(outputByteSlice, ip)
	}
	return outputByteSlice, nil
}

func executeSetWithFileCheck(cfg *AppFlags) error {
	jsonSetFile, err := readFilePath(cfg.Set)
	if err != nil {
		return fmt.Errorf("Failed to read JSON file %s: %v",
			cfg.Set, err)
	}

	var hrss hostRecordSetStr
	if err = json.Unmarshal(jsonSetFile, &hrss); err != nil {
		return fmt.Errorf("Failed to parse JSON file %s: %v", cfg.Del, err)
	}

	if hrss.RecordType == "" {
		fmt.Printf("RecordType not provided, setting \"A\" as default")
		hrss.RecordType = "A"
	}

	val, ok := edgednspb.RType_value[hrss.RecordType]
	if !ok {
		return fmt.Errorf("RecordType of HostRecordSet is not valid[%s]. %s",
			hrss.RecordType,
			"Please provide 'None' or 'A' or ... in JSON file")
	}

	adr, err := parseAddresses(hrss.Addresses)
	if err != nil {
		return fmt.Errorf("dns address translation failure: %v", err)
	}

	hrs := edgednspb.HostRecordSet{
		RecordType: edgednspb.RType(val),
		Fqdn:       hrss.FQDN,
		Addresses:  adr}

	return set(context.Background(), cfg, &hrs)
}

func executeDeleteWithFileCheck(cfg *AppFlags) error {
	jsonDeleteFile, err := readFilePath(cfg.Del)
	if err != nil {
		return fmt.Errorf("Failed to read JSON file %s: %v", cfg.Del, err)
	}

	var rss recordSetStr
	if err = json.Unmarshal(jsonDeleteFile, &rss); err != nil {
		return fmt.Errorf("Failed to parse JSON file %s: %v", cfg.Del, err)
	}

	if rss.RecordType == "" {
		fmt.Printf("RecordType not provided, setting \"A\" as default")
		rss.RecordType = "A"
	}

	val, ok := edgednspb.RType_value[rss.RecordType]
	if !ok {
		return fmt.Errorf("RecordType of HostRecordSet is not valid[%s]. %s",
			rss.RecordType,
			"Please provide 'None' or 'A' or ... in JSON file")
	}

	rs := edgednspb.RecordSet{
		RecordType: edgednspb.RType(val),
		Fqdn:       rss.FQDN}

	return del(context.Background(), cfg, &rs)
}

// ExecuteCommands executes set and delete command with file checking.
// There is a possiblity to execute set and delete at a time.
func ExecuteCommands(cfg *AppFlags) error {

	if cfg.Set != "" {
		if err := executeSetWithFileCheck(cfg); err != nil {
			fmt.Printf("set failure: %v", err)
			return err
		}
	}

	if cfg.Del != "" {
		if err := executeDeleteWithFileCheck(cfg); err != nil {
			fmt.Printf("del failure: %v", err)
			return err
		}
	}

	return nil
}
