// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/otcshare/edgecontroller/edgednscli"
)

func main() {
	addr := flag.String("address", ":4204", "EdgeDNS API address")
	set := flag.String("set", "",
		"Path to JSON file containing HostRecordSet for set operation")
	del := flag.String("del", "",
		"Path to JSON file containing RecordSet for del operation")

	pkiCrtPath := flag.String("cert", "certs/cert.pem", "PKI Cert Path")
	pkiKeyPath := flag.String("key", "certs/key.pem", "PKI Key Path")
	pkiCAPath := flag.String("ca", "certs/root.pem", "PKI CA Path")
	serverNameOverride := flag.String("name", "",
		"PKI Server Name to override while grpc connection")

	flag.Parse()

	pki := cli.PKIPaths{
		CrtPath:            *pkiCrtPath,
		KeyPath:            *pkiKeyPath,
		CAPath:             *pkiCAPath,
		ServerNameOverride: *serverNameOverride}

	cfg := cli.AppFlags{
		Address: *addr,
		Set:     *set,
		Del:     *del,
		PKI:     &pki}

	if cfg.Set == "" && cfg.Del == "" {
		fmt.Println("No 'set' or 'del' command specified. Please use -h or -help")
		os.Exit(-1)
	}

	if err := cli.ExecuteCommands(&cfg); err != nil {
		fmt.Printf("Execution failed: %v\n", err)
		os.Exit(-1)
	}
}
