// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package main

import (
	"context"
	"flag"
	"os"

	"github.com/otcshare/common/log"
	"github.com/otcshare/edgenode/pkg/certrequester"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	certPath = "./certs/cert.pem"
	keyPath  = "./certs/key.pem"
)

func main() {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Errf("Failed to get cluster config %s\n", err.Error())
		os.Exit(1)
	}

	clientset, err := clientset.NewForConfig(config)
	if err != nil {
		log.Errf("Failed to initialize clientset: %s\n", err.Error())
		os.Exit(1)
	}

	configPath := flag.String("cfg", "certrequest.json", "CSR config path")
	flag.Parse()

	err = certrequester.GetCertificate(context.Background(), clientset, *configPath, certPath, keyPath)
	if err != nil {
		log.Errf("Failed to generate certificate: %s\n", err.Error())
		os.Exit(1)
	}
}
