// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package main

import (
	"fmt"
	"os"

	"github.com/otcshare/edgeservices/pkg/certsigner"
	"github.com/otcshare/edgeservices/pkg/service"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	config, err := rest.InClusterConfig()
	if err != nil {
		fmt.Printf("Failed to get cluster config %s\n", err.Error())
		os.Exit(1)
	}

	cli, err := clientset.NewForConfig(config)
	if err != nil {
		fmt.Printf("Failed to initialize clientset %s\n", err.Error())
		os.Exit(1)
	}

	cs := certsigner.NewCertificateSigner(cli)

	if !service.RunServices([]service.StartFunction{cs.Run}) {
		os.Exit(1)
	}

	service.Log.Infof("Service stopped gracefully")
}
