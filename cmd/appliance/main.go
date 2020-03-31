// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

package main

import (
	"os"
	"time"

	"github.com/open-ness/edgenode/pkg/auth"
	"github.com/open-ness/edgenode/pkg/service"
)

const enrollBackoff = time.Second * 10

func main() {
	for {
		if err := auth.Enroll(service.Cfg.Enroll.CertsDir, service.Cfg.Enroll.Endpoint,
			service.Cfg.Enroll.ConnTimeout.Duration, auth.EnrollClient{}); err != nil {
			service.Log.Errf("Enrollment failed %v\n", err)
			service.Log.Infof("Retrying enrollment in %s...", enrollBackoff)
			time.Sleep(enrollBackoff)
		} else {
			service.Log.Info("Successfully enrolled")
			break
		}
	}

	if !service.RunServices(EdgeServices) {
		os.Exit(1)
	}

	service.Log.Infof("Services stopped gracefully")
}
