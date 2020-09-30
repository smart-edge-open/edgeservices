// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package main

import (
	"flag"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	logger "github.com/open-ness/common/log"
)

var log = logger.DefaultLogger.WithField("hddl", nil)

func checkHddlService() {
	var err error

	output, err := exec.Command("ps", "-A").Output()
	if err != nil {
		log.Errf("Error executing ps: %+v", err)
	}

	if strings.Contains(string(output), "autoboot") {
		log.Infof("HDDL service is running")
	} else {
		log.Infof("HDDL service is not running")
	}
}

func main() {
	logLvl := flag.String("log", "info", "Log level.\nSupported values: "+
		"debug, info, notice, warning, error, critical, alert, emergency")
	syslogAddr := flag.String("syslog", "", "Syslog address")
	flag.Parse()

	lvl, err := logger.ParseLevel(*logLvl)
	if err != nil {
		log.Errf("Failed to parse log level: %s", err.Error())
		os.Exit(1)
	}
	logger.SetLevel(lvl)

	err = logger.ConnectSyslog(*syslogAddr)
	if err != nil {
		log.Errf("Syslog(%s) connection failed: %s", *syslogAddr, err.Error())
		os.Exit(1)
	}

	log.Infof("HDDL SERVICE watchdog started")

	ticker := time.NewTicker(10 * time.Second)
	done := make(chan bool)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				checkHddlService()
			}
		}
	}()

	sig := <-c
	ticker.Stop()
	done <- true
	log.Infof("HDDL Service Container received %s signal. Aborting...\n", sig)
	os.Exit(0)
}
