// Copyright 2019 Intel Corporation and Smart-Edge.com, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"
	"strings"
	"os/exec"

	logger "github.com/open-ness/common/log"
)

var log = logger.DefaultLogger.WithField("hddl", nil)
var cmd *exec.Cmd

func checkHddlService() {
	var err error
	
	output, err := exec.Command( "ps", "-A" ).Output()
	if err != nil {
		log.Errf("Error executing ps: %+v", err)
	}

	if strings.Contains(string(output), "autoboot"){
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

	c := make(chan os.Signal)
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

	select {
	case sig := <-c:
		ticker.Stop()
		done <- true
		log.Infof("HDDL Service Container received %s signal. Aborting...\n", sig)
		os.Exit(0)
	}
}
