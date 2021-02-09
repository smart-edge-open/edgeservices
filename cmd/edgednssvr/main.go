// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	logger "github.com/open-ness/common/log"
	edgedns "github.com/open-ness/edgenode/pkg/edgedns"
	"github.com/open-ness/edgenode/pkg/edgedns/grpc"
	"github.com/open-ness/edgenode/pkg/edgedns/storage"
	"github.com/open-ness/edgenode/pkg/util"
)

var log = logger.DefaultLogger.WithField("main", nil)

func main() {
	logLvl := flag.String("log", "info", "Log level.\nSupported values: "+
		"debug, info, notice, warning, error, critical, alert, emergency")
	syslogAddr := flag.String("syslog", "", "Syslog address")
	v4 := flag.String("4", "", "IPv4 listener address")
	port := flag.Int("port", 53, "listener UDP port")
	sock := flag.String("sock", "/run/edgedns.sock",
		"API socket path used by default. "+
			"This parameter is not used if 'address' is defined.")
	addr := flag.String("address", "",
		"API IP address. If defined, socket parameter is not used.")
	db := flag.String("db", "/var/lib/edgedns/rrsets.db",
		"Database file path")
	fwdr := flag.String("fwdr", "8.8.8.8", "Forwarder")
	hbInterval := flag.Int("hb", 60, "Heartbeat interval in s")
	pkiCrtPath := flag.String("cert", "certs/cert.pem", "PKI Cert Path")
	pkiKeyPath := flag.String("key", "certs/key.pem", "PKI Key Path")
	pkiCAPath := flag.String("ca", "certs/root.pem", "PKI CA Path")
	flag.Parse()

	lvl, err := logger.ParseLevel(*logLvl)
	if err != nil {
		log.Errf("Failed to parse log level: %s", err.Error())
		os.Exit(1)
	}
	logger.SetLevel(lvl)

	err = logger.ConnectSyslog(*syslogAddr)
	if err != nil {
		if *syslogAddr != "" {
			log.Errf("Syslog(%s) connection failed: %s", *syslogAddr, err.Error())
			os.Exit(1)
		} else {
			log.Warningf("Fail to connect to local syslog")
		}
	}

	sockPath := path.Dir(*sock)
	if _, err = os.Stat(sockPath); os.IsNotExist(err) {
		err = os.MkdirAll(sockPath, 0750)
		if err != nil {
			log.Err(err)
			os.Exit(1)
		}
	}

	dbPath := path.Dir(*db)
	if _, err = os.Stat(dbPath); os.IsNotExist(err) {
		err = os.MkdirAll(dbPath, 0750)
		if err != nil {
			log.Err(err)
			os.Exit(1)
		}
	}

	cfg := edgedns.Config{
		Addr4: *v4,
		Port:  *port,
	}

	stg := &storage.BoltDB{
		Filename: *db,
	}

	pki := &grpc.ControlServerPKI{
		Crt: *pkiCrtPath,
		Key: *pkiKeyPath,
		Ca:  *pkiCAPath,
	}

	ctl := &grpc.ControlServer{
		Sock:    *sock,
		Address: *addr,
		PKI:     pki,
	}

	svr := edgedns.NewResponder(cfg, stg, ctl)
	svr.SetDefaultForwarder(*fwdr)
	err = svr.Start()
	defer svr.Stop()

	if err != nil {
		log.Err(err)
		os.Exit(1)
	}

	// Heartbeat routine
	var interval util.Duration
	interval.Duration = time.Second * time.Duration(*hbInterval)
	util.Heartbeat(context.Background(), interval, func() {
		// TODO: implementation of modules checking
		log.Info("Heartbeat")
	})

	// Receive OS signals and listener errors from Start()
	signal.Notify(svr.Sig, syscall.SIGINT, syscall.SIGTERM)
	sig := <-svr.Sig
	switch sig {
	case syscall.SIGCHLD:
		log.Err("Child lisenter/service unexpectedly died")
	default:
		log.Infof("Signal (%v) received, shutting down", sig)
	}
}
