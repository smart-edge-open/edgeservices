// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"

	logger "github.com/open-ness/common/log"
	"github.com/open-ness/edgenode/pkg/config"
	"github.com/open-ness/edgenode/pkg/util"
)

type services map[string]Service
type consumerConns map[string]ConsumerConnection

type eaaContext struct {
	serviceInfo         services
	consumerConnections consumerConns
	subscriptionInfo    NotificationSubscriptions
	certsEaaCa          Certs
	cfg                 Config
}

// Certs stores certs and keys for root ca and eaa
type Certs struct {
	rca *CertKeyPair
	eaa *CertKeyPair
}

var (
	log = logger.DefaultLogger.WithField("eaa", nil)
)

// CreateAndSetCACertPool creates and set CA cert pool
func CreateAndSetCACertPool(caFile string) (*x509.CertPool, error) {

	certPool := x509.NewCertPool()

	certs, err := ioutil.ReadFile(filepath.Clean(caFile))
	if err != nil {
		return nil, err
	}

	if res := certPool.AppendCertsFromPEM(certs); !res {
		return nil, errors.New(
			"Failed to append cert to pool")
	}

	return certPool, nil
}

// RunServer starts Edge Application Agent server listening
// on port read from config file
func RunServer(parentCtx context.Context, eaaCtx *eaaContext) error {
	var err error

	eaaCtx.serviceInfo = services{}
	eaaCtx.consumerConnections = consumerConns{}
	eaaCtx.subscriptionInfo = NotificationSubscriptions{}

	if eaaCtx.certsEaaCa.rca, err = InitRootCA(eaaCtx.cfg.Certs); err != nil {
		log.Errf("CA cert creation error: %#v", err)
		return err
	}

	if eaaCtx.certsEaaCa.eaa, err = InitEaaCert(eaaCtx.cfg.Certs); err != nil {
		log.Errf("EAA cert creation error: %#v", err)
		return err
	}

	certPool, err := CreateAndSetCACertPool(eaaCtx.cfg.Certs.CaRootPath)
	if err != nil {
		log.Errf("Cert Pool error: %#v", err)
	}

	router := NewEaaRouter(eaaCtx)
	server := &http.Server{
		Addr: eaaCtx.cfg.TLSEndpoint,
		TLSConfig: &tls.Config{
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    certPool,
			MinVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		},
		Handler: router,
	}

	authRouter := NewAuthRouter(eaaCtx)
	serverAuth := &http.Server{Addr: eaaCtx.cfg.OpenEndpoint,
		Handler: authRouter}

	lis, err := net.Listen("tcp", eaaCtx.cfg.TLSEndpoint)
	if err != nil {

		log.Errf("net.Listen error: %+v", err)

		e, ok := err.(*os.SyscallError)
		if ok {
			log.Errf("net.Listen error: %+v", e.Error())
		}
		return err
	}

	stopServerCh := make(chan bool, 2)

	go func(stopServerCh chan bool) {
		<-parentCtx.Done()
		log.Info("Executing graceful stop")
		if err = server.Close(); err != nil {
			log.Errf("Could not close EAA server: %#v", err)
		}
		if err = serverAuth.Close(); err != nil {
			log.Errf("Could not close Auth server: %#v", err)
		}
		log.Info("EAA server stopped")
		log.Info("Auth server stopped")
		stopServerCh <- true
	}(stopServerCh)

	defer log.Info("Stopped EAA serving")

	go func(stopServerCh chan bool) {
		log.Infof("Serving Auth on: %s", eaaCtx.cfg.OpenEndpoint)
		if err = serverAuth.ListenAndServe(); err != nil {
			log.Info("Auth server error: " + err.Error())
		}
		log.Errf("Stopped Auth serving")
		stopServerCh <- true
	}(stopServerCh)

	log.Infof("Serving EAA on: %s", eaaCtx.cfg.TLSEndpoint)
	util.Heartbeat(parentCtx, eaaCtx.cfg.HeartbeatInterval, func() {
		// TODO: implementation of modules checking
		log.Info("Heartbeat")
	})
	if err = server.ServeTLS(lis, eaaCtx.cfg.Certs.ServerCertPath,
		eaaCtx.cfg.Certs.ServerKeyPath); err != http.ErrServerClosed {
		log.Errf("server.Serve error: %#v", err)
		return err
	}
	<-stopServerCh
	<-stopServerCh
	return nil
}

// Run start EAA
func Run(parentCtx context.Context, cfgPath string) error {
	var eaaCtx eaaContext

	err := config.LoadJSONConfig(cfgPath, &eaaCtx.cfg)
	if err != nil {
		log.Errf("Failed to load config: %#v", err)
		return err
	}

	return RunServer(parentCtx, &eaaCtx)
}
