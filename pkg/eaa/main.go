// Copyright 2019 Intel Corporation and Smart-Edge.com, Inc. All rights reserved
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

	"github.com/smartedgemec/appliance-ce/pkg/config"
	"github.com/smartedgemec/appliance-ce/pkg/util"
	logger "github.com/smartedgemec/log"
)

type services map[string]Service
type consumerConns map[string]ConsumerConnection

type eaaContext struct {
	serviceInfo         services
	consumerConnections consumerConns
	subscriptionInfo    NotificationSubscriptions
	certsEaaCa          Certs
}

// Certs stores certs and keys for root ca and eaa
type Certs struct {
	rca *CertKeyPair
	eaa *CertKeyPair
}

var (
	cfg    Config
	eaaCtx eaaContext

	log = logger.DefaultLogger.WithField("eaa", nil)
)

// Initialize EAA context structures
func Init() error {
	if eaaCtx.serviceInfo != nil || eaaCtx.subscriptionInfo != nil {
		return errors.New("EAA is already initialized")
	}

	eaaCtx.serviceInfo = services{}
	eaaCtx.consumerConnections = consumerConns{}
	eaaCtx.subscriptionInfo = NotificationSubscriptions{}

	return nil
}

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

// Start Edge Application Agent server listening on port read from config file
func RunServer(parentCtx context.Context) error {
	var err error

	if err = Init(); err != nil {
		log.Errf("init error: %#v", err)
		return errors.New("Running EAA module failure: " + err.Error())
	}

	if eaaCtx.certsEaaCa.rca, err = InitRootCA(cfg.Certs); err != nil {
		log.Errf("CA cert craetion error: %#v", err)
		return err
	}

	if eaaCtx.certsEaaCa.eaa, err = InitEaaCert(cfg.Certs); err != nil {
		log.Errf("EAA cert craetion error: %#v", err)
		return err
	}

	certPool, err := CreateAndSetCACertPool(cfg.Certs.CaRootPath)
	if err != nil {
		log.Errf("Cert Pool error: %#v", err)
	}

	router := NewEaaRouter()
	server := &http.Server{
		Addr: cfg.TLSEndpoint,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  certPool,
		},
		Handler: router,
	}

	lis, err := net.Listen("tcp", cfg.TLSEndpoint)
	if err != nil {

		log.Errf("net.Listen error: %+v", err)

		e, ok := err.(*os.SyscallError)
		if ok {
			log.Errf("net.Listen error: %+v", e.Error())
		}
		return err
	}

	go func() {
		<-parentCtx.Done()
		log.Info("Executing graceful stop")
		if err = server.Close(); err != nil {
			log.Errf("Could not close server: %#v", err)
		}
	}()

	defer log.Info("Stopped EAA serving")

	go func() {
		log.Infof("Serving Auth on: %s", cfg.OpenEndpoint)
		authRouter := NewAuthRouter()
		if err = http.ListenAndServe(
			cfg.OpenEndpoint, authRouter); err != nil {
			log.Info("Auth server failure: " + err.Error())
		}
		log.Info("Stopped Auth serving")
	}()

	log.Infof("Serving EAA on: %s", cfg.TLSEndpoint)
	util.Heartbeat(parentCtx, cfg.HeartbeatInterval, func() {
		// TODO: implementation of modules checking
		log.Info("Heartbeat")
	})
	if err = server.ServeTLS(lis, cfg.Certs.ServerCertPath,
		cfg.Certs.ServerKeyPath); err != http.ErrServerClosed {
		log.Errf("server.Serve error: %#v", err)
		return err
	}

	return nil
}

func Run(parentCtx context.Context, cfgPath string) error {
	err := config.LoadJSONConfig(cfgPath, &cfg)
	if err != nil {
		log.Errf("Failed to load config: %#v", err)
		return err
	}
	return RunServer(parentCtx)
}
