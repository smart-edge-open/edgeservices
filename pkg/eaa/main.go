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

	"github.com/smartedgemec/appliance-ce/pkg/config"
	logger "github.com/smartedgemec/log"
)

type services map[string]Service

type eaaContext struct {
	serviceInfo      services
	subscriptionInfo NotificationSubscriptions
}

var (
	cfg    Config
	eaaCtx eaaContext

	log = logger.DefaultLogger.WithField("component", "eaa")
)

// Initialize EAA context structures
func Init() error {
	if eaaCtx.serviceInfo != nil || eaaCtx.subscriptionInfo != nil {
		return errors.New("EAA is already initialized")
	}

	eaaCtx.serviceInfo = services{}
	eaaCtx.subscriptionInfo = NotificationSubscriptions{}

	return nil
}

func CreateAndSetCACertPool(caFile string) (*x509.CertPool, error) {

	certPool := x509.NewCertPool()

	certs, err := ioutil.ReadFile(caFile)
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
	if err := Init(); err != nil {
		log.Errf("init error: %#v", err)
		return errors.New("Running EAA module failure: " + err.Error())
	}

	certPool, err := CreateAndSetCACertPool(cfg.Certs.CaRootPath)
	if err != nil {
		log.Errf("Cert Pool error: %#v", err)
		return err
	}

	router := NewRouter()
	server := &http.Server{
		Addr: cfg.ServerAddr.Hostname + ":" + cfg.ServerAddr.Port,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  certPool,
		},
		Handler: router,
	}

	lis, err := net.Listen("tcp",
		cfg.ServerAddr.Hostname+":"+cfg.ServerAddr.Port)
	if err != nil {
		log.Errf("net.Listen error: %#v", err)
		return err
	}

	go func() {
		<-parentCtx.Done()
		log.Info("Executing graceful stop")
		server.Close()
	}()

	defer log.Info("Stopped serving")

	log.Infof("EAA Server started and listening on port %s",
		cfg.ServerAddr.Port)
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

// TestSubDataInitialization function is meant to satisfy lint checks
// before handlers using the subscription data structures are implemented
// TODO: remove
func TestSubDataInitialization() {
	namespace := NotificationSubscriptions{}

	namespace["testNamespace:notName:notVersion"] =
		ConsumerSubscription{
			serviceSubscriptions: make(map[string]SubscriberIds),
		}

	namespace["testNamespace:notName:notVersion"].
		serviceSubscriptions["testProducerId"] = SubscriberIds{}

	namespace["testNamespace:notName:notVersion"] =
		ConsumerSubscription{
			namespaceSubscriptions: append(
				namespace["testNamespace:notName:notVersion"].
					serviceSubscriptions["testProducerId"], "id1", "id2"),
			serviceSubscriptions: namespace["testNamespace:notName:notVersion"].
				serviceSubscriptions,
		}
}
