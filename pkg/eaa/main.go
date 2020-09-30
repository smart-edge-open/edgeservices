// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid"
	logger "github.com/open-ness/common/log"
	"github.com/open-ness/edgenode/pkg/config"
	"github.com/open-ness/edgenode/pkg/util"
	"github.com/pkg/errors"
)

type services struct {
	sync.RWMutex
	m map[string]Service
}

type consumerConns struct {
	sync.RWMutex
	m map[string]ConsumerConnection
}

// Context holds all EAA structures
type Context struct {
	serviceInfo         services
	consumerConnections consumerConns
	subscriptionInfo    NotificationSubscriptions
	certsEaaCa          Certs
	cfg                 Config
	MsgBrokerCtx        msgBroker
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

func newKafkaTLSConfig(clientCertFile, clientKeyFile, caCertFile string) (*tls.Config, error) {
	tlsConfig := tls.Config{}

	// Load client cert
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load Client Cert/Key pair")
	}
	tlsConfig.Certificates = []tls.Certificate{clientCert}

	// Load CA cert
	caCertPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile(filepath.Clean(caCertFile))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load CA Cert1")
	}
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig.RootCAs = caCertPool

	return &tlsConfig, nil
}

// InitEaaContext initializes the Eaa Context
func InitEaaContext(cfgPath string, eaaCtx *Context) error {
	eaaCtx.serviceInfo = services{m: make(map[string]Service)}
	eaaCtx.consumerConnections = consumerConns{m: make(map[string]ConsumerConnection)}
	eaaCtx.subscriptionInfo = NotificationSubscriptions{
		m: make(map[UniqueNotif]*ConsumerSubscription)}

	var err error

	err = config.LoadJSONConfig(cfgPath, &eaaCtx.cfg)
	if err != nil {
		log.Errf("Failed to load config: %#v", err)
		return err
	}

	if eaaCtx.certsEaaCa.rca, err = InitRootCA(eaaCtx.cfg.Certs); err != nil {
		log.Errf("CA cert creation error: %#v", err)
		return err
	}

	if eaaCtx.certsEaaCa.eaa, err = InitEaaCert(eaaCtx.cfg.Certs); err != nil {
		log.Errf("EAA cert creation error: %#v", err)
		return err
	}

	return nil
}

// RunServer starts Edge Application Agent server listening
// on port read from config file
func RunServer(parentCtx context.Context, eaaCtx *Context) error {
	var err error

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

	stopServerCh := make(chan bool, 2)
	var lis net.Listener

	// Add Publisher and Subscriber for Services topic
	err = eaaCtx.MsgBrokerCtx.addPublisher(servicesPublisher, servicesTopic, nil)
	if err != nil {
		err = errors.Wrapf(err, "Couldn't add publisher of type %s and ID %s",
			servicesPublisher.String(), servicesTopic)
		goto cleanup
	}
	err = eaaCtx.MsgBrokerCtx.addSubscriber(servicesSubscriber, servicesTopic, nil)
	if err != nil {
		err = errors.Wrapf(err, "Couldn't add subscriber of type %s and ID %s",
			servicesSubscriber.String(), servicesTopic)
		goto cleanup
	}

	lis, err = net.Listen("tcp", eaaCtx.cfg.TLSEndpoint)
	if err != nil {

		log.Errf("net.Listen error: %+v", err)

		e, ok := err.(*os.SyscallError)
		if ok {
			log.Errf("net.Listen error: %+v", e.Error())
		}
		goto cleanup
	}

	go func(stopServerCh chan bool) {
		<-parentCtx.Done()
		log.Info("Executing graceful stop")
		if servErr := server.Close(); servErr != nil {
			log.Errf("Could not close EAA server: %#v", servErr)
		}
		if servErr := serverAuth.Close(); servErr != nil {
			log.Errf("Could not close Auth server: %#v", servErr)
		}
		log.Info("EAA server stopped")
		log.Info("Auth server stopped")
		stopServerCh <- true
	}(stopServerCh)

	defer log.Info("Stopped EAA serving")

	go func(stopServerCh chan bool) {
		log.Infof("Serving Auth on: %s", eaaCtx.cfg.OpenEndpoint)
		if authErr := serverAuth.ListenAndServe(); authErr != nil {
			log.Info("Auth server error: " + authErr.Error())
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
		goto cleanup
	} else {
		err = nil
	}
	<-stopServerCh
	<-stopServerCh

cleanup:
	cleanupErr := eaaCtx.MsgBrokerCtx.removeAll()
	if cleanupErr != nil {
		if err == nil {
			err = cleanupErr
		} else {
			err = errors.Wrap(err, cleanupErr.Error())
		}
	}

	return err
}

// Run start EAA
func Run(parentCtx context.Context, cfgPath string) error {
	var eaaCtx Context

	err := InitEaaContext(cfgPath, &eaaCtx)
	if err != nil {
		log.Errf("Failed to initialize EAA Context: %#v", err)
		return err
	}

	kafkaTLSConfig, err := newKafkaTLSConfig(eaaCtx.cfg.Certs.KafkaUserCertPath,
		eaaCtx.cfg.Certs.KafkaUserKeyPath, eaaCtx.cfg.Certs.KafkaCAPath)
	if err != nil {
		log.Errf("Failed to create a Kafka Message Broker: %#v", err)
		return err
	}

	// Each EAA instance should be in a different Consumer Group to get all Service Updates
	instanceID := uuid.New()
	msgBrokerCtx, err := NewKafkaMsgBroker(&eaaCtx, "EAA_"+instanceID.String(), kafkaTLSConfig)
	if err != nil {
		log.Errf("Failed to create a Kafka Message Broker: %#v", err)
		return err
	}
	eaaCtx.MsgBrokerCtx = msgBrokerCtx

	return RunServer(parentCtx, &eaaCtx)
}
