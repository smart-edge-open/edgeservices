// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package certsigner

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"

	"encoding/pem"
	"fmt"
	"time"

	logger "github.com/open-ness/common/log"
	configutil "github.com/open-ness/edgenode/pkg/config"
	"github.com/open-ness/edgenode/pkg/util"

	"github.com/pkg/errors"
	capi "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	capihelper "k8s.io/kubernetes/pkg/apis/certificates/v1"
	"k8s.io/kubernetes/pkg/controller/certificates"
	"k8s.io/kubernetes/pkg/controller/certificates/authority"
)

var (
	log = logger.DefaultLogger.WithField("certsigner", nil)
)

type config struct {
	SignerName     string
	ControllerName string
	ResyncPeriod   util.Duration
	CertTTL        util.Duration
	CaCertPath     string
	CaKeyPath      string
}

// CertificateSigner is a wrapper for Kubernetes Certificate Controller
type CertificateSigner struct {
	clientset kubernetes.Interface
	cfg       config
	ca        authority.CertificateAuthority
}

// NewCertificateSigner creates a CertificateSigner with the provided Clientset
func NewCertificateSigner(clientset kubernetes.Interface) *CertificateSigner {
	c := &CertificateSigner{}
	c.clientset = clientset
	return c
}

// Run creates and starts the Kubernetes Certificate Controller
func (c *CertificateSigner) Run(ctx context.Context, cfgPath string) error {
	logger.Infof("Loading config from path: \"%v\"", cfgPath)
	err := configutil.LoadJSONConfig(cfgPath, &c.cfg)
	if err != nil {
		return errors.Wrapf(err, "Failed to load config from path: \"%v\"", cfgPath)
	}
	logger.Debugf("Loaded config: %#v", c.cfg)

	ca, err := loadCA(c.cfg.CaCertPath, c.cfg.CaKeyPath)
	if err != nil {
		return errors.Wrap(err, "Failed to load CA")
	}
	c.ca = ca

	informerFactory := informers.NewSharedInformerFactory(c.clientset, c.cfg.ResyncPeriod.Duration)
	signerController := certificates.NewCertificateController(c.cfg.ControllerName, c.clientset,
		informerFactory.Certificates().V1().CertificateSigningRequests(), c.handleCSR)

	informerFactory.Start(ctx.Done())
	if err != nil {
		return errors.Wrap(err, "Failed to create signer controller")
	}
	signerController.Run(1, ctx.Done())

	return nil
}

// handleCSR is a callback ran for each CSR object update
func (c *CertificateSigner) handleCSR(csr *capi.CertificateSigningRequest) error {
	log.Infof("New CSR: %v", csr.Name)
	log.Debugf("CSR: %#v", csr)
	if csr.Spec.SignerName != c.cfg.SignerName || !certificates.IsCertificateRequestApproved(csr) {
		log.Debugf("Requested Signer name: \"%v\", Signer name: \"%v\", isApproved: %v", csr.Spec.SignerName,
			c.cfg.SignerName, certificates.IsCertificateRequestApproved(csr))
		log.Info("CSR skipped")
		return nil
	}

	x509cr, err := capihelper.ParseCSR(csr.Spec.Request)
	if err != nil {
		return errors.Wrap(err, "Failed to parse CSR")
	}

	certData, err := c.ca.Sign(x509cr.Raw, authority.PermissiveSigningPolicy{
		TTL:    c.cfg.CertTTL.Duration,
		Usages: csr.Spec.Usages,
	})
	if err != nil {
		return errors.Wrap(err, "Failed to sign certificate")
	}

	csr.Status.Certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certData})
	_, err = c.clientset.CertificatesV1().CertificateSigningRequests().UpdateStatus(context.TODO(), csr,
		metav1.UpdateOptions{})
	if err != nil {
		return errors.Wrap(err, "Failed to update CSR")
	}

	log.Info("CSR successfully signed")

	return nil
}

func loadCA(certPath, keyPath string) (authority.CertificateAuthority, error) {
	caCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return authority.CertificateAuthority{}, errors.Wrapf(err, "Failed to Load key pair: %s, %s", certPath, keyPath)
	}

	cert, err := x509.ParseCertificate(caCert.Certificate[0])
	if err != nil {
		return authority.CertificateAuthority{}, errors.Wrap(err, "Failed to parse certificate")
	}

	signerKey, ok := caCert.PrivateKey.(crypto.Signer)
	if !ok {
		return authority.CertificateAuthority{}, fmt.Errorf("Private key does not implement Signer interface")
	}

	return authority.CertificateAuthority{
		Certificate: cert,
		PrivateKey:  signerKey,
		Backdate:    5 * time.Minute,
	}, nil
}
