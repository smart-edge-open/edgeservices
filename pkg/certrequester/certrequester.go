// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package certrequester

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"net"

	logger "github.com/smart-edge-open/edgeservices/common/log"
	"github.com/smart-edge-open/edgeservices/pkg/config"
	"github.com/smart-edge-open/edgeservices/pkg/util"
	"github.com/pkg/errors"
	certificatesv1 "k8s.io/api/certificates/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/certificate/csr"
	"k8s.io/client-go/util/keyutil"
)

const (
	megabyte = 1024 * 1024
)

var (
	log = logger.DefaultLogger.WithField("certrequester", nil)
)

// CSRConfig describes the CSR
type CSRConfig struct {
	Name      string
	Subject   pkix.Name
	DNSSANs   []string
	IPSANs    []net.IP
	KeyUsages []certificatesv1.KeyUsage
}

// Config describes the CSR and selects a specific Signer
type Config struct {
	CSR         CSRConfig
	Signer      string
	WaitTimeout util.Duration
}

// GetCertificate creates a CSR that needs to be approved and signed by a specific signer.
// The certificate and private key are then dumped to certPath and keyPath respectively.
func GetCertificate(ctx context.Context, clientset clientset.Interface, cfgPath, certPath, keyPath string) error {
	var cfg Config
	err := config.LoadJSONConfigWithLimit(cfgPath, megabyte, &cfg)
	if err != nil {
		return errors.Wrapf(err, "Failed to load config from path: %v", cfgPath)
	}
	logger.Debugf("Config: %#v", cfg)

	if isKeyPairValid(certPath, keyPath) {
		log.Info("Key pair already exists and is valid")
		return nil
	}

	log.Infof("Continuing to generate key pair...")

	keyData, new, err := keyutil.LoadOrGenerateKeyFile(keyPath)
	if err != nil {
		return errors.Wrapf(err, "Failed to get the private key from: %s", keyPath)
	}
	if new {
		log.Infof("The private key was generated in: %s", keyPath)
	}
	privateKey, err := keyutil.ParsePrivateKeyPEM(keyData)
	if err != nil {
		return errors.Wrapf(err, "Failed to parse the private key from: %s", keyPath)
	}

	// Remove old CSR with the same name
	err = clientset.CertificatesV1().CertificateSigningRequests().Delete(ctx, cfg.CSR.Name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrap(err, "Failed to remove old CSR")
	}

	csrPEM, err := cert.MakeCSR(privateKey, &cfg.CSR.Subject, cfg.CSR.DNSSANs, cfg.CSR.IPSANs)
	if err != nil {
		return errors.Wrap(err, "Failed to create CSR")
	}

	reqName, reqUID, err := csr.RequestCertificate(clientset, csrPEM, cfg.CSR.Name, cfg.Signer, cfg.CSR.KeyUsages,
		privateKey)
	if err != nil {
		return errors.Wrap(err, "CSR Request failed")
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.WaitTimeout.Duration)
	defer cancel()

	certPEM, err := csr.WaitForCertificate(ctx, clientset, reqName, reqUID)
	if err != nil {
		return errors.Wrap(err, "Waiting for certifcate failed")
	}

	err = cert.WriteCert(certPath, certPEM)
	if err != nil {
		return errors.Wrapf(err, "Failed to write the certificate to: %s", certPath)
	}

	logger.Info("CSR successfully signed")

	return nil
}

func isKeyPairValid(certPath, keyPath string) bool {
	_, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Infof("X509 key pair not valid: %v", err.Error())
		return false
	}
	return true
}
