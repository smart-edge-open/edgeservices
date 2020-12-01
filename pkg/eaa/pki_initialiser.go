// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa

import (
	"crypto"
	"crypto/x509"

	"time"

	"github.com/otcshare/edgenode/pkg/auth"
	"github.com/pkg/errors"
)

// CertKeyPair manages digital certificates.
type CertKeyPair struct {
	x509Cert *x509.Certificate
	prvKey   crypto.PrivateKey
}

// InitEaaCert generates cartificate for server signed by CA
func InitEaaCert(certInfo CertsInfo) (*CertKeyPair, error) {
	var (
		err           error
		eaaKey        crypto.PrivateKey
		signedEaaCert *x509.Certificate
	)

	// Load EAA Key
	if eaaKey, err = auth.LoadKey(certInfo.ServerKeyPath); err != nil {
		return nil, errors.Wrap(err, "LoadKey failed")
	}

	// Load EAA certificate
	if signedEaaCert, err = auth.LoadCert(
		certInfo.ServerCertPath); err != nil {
		return nil, errors.Wrap(err, "LoadCert failed")
	}

	if err = validateCert(signedEaaCert); err != nil {
		return nil, errors.Wrap(err, "EAA cert validation failed")
	}

	return &CertKeyPair{
		x509Cert: signedEaaCert,
		prvKey:   eaaKey,
	}, nil
}

func validateCert(cert *x509.Certificate) error {
	if time.Now().Before(cert.NotBefore) {
		return errors.New("Cartificate expired, valid from: " +
			cert.NotBefore.String())
	}
	if time.Now().After(cert.NotAfter) {
		return errors.New("Cartificate expired, valid to: " +
			cert.NotAfter.String())
	}
	return nil
}

// func validateRCACert(cert *x509.Certificate) error {
// 	if !cert.IsCA {
// 		return errors.New("loaded cert is not CA")
// 	}
// 	return validateCert(cert)
// }
