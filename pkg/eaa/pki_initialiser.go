// Copyright 2019 Smart-Edge.com, Inc. All rights reserved.
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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"path/filepath"

	"math/big"
	rdm "math/rand"
	"os"
	"time"

	"github.com/smartedgemec/appliance-ce/pkg/auth"

	"github.com/pkg/errors"
)

// EaaCommonName Common Name that EAA uses for TLS connection
const EaaCommonName string = "eaa.community.appliance.mec"

// CertKeyPair manages digital certificates.
type CertKeyPair struct {
	x509Cert *x509.Certificate
	prvKey   crypto.PrivateKey
}

// InitRootCA creates a RootCA by loading the CA certificate and key from the
// certificates paths. If they do not exist or the certificate was not
// signed with the key, a new certificate and key will generated.
func InitRootCA(certPaths CertsInfo) (*CertKeyPair, error) {
	var (
		err error

		key crypto.PrivateKey

		cert    *x509.Certificate
		certDER []byte
	)

	if key, err = auth.LoadKey(certPaths.CaRootKeyPath); err != nil {
		if key, err = ecdsa.GenerateKey(
			elliptic.P256(),
			rand.Reader,
		); err != nil {
			return nil, errors.Wrap(err, "Unable to generate CA key")
		}
		if err = createDir(certPaths.CaRootKeyPath); err != nil {
			return nil, errors.Wrap(err, "Unable to create directory")
		}
		if err = auth.SaveKey(key, certPaths.CaRootKeyPath); err != nil {
			return nil, errors.Wrap(err, "Unable to store CA key")
		}

		log.Info("Generated and stored CA key at: ", certPaths.CaRootKeyPath)
	}

	if cert, err = auth.LoadCert(certPaths.CaRootPath); err != nil {
		if cert, err = generateRootCA(key); err != nil {
			return nil, errors.Wrap(err, "unable to generate root CA")
		}
		if err = createDir(certPaths.CaRootPath); err != nil {
			return nil, errors.Wrap(err, "Unable to create directory")
		}
		if err = auth.SaveCert(certPaths.CaRootPath, cert); err != nil {
			return nil, errors.Wrap(err, "unable to store CA certificate")
		}

		log.Info("Generated and stored CA certificate at: ",
			certPaths.CaRootPath)
	} else {
		if err = validateRCACert(cert); err != nil {
			return nil, errors.Wrap(err, "CA cert validation failed")
		}
	}

	if certDER, err = x509.MarshalPKIXPublicKey(
		key.(crypto.Signer).Public(),
	); err != nil {
		return nil, errors.Wrap(err, "unable to marshal public key")
	}

	// Verify the certificate was signed with the private key
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, certDER) {
		return nil, errors.Wrap(err, "Verification of root ca failed!")
	}

	return &CertKeyPair{
		x509Cert: cert,
		prvKey:   key,
	}, nil
}

// generateRootCA creates a root CA from the private key valid for 3 years.
func generateRootCA(key crypto.PrivateKey) (*x509.Certificate, error) {
	var (
		err          error
		k            crypto.Signer
		ok           bool
		source       rdm.Source
		serialNumber *big.Int
		template     *x509.Certificate
		certDER      []byte
	)

	if k, ok = key.(crypto.Signer); !ok {
		return nil, errors.Wrap(err, "unable to parse key")
	}

	source = rdm.NewSource(time.Now().UnixNano())

	serialNumber = big.NewInt(int64(rdm.New(source).Uint64()))

	template = &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Appliance Root CA Authority"},
		},
		NotBefore:             time.Now().Add(-15 * time.Second),
		NotAfter:              time.Now().Add(3 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		BasicConstraintsValid: true,
	}

	if certDER, err = x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		k.Public(),
		key,
	); err != nil {
		return nil, errors.Wrap(err, "unable to create CA certificate")
	}

	return x509.ParseCertificate(certDER)
}

// InitEaaCert generates cartificate for server signed by CA
func InitEaaCert(certPaths CertsInfo) (*CertKeyPair, error) {
	var (
		err error

		rootCaKey  crypto.PrivateKey
		rootCaCert *x509.Certificate

		eaaKey        crypto.PrivateKey
		signedEaaCert *x509.Certificate
	)

	// Load Root CA cert
	if rootCaCert, err = auth.LoadCert(certPaths.CaRootPath); err != nil {
		return nil, errors.Wrap(err, "Unable to load Root CA Cert")
	}

	// Load Root CA private key
	if rootCaKey, err = auth.LoadKey(certPaths.CaRootKeyPath); err != nil {
		return nil, errors.Wrap(err, "Unable to load Root CA Private Key")
	}

	// Load EAA Key
	if eaaKey, err = auth.LoadKey(certPaths.ServerKeyPath); err != nil {
		// Generate key
		eaaKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, errors.Wrap(err, "Unable to create EAA private key")
		}
		if err = createDir(certPaths.ServerKeyPath); err != nil {
			return nil, errors.Wrap(err, "Unable to create directory")
		}
		if err = auth.SaveKey(
			eaaKey, certPaths.ServerKeyPath); err != nil {
			return nil, errors.Wrap(err, "Unable to store CA key")
		}
		log.Info("Generated and stored EAA key at: ",
			certPaths.ServerKeyPath)
	}

	// Load EAA certificate
	if signedEaaCert, err = auth.LoadCert(
		certPaths.ServerCertPath); err != nil {

		if signedEaaCert, err = generateEAACert(
			rootCaCert, eaaKey, rootCaKey); err != nil {
			return nil, errors.Wrap(err, "Unable to create directory")
		}

		//Store signed cert
		if err = createDir(certPaths.ServerCertPath); err != nil {
			return nil, errors.Wrap(err, "Unable to create directory")
		}
		if err = auth.SaveCert(
			certPaths.ServerCertPath, signedEaaCert); err != nil {
			return nil, errors.Wrap(err, "Unable to store EAA certificate")
		}
		log.Info("Generated and stored EAA cert at: ", certPaths.ServerCertPath)
	} else {
		if err = validateCert(signedEaaCert); err != nil {
			return nil, errors.Wrap(err, "EAA cert validation failed")
		}
	}

	return &CertKeyPair{
		x509Cert: signedEaaCert,
		prvKey:   eaaKey,
	}, nil
}

// generateEAACert generates certificate for EAA
func generateEAACert(rcaCert *x509.Certificate,
	eaaPrivateKey crypto.PrivateKey,
	rootCaKey crypto.PrivateKey) (*x509.Certificate, error) {

	// Prepare certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization: []string{"Appliance Authority"},
			CommonName:   EaaCommonName,
		},
		NotBefore:    time.Now().Add(-15 * time.Second),
		NotAfter:     time.Now().Add(3 * 365 * 24 * time.Hour),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Sign the certificate
	signedDerCert, err := x509.CreateCertificate(
		rand.Reader,
		cert,
		rcaCert, //rootCaCert,
		eaaPrivateKey.(crypto.Signer).Public(),
		rootCaKey)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to create EAA cert data")
	}

	return x509.ParseCertificate(signedDerCert)
}

// SignCSR signs a "PEM-encoded" signing request.
func SignCSR(csrPEM string) (*x509.Certificate, error) {

	block, _ := pem.Decode([]byte(csrPEM))

	if block == nil {
		return nil, errors.New(
			"csr block cannot be decoded")
	}

	if block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New(
			"csr block is not type of CERTIFICATE REQUEST but: " + block.Type)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse CSR")
	}

	source := rdm.NewSource(time.Now().UnixNano())
	serial := big.NewInt(int64(rdm.New(source).Uint64()))

	template := &x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,
		PublicKey:          csr.PublicKey,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		SerialNumber:       serial,
		Issuer:             eaaCtx.certsEaaCa.rca.x509Cert.Subject,
		Subject:            csr.Subject,
		NotBefore:          time.Now(),
		NotAfter:           eaaCtx.certsEaaCa.rca.x509Cert.NotAfter,
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		eaaCtx.certsEaaCa.rca.x509Cert,
		template.PublicKey,
		eaaCtx.certsEaaCa.rca.prvKey,
	)
	if err != nil {
		return nil, errors.Wrapf(err,
			"Unable to sign certificate from csr: %+v", csr)
	}

	return x509.ParseCertificate(certDER)
}

func createDir(filePath string) error {
	dirPerm := os.FileMode(0700)

	basepath := filepath.Dir(filePath)
	if basepath != "" {
		if err := os.MkdirAll(basepath, dirPerm); err != nil {
			return errors.Wrapf(err, "Unable to create %s directory", basepath)
		}

		// If basepath exists MkdirAll will not change its permissions
		if err := os.Chmod(basepath, dirPerm); err != nil {
			return errors.Wrapf(err,
				"Failed to set permissions on %s directory", dirPerm)
		}
	}
	return nil
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

func validateRCACert(cert *x509.Certificate) error {
	if !cert.IsCA {
		return errors.New("loaded cert is not CA")
	}
	return validateCert(cert)
}
