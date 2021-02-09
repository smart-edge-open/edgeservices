// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"time"

	logger "github.com/open-ness/common/log"
	pb "github.com/open-ness/edgenode/pkg/auth/pb"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	grpcCreds "google.golang.org/grpc/credentials"
)

const dirPerm = os.FileMode(0700)

var log = logger.DefaultLogger.WithField("auth", nil)

// File names used for saving and loading credentials
const (
	KeyName     = "key.pem"
	CertName    = "cert.pem"
	CAChainName = "cacerts.pem"
	CAPoolName  = "root.pem"
)

// Community edition controller server names
const (
	ControllerServerName = "controller.openness"
	EnrollServerName     = "enroll.controller.openness"
)

// credentials stores loaded/received credentials including locally generated
// private key
type credentials struct {
	key         crypto.PrivateKey
	cert        *x509.Certificate
	caChain     []*x509.Certificate
	caPoolCerts []*x509.Certificate
}

// CredentialsClient is the interface that wraps Get method
// Get gets credentials from the endpoint using provided id
type CredentialsClient interface {
	Get(id *pb.Identity, timeout time.Duration,
		endpoint string) (*pb.Credentials, error)
}

// EnrollClient implements CredentialsClient interface
type EnrollClient struct{}

// Get gets credentials from gRPC endpoint using TLS connection
func (c EnrollClient) Get(id *pb.Identity, timeout time.Duration,
	endpoint string) (*pb.Credentials, error) {

	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get system cert pool")
	}
	creds := grpcCreds.NewClientTLSFromCert(pool, EnrollServerName)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := grpc.DialContext(ctx,
		endpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, errors.Wrapf(err,
			"Failed create a connection to %s", endpoint)
	}
	defer func() {
		if err1 := conn.Close(); err1 != nil {
			log.Errf("Failed to close connection: %v", err1)
		}
	}()

	authCLI := pb.NewAuthServiceClient(conn)

	return authCLI.RequestCredentials(ctx, id, grpc.WaitForReady(true))
}

// loadCredentials loads and verifies credentials after
// checking directory/files permissions
func loadCredentials(certsDir string) (*credentials, error) {
	var (
		c   credentials
		err error
	)
	stat, err := os.Stat(certsDir)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get file info")
	}
	if fPerm := stat.Mode().Perm(); fPerm != dirPerm {
		return nil, errors.Errorf(
			"Invalid file permissions. Got: %o Expected: %o", fPerm, dirPerm)
	}

	c.key, err = LoadKey(filepath.Join(certsDir, KeyName))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load key")
	}

	c.cert, err = LoadCert(filepath.Join(certsDir, CertName))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load certificate")
	}

	c.caChain, err = LoadCerts(filepath.Join(certsDir, CAChainName))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load CA chain")
	}

	c.caPoolCerts, err = LoadCerts(filepath.Join(certsDir, CAPoolName))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load CA pool")
	}

	if err := c.verify(); err != nil {
		return nil, errors.Wrap(err, "credentials verification failed")
	}

	return &c, nil
}

// verify verifies credentials
func (c *credentials) verify() error {
	if c == nil {
		return errors.New("Invalid receiver(nil)")
	}

	if c.cert == nil || len(c.caChain) == 0 || len(c.caPoolCerts) == 0 {
		return errors.New("Empty fields found, credentials not loaded?")
	}

	s, ok := c.key.(crypto.Signer)
	if !ok {
		return errors.New("Key is not of (crypto.Signer) type")
	}
	keyDER, err := x509.MarshalPKIXPublicKey(s.Public())
	if err != nil {
		return errors.Wrap(err, "Failed to marshall key")
	}

	if !bytes.Equal(c.cert.RawSubjectPublicKeyInfo, keyDER) {
		return errors.New("Certificate is not signed with key")
	}

	if err := c.cert.CheckSignatureFrom(c.caChain[0]); err != nil {
		return errors.Wrap(err, "Certificate is not signed by CA")
	}
	ok = false
	for _, cert := range c.caPoolCerts {
		if cert.Equal(c.caChain[len(c.caChain)-1]) {
			ok = true
			break
		}
	}
	if !ok {
		return errors.New("CA Pool does not contain CA")
	}
	return nil
}

// save saves credentials in certsDir with 0700 permissions
func (c *credentials) save(certsDir string) error {
	if err := c.verify(); err != nil {
		return err
	}

	if err := os.MkdirAll(certsDir, dirPerm); err != nil {
		return errors.Wrapf(err, "Failed create %s directory", certsDir)
	}
	// If certsDir exists MkdirAll will not change permissions
	if err := os.Chmod(certsDir, dirPerm); err != nil {
		return errors.Wrapf(err, "Failed to set permissions on %s directory",
			certsDir)
	}

	if err := SaveKey(c.key, filepath.Join(certsDir, KeyName)); err != nil {
		return errors.Wrap(err, "Failed to save key")
	}
	if err := SaveCert(filepath.Join(certsDir, CertName), c.cert); err != nil {
		return errors.Wrap(err, "Failed to save certificate")
	}
	if err := SaveCert(filepath.Join(certsDir, CAChainName),
		c.caChain...); err != nil {
		return errors.Wrap(err, "Failed to save CA chain")
	}
	if err := SaveCert(filepath.Join(certsDir, CAPoolName),
		c.caPoolCerts...); err != nil {
		return errors.Wrap(err, "Failed to save CA Pool chain")
	}
	return nil
}

// decodeCerts decodes PEM encoded list of certificates
func decodeCerts(certs []string) ([]*x509.Certificate, error) {
	var decodedCerts []byte
	for _, cert := range certs {
		block, _ := pem.Decode([]byte(cert))
		if block == nil {
			return nil, errors.New("Failed to decode certificates")
		}
		if block.Type != "CERTIFICATE" {
			return nil, errors.Errorf(
				"Invalid block type. Got: %s Expected: CERTIFICATE", block.Type)
		}
		decodedCerts = append(decodedCerts, block.Bytes...)
	}

	return x509.ParseCertificates(decodedCerts)
}

// decodeCredentials decodes pb.Credentials to credentials type
func decodeCredentials(c *pb.Credentials) (*credentials, error) {
	var (
		cr  credentials
		err error
	)

	block, _ := pem.Decode([]byte(c.Certificate))
	if block == nil {
		return nil, errors.New("Failed to decode certificate")
	}
	cr.cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse certificate")
	}

	cr.caChain, err = decodeCerts(c.CaChain)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse CA certificates")
	}

	cr.caPoolCerts, err = decodeCerts(c.CaPool)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse CA pool certificates")
	}

	return &cr, nil
}

// requestCredentials creates a credentials request, sends a request and
// decodes them
func requestCredentials(key crypto.PrivateKey,
	template *x509.CertificateRequest, endpoint string, timeout time.Duration,
	client CredentialsClient) (*credentials, error) {

	csrDER, err := x509.CreateCertificateRequest(
		rand.Reader,
		template,
		key,
	)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create CSR")
	}
	csrPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrDER,
		})
	if csrPEM == nil {
		return nil, errors.New("Failed to encode CSR")
	}

	credentials, err := client.Get(
		&pb.Identity{
			Csr: string(csrPEM),
		},
		timeout,
		endpoint)
	if err != nil {
		return nil, err
	}

	c, err := decodeCredentials(credentials)
	if err != nil {
		return nil, err
	}
	c.key = key

	if err = c.verify(); err != nil {
		return nil, err
	}

	return c, nil
}

// Enroll tries to load credentials from certsDir.
// If loading failed it requests credentials from endpoint and saves
// them to certsDir
func Enroll(certsDir, endpoint string, timeout time.Duration,
	cc CredentialsClient) error {
	if _, err := loadCredentials(certsDir); err == nil {
		log.Info("credentials loaded successfully")
		return nil
	}
	// Avoid recreating the key if possible
	key, err := LoadKey(filepath.Join(certsDir, KeyName))
	if err != nil {
		log.Notice("Creating new key")
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return errors.Wrap(err, "Failed to generate key")
		}

		if err = os.MkdirAll(certsDir, dirPerm); err != nil {
			return errors.Wrapf(err, "Failed create %s directory", certsDir)
		}
		// If certsDir exists MkdirAll will not change permissions
		if err = os.Chmod(certsDir, dirPerm); err != nil {
			return errors.Wrapf(err, "Failed to set permissions on %s",
				certsDir)
		}
		if err = SaveKey(key,
			filepath.Join(certsDir, KeyName)); err != nil {
			return errors.Wrap(err, "Failed to save key")
		}
	}

	log.Infof("Requesting credentials from %s", endpoint)
	c, err := requestCredentials(key, &x509.CertificateRequest{}, endpoint,
		timeout, cc)
	if err != nil {
		return err
	}
	return c.save(certsDir)
}
