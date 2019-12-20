// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package auth_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-ness/edgenode/pkg/auth"
	pb "github.com/open-ness/edgenode/pkg/auth/pb"
)

func TestEnroll(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Enroll Suite")
}

type enrollClientStub struct {
	getHandler func(id *pb.Identity, timeout time.Duration,
		endpoint string) (*pb.Credentials, error)
}

func (c enrollClientStub) Get(id *pb.Identity, timeout time.Duration,
	endpoint string) (*pb.Credentials, error) {
	return c.getHandler(id, timeout, endpoint)
}

var getCredSuccess = func(id *pb.Identity,
	timeout time.Duration, endpoint string) (*pb.Credentials, error) {
	var c pb.Credentials

	csrPEM, _ := pem.Decode([]byte(id.GetCsr()))
	Expect(csrPEM).ToNot(BeNil())
	csr, err := x509.ParseCertificateRequest(csrPEM.Bytes)
	Expect(err).ToNot(HaveOccurred())

	caKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	Expect(err).ToNot(HaveOccurred())
	caCert, err := genCert(caKey)
	Expect(err).ToNot(HaveOccurred())
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     caCert.NotAfter,
	}

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		caCert,
		csr.PublicKey,
		caKey,
	)
	Expect(err).ToNot(HaveOccurred())
	encodedCert := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		},
	)
	Expect(encodedCert).ToNot(BeNil())
	encodedCA := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCert.Raw,
		},
	)
	Expect(encodedCA).ToNot(BeNil())

	c.Certificate = string(encodedCert)
	c.CaChain = []string{string(encodedCA), string(encodedCA)}
	c.CaPool = []string{string(encodedCA), string(encodedCA)}
	return &c, nil
}

var getCredFail = func(id *pb.Identity,
	timeout time.Duration, endpoint string) (*pb.Credentials, error) {
	return nil, errors.New("Get credentials failed")
}

var getCredFailCert = func(id *pb.Identity,
	timeout time.Duration, endpoint string) (*pb.Credentials, error) {
	c, err := getCredSuccess(id, timeout, "")
	Expect(err).ToNot(HaveOccurred())
	c.Certificate = ""
	return c, nil
}

var getCredFailCAChain = func(id *pb.Identity,
	timeout time.Duration, endpoint string) (*pb.Credentials, error) {
	c, err := getCredSuccess(id, timeout, "")
	Expect(err).ToNot(HaveOccurred())
	c.CaChain = []string{}
	return c, nil
}

var getCredFailCAPool = func(id *pb.Identity,
	timeout time.Duration, endpoint string) (*pb.Credentials, error) {
	c, err := getCredSuccess(id, timeout, "")
	Expect(err).ToNot(HaveOccurred())
	c.CaPool = []string{}
	return c, nil
}

var _ = Describe("Enrollment", func() {
	certDir := filepath.Join(os.TempDir(), "certs")
	AfterEach(func() {
		os.RemoveAll(certDir)
	})
	Describe("Requests and verifies credentials", func() {
		When("Received credentials are invalid", func() {
			It("Fails with an error", func() {
				err := auth.Enroll(certDir, "", time.Second,
					enrollClientStub{getCredFail})
				Expect(err).To(HaveOccurred())

				err = auth.Enroll(certDir, "", time.Second,
					enrollClientStub{getCredFailCert})
				Expect(err).To(HaveOccurred())

				err = auth.Enroll(certDir, "", time.Second,
					enrollClientStub{getCredFailCAChain})
				Expect(err).To(HaveOccurred())

				err = auth.Enroll(certDir, "", time.Second,
					enrollClientStub{getCredFailCAPool})
				Expect(err).To(HaveOccurred())
			})
		})
		When("Received credentials are correct", func() {
			It("Saves credentials and returns no error", func() {
				err := auth.Enroll(certDir, "", time.Second,
					enrollClientStub{getCredSuccess})
				Expect(err).ToNot(HaveOccurred())

				Expect(certDir).To(BeADirectory())
				Expect(filepath.Join(certDir, "key.pem")).To(BeAnExistingFile())
				Expect(filepath.Join(certDir, "cert.pem")).To(
					BeAnExistingFile())
				Expect(filepath.Join(certDir, "cacerts.pem")).To(
					BeAnExistingFile())
				Expect(filepath.Join(certDir, "root.pem")).To(
					BeAnExistingFile())

				caPool, err := ioutil.ReadFile(filepath.Join(
					certDir, "root.pem"))
				Expect(err).ToNot(HaveOccurred())
				caChain, err := ioutil.ReadFile(filepath.Join(certDir,
					"cacerts.pem"))
				Expect(err).ToNot(HaveOccurred())
				Expect(caPool).To(Equal(caChain))

				err = auth.Enroll(certDir, "", time.Second,
					enrollClientStub{getCredFail})
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})
})
