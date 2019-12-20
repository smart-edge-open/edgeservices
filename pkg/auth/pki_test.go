// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package auth_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
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
)

func TestPKI(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "PKI Suite")
}

func genCert(key crypto.PrivateKey) (*x509.Certificate, error) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	s, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("Key is not of (crypto.Signer) type")
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template,
		s.Public(), key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

var _ = Describe("Key management", func() {
	var (
		key        crypto.PrivateKey
		encodedKey []byte
		keyPath    = filepath.Join(os.TempDir(), "key.pem")
	)

	BeforeEach(func() {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).ToNot(HaveOccurred())
		der, err := x509.MarshalPKCS8PrivateKey(key)
		Expect(err).ToNot(HaveOccurred())
		encodedKey = pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: der,
			},
		)
		Expect(encodedKey).ToNot(BeNil())

	})
	AfterEach(func() {
		os.Remove(keyPath)
	})
	Describe("LoadKey", func() {
		It("Should load a key from file", func() {
			err := ioutil.WriteFile(keyPath,
				encodedKey, os.FileMode(0644))
			Expect(err).ToNot(HaveOccurred())

			By("Verifying file permissions")
			_, err = auth.LoadKey(keyPath)
			Expect(err).To(HaveOccurred())

			err = os.Chmod(keyPath, os.FileMode(0600))
			Expect(err).ToNot(HaveOccurred())

			By("Loading key")
			loadedKey, err := auth.LoadKey(keyPath)
			Expect(err).ToNot(HaveOccurred())
			Expect(loadedKey).To(Equal(key))

		})
	})

	Describe("SaveKey", func() {
		It("Should save a key to file", func() {
			By("Saving key")
			err := auth.SaveKey(key, keyPath)
			Expect(err).ToNot(HaveOccurred())

			By("Setting file permissions")
			stat, err := os.Stat(keyPath)
			Expect(err).ToNot(HaveOccurred())
			Expect(stat.Mode().Perm()).To(Equal(os.FileMode(0600)))

			data, err := ioutil.ReadFile(keyPath)
			Expect(err).ToNot(HaveOccurred())

			Expect(data).To(Equal(encodedKey))
		})
	})
})

var _ = Describe("Cert management", func() {
	var (
		cert        *x509.Certificate
		encodedCert []byte
		certPath    = filepath.Join(os.TempDir(), "cert.pem")
	)

	BeforeEach(func() {
		var err error
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		Expect(err).ToNot(HaveOccurred())

		cert, err = genCert(key)
		Expect(err).ToNot(HaveOccurred())
		encodedCert = pem.EncodeToMemory(
			&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			},
		)
		Expect(encodedCert).ToNot(BeNil())
	})
	AfterEach(func() {
		os.Remove(certPath)
	})

	Describe("LoadCert", func() {
		It("Should load a certificate from file", func() {
			err := ioutil.WriteFile(certPath,
				encodedCert, os.FileMode(0644))
			Expect(err).ToNot(HaveOccurred())

			By("Verifying file permissions")
			_, err = auth.LoadCert(certPath)
			Expect(err).To(HaveOccurred())

			err = os.Chmod(certPath, os.FileMode(0600))
			Expect(err).ToNot(HaveOccurred())

			By("Loading cert")
			loadedCert, err := auth.LoadCert(certPath)
			Expect(err).ToNot(HaveOccurred())
			Expect(loadedCert).To(Equal(cert))
		})
	})

	Describe("LoadCerts", func() {
		It("Should load certificates from file", func() {
			err := ioutil.WriteFile(certPath,
				[]byte{}, os.FileMode(0600))
			Expect(err).ToNot(HaveOccurred())

			By("Verifying a file with no certificates")
			_, err = auth.LoadCerts(certPath)
			Expect(err).To(HaveOccurred())

			os.Remove(certPath)
			data := append(encodedCert, encodedCert...)
			err = ioutil.WriteFile(certPath,
				data, os.FileMode(0644))
			Expect(err).ToNot(HaveOccurred())

			By("Verifying file permissions")
			fmt.Println(certPath)
			_, err = auth.LoadCerts(certPath)
			Expect(err).To(HaveOccurred())

			err = os.Chmod(certPath, os.FileMode(0600))
			Expect(err).ToNot(HaveOccurred())

			By("Loading certs")
			_, err = auth.LoadCerts(certPath)
			Expect(err).ToNot(HaveOccurred())
			loadedCerts, err := auth.LoadCerts(certPath)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(loadedCerts)).To(Equal(2))
			Expect(loadedCerts[0]).To(Equal(cert))
			Expect(loadedCerts[1]).To(Equal(cert))
		})
	})

	Describe("SaveCert", func() {
		It("Should save a certificate to file", func() {
			By("Saving certificate")
			err := auth.SaveCert(certPath, cert)
			Expect(err).ToNot(HaveOccurred())

			By("Setting file permissions")
			stat, err := os.Stat(certPath)
			Expect(err).ToNot(HaveOccurred())
			Expect(stat.Mode().Perm()).To(Equal(os.FileMode(0600)))

			data, err := ioutil.ReadFile(certPath)
			Expect(err).ToNot(HaveOccurred())

			Expect(data).To(Equal(encodedCert))
		})
	})
})
