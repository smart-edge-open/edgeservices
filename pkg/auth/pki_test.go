// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package auth_test

import (
	"bytes"
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
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/open-ness/edgenode/pkg/auth"
	. "github.com/undefinedlabs/go-mpatch"
)

func TestPKI(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "PKI Suite")
}

const (
	errorNone  int = 0
	errorType  int = 1
	errorLen   int = 2
	errorBlock int = 3
)

func genCert(key crypto.PrivateKey, isCA bool) (*x509.Certificate, error) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
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

func getTestCert(cert *x509.Certificate, t int) []byte {
	bigArray := [1024 * 1025]byte{1}
	blockType := "CERTIFICATE"
	blockData := cert.Raw

	switch t {
	case errorType:
		blockType = blockType + "1"
	case errorLen:
		blockData = bigArray[1:]
	case errorBlock:
		blockData = []byte{1}
	}
	encodedCert := pem.EncodeToMemory(
		&pem.Block{
			Type:  blockType,
			Bytes: blockData,
		},
	)
	Expect(encodedCert).ToNot(BeNil())
	return encodedCert
}

var _ = Describe("Key management", func() {
	var (
		key         crypto.PrivateKey
		encodedKey  []byte
		encodedKey1 []byte
		keyPath     = filepath.Join(os.TempDir(), "key.pem")
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
		encodedKey1 = pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY1",
				Bytes: bytes.ToLower(der),
			},
		)
		Expect(encodedKey1).ToNot(BeNil())

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

			_, err = auth.LoadKey("./key.pem")
			Expect(err).To(HaveOccurred())

			err = os.Chmod(keyPath, os.FileMode(0600))
			Expect(err).ToNot(HaveOccurred())

			By("Loading key")
			loadedKey, err := auth.LoadKey(keyPath)
			Expect(err).ToNot(HaveOccurred())
			Expect(loadedKey).To(Equal(key))

			By("Decode the key")
			err = os.Remove(keyPath)
			Expect(err).ToNot(HaveOccurred())
			err = ioutil.WriteFile(keyPath,
				[]byte{1, 2, 3}, os.FileMode(0600))
			Expect(err).ToNot(HaveOccurred())
			_, err = auth.LoadKey(keyPath)
			Expect(err).To(HaveOccurred())

			By("Check the Key type")
			err = os.Remove(keyPath)
			Expect(err).ToNot(HaveOccurred())
			err = ioutil.WriteFile(keyPath,
				encodedKey1, os.FileMode(0600))
			Expect(err).ToNot(HaveOccurred())
			_, err = auth.LoadKey(keyPath)
			Expect(err).To(HaveOccurred())

			By("Make os.Stat occure error")
			var s *os.File
			fd, err := os.Create("/tmp/testfile")
			Expect(err).ToNot(HaveOccurred())
			patche1, err := PatchMethod(os.OpenFile, func(_ string,
				_ int, _ os.FileMode) (*os.File, error) {
				return fd, nil
			})
			Expect(err).ToNot(HaveOccurred())
			defer patche1.Unpatch()
			patche2, err := PatchInstanceMethodByName(reflect.TypeOf(s),
				"Stat", func(_ *os.File) (os.FileInfo, error) {
					return nil, errors.New("Failed")
				})
			Expect(err).ToNot(HaveOccurred())
			defer patche2.Unpatch()
			Expect(err).ToNot(HaveOccurred())
			_, err = auth.LoadKey(keyPath)
			Expect(err).To(HaveOccurred())
			err = os.Remove("/tmp/testfile")
			Expect(err).ToNot(HaveOccurred())
		})
	})
	Describe("SaveKey", func() {
		It("Should save a key to file", func() {
			By("Saving key")
			err := auth.SaveKey(key, keyPath)
			Expect(err).ToNot(HaveOccurred())

			err = auth.SaveKey(key, "")
			Expect(err).To(HaveOccurred())

			err = auth.SaveKey(nil, keyPath)
			Expect(err).To(HaveOccurred())

			By("Check file permissions")
			_, err = os.OpenFile(keyPath, os.O_WRONLY, 0)
			Expect(err).ToNot(HaveOccurred())

			By("Setting file permissions")
			stat, err := os.Stat(keyPath)
			Expect(err).ToNot(HaveOccurred())
			Expect(stat.Mode().Perm()).To(Equal(os.FileMode(0600)))

			data, err := ioutil.ReadFile(keyPath)
			Expect(err).ToNot(HaveOccurred())

			Expect(data).To(Equal(encodedKey))
		})
		It("Must be panic", func() {
			patches, err := PatchMethod(os.OpenFile, func(_ string,
				_ int, _ os.FileMode) (*os.File, error) {
				return nil, nil
			})
			Expect(err).ToNot(HaveOccurred())
			defer patches.Unpatch()
			err = auth.SaveKey(key, keyPath)
			Expect(err).To(HaveOccurred())
		})
		It("Must be panic", func() {
			var s *os.File
			fd, err := os.Create("/tmp/testfile")
			Expect(err).ToNot(HaveOccurred())
			patche1, err := PatchMethod(os.OpenFile, func(_ string,
				_ int, _ os.FileMode) (*os.File, error) {
				return fd, nil
			})
			Expect(err).ToNot(HaveOccurred())
			defer patche1.Unpatch()
			patche2, err := PatchInstanceMethodByName(reflect.TypeOf(s),
				"Write", func(_ *os.File, _ []byte) (int, error) {
					return 0, errors.New("Failed")
				})
			Expect(err).ToNot(HaveOccurred())
			defer patche2.Unpatch()
			Expect(err).ToNot(HaveOccurred())
			err = auth.SaveKey(key, keyPath)
			Expect(err).To(HaveOccurred())
			err = os.Remove("/tmp/testfile")
			Expect(err).ToNot(HaveOccurred())
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

		cert, err = genCert(key, true)
		Expect(err).ToNot(HaveOccurred())
		encodedCert = getTestCert(cert, errorNone)
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

			By("Decode certificates with valid data")
			err = os.Remove(certPath)
			Expect(err).ToNot(HaveOccurred())
			err = ioutil.WriteFile(certPath,
				[]byte{1}, os.FileMode(0600))
			Expect(err).ToNot(HaveOccurred())
			_, err = auth.LoadCerts(certPath)
			Expect(err).To(HaveOccurred())

			By("Valid certificates with valid type")
			os.Remove(certPath)
			encodedInvalidCert := getTestCert(cert, errorType)
			data := append(encodedInvalidCert, encodedInvalidCert...)
			err = ioutil.WriteFile(certPath,
				data, os.FileMode(0600))
			Expect(err).ToNot(HaveOccurred())
			_, err = auth.LoadCerts(certPath)
			Expect(err).To(HaveOccurred())

			By("Valid certificates with valid block data")
			os.Remove(certPath)
			encodedInvalidCert = getTestCert(cert, errorBlock)
			data = append(encodedInvalidCert, encodedInvalidCert...)
			err = ioutil.WriteFile(certPath,
				data, os.FileMode(0600))
			Expect(err).ToNot(HaveOccurred())
			_, err = auth.LoadCerts(certPath)
			Expect(err).To(HaveOccurred())

			By("Valid certificates with too long data")
			os.Remove(certPath)
			encodedInvalidCert = getTestCert(cert, errorLen)
			data = append(encodedInvalidCert, encodedInvalidCert...)
			err = ioutil.WriteFile(certPath,
				data, os.FileMode(0600))
			Expect(err).ToNot(HaveOccurred())
			_, err = auth.LoadCerts(certPath)
			Expect(err).To(HaveOccurred())

			os.Remove(certPath)
			data = append(encodedCert, encodedCert...)
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

			err = auth.SaveCert("", cert)
			Expect(err).To(HaveOccurred())

			By("Setting file permissions")
			stat, err := os.Stat(certPath)
			Expect(err).ToNot(HaveOccurred())
			Expect(stat.Mode().Perm()).To(Equal(os.FileMode(0600)))

			data, err := ioutil.ReadFile(certPath)
			Expect(err).ToNot(HaveOccurred())

			Expect(data).To(Equal(encodedCert))
		})
		It("Must be panic", func() {
			patches, err := PatchMethod(os.OpenFile, func(_ string,
				_ int, _ os.FileMode) (*os.File, error) {
				return nil, nil
			})
			Expect(err).ToNot(HaveOccurred())
			defer patches.Unpatch()
			err = auth.SaveCert(certPath, cert)
			Expect(err).To(HaveOccurred())

		})
		It("Must be panic", func() {
			patches, err := PatchMethod(pem.Encode, func(_ io.Writer, _ *pem.Block) error {
				return errors.New("Failed")
			})
			Expect(err).ToNot(HaveOccurred())
			defer patches.Unpatch()
			err = auth.SaveCert(certPath, cert)
			Expect(err).To(HaveOccurred())
		})
	})
})
