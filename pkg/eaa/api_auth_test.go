// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/open-ness/edgenode/pkg/auth"
	"github.com/open-ness/edgenode/pkg/eaa"
)

// PrepareCertificateRequestTemplate prepares a template
// needed to sign a CSR.
// In tests x509.CertificateRequest might be overridden.
func PrepareCertificateRequestTemplate() x509.CertificateRequest {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "testNamespace:testAppId",
			Organization: []string{"TestOrg"},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		EmailAddresses:     []string{"test@test.org"},
	}
	return template
}

// CreateCSR creates a CSR.
func CreateCSR(prvKey crypto.PrivateKey,
	csrTemplate x509.CertificateRequest) string {

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate,
		prvKey)
	Expect(err).ShouldNot(HaveOccurred())

	m := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST",
		Bytes: csrBytes})

	return string(m)
}

var _ = Describe("ApiAuth", func() {
	var (
		clientPriv crypto.PrivateKey
		identity   eaa.AuthIdentity
		err        error
	)
	startStopCh := make(chan bool)
	BeforeEach(func() {

		err = runEaa(startStopCh)
		Expect(err).ShouldNot(HaveOccurred())

		clientPriv, err = ecdsa.GenerateKey(
			elliptic.P256(),
			rand.Reader,
		)
		Expect(err).ShouldNot(HaveOccurred())
	})

	AfterEach(func() {
		stopEaa(startStopCh)
	})

	Describe("/Auth Post", func() {

		Context("Working path", func() {
			Specify("Will return response code set to 200", func() {

				identity.Csr = CreateCSR(clientPriv,
					PrepareCertificateRequestTemplate())

				reqBody, err := json.Marshal(identity)
				Expect(err).ShouldNot(HaveOccurred())

				resp, err := http.Post("http://"+cfg.OpenEndpoint+"/auth", "",
					bytes.NewBuffer(reqBody))
				Expect(err).ShouldNot(HaveOccurred())
				Expect(resp.StatusCode).Should(Equal(
					http.StatusOK))
			})
		})

		Context("Broken JSON in Request Body", func() {
			Specify("Will return response code set to 500", func() {

				identity.Csr = CreateCSR(clientPriv,
					PrepareCertificateRequestTemplate())

				reqBody, err := json.Marshal(identity)
				Expect(err).ShouldNot(HaveOccurred())

				By("Replace of { tp be X incide of JSON body")
				By("JSON parsing should fail!")
				reqBody[0] = 'X'

				resp, err := http.Post("http://"+cfg.OpenEndpoint+"/auth", "",
					bytes.NewBuffer(reqBody))
				Expect(err).ShouldNot(HaveOccurred())
				Expect(resp.StatusCode).Should(Equal(
					http.StatusInternalServerError))
			})
		})

		Context("Invalid CSR format", func() {
			Specify("Will return response code set to 500", func() {

				identity.Csr = "Some_random_string_instead_of_CSR_data"

				reqBody, err := json.Marshal(identity)
				Expect(err).ShouldNot(HaveOccurred())

				By("Our JSON doesn't contain a CSR, but " + string(reqBody))

				resp, err := http.Post("http://"+cfg.OpenEndpoint+"/auth", "",
					bytes.NewBuffer(reqBody))
				Expect(err).ShouldNot(HaveOccurred())
				Expect(resp.StatusCode).Should(
					Equal(http.StatusInternalServerError))
			})
		})

		Context("Invalid private key", func() {
			Specify("Will return response code set to 500", func() {

				// Lets override orivate key
				rsaPrivateKey, err := rsa.GenerateKey(
					rand.Reader, 2048, //512
				)
				Expect(err).ShouldNot(HaveOccurred())

				template := PrepareCertificateRequestTemplate()
				template.SignatureAlgorithm = x509.SHA256WithRSA

				identity.Csr = CreateCSR(rsaPrivateKey,
					template)

				reqBody, err := json.Marshal(identity)
				Expect(err).ShouldNot(HaveOccurred())

				resp, err := http.Post("http://"+cfg.OpenEndpoint+"/auth", "",
					bytes.NewBuffer(reqBody))
				Expect(err).ShouldNot(HaveOccurred())
				Expect(resp.StatusCode).Should(
					Equal(http.StatusInternalServerError))
			})
		})

		Context("IP Verification failed", func() {
			Specify("Will return response code set to 404", func() {

				oldEvaResponse := responseFromEva
				responseFromEva = ""

				identity.Csr = CreateCSR(clientPriv,
					PrepareCertificateRequestTemplate())

				reqBody, err := json.Marshal(identity)
				Expect(err).ShouldNot(HaveOccurred())

				resp, err := http.Post("http://"+cfg.OpenEndpoint+"/auth", "",
					bytes.NewBuffer(reqBody))
				Expect(err).ShouldNot(HaveOccurred())

				Expect(resp.StatusCode).Should(
					Equal(http.StatusUnauthorized))

				responseFromEva = oldEvaResponse
			})
		})
	})
})

func replaceRCACert(isCA bool, start time.Time, stop time.Time) {

	// load private key
	key, err := auth.LoadKey(tempConfCaRootKeyPath)
	Expect(err).ShouldNot(HaveOccurred())

	// create new one
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization: []string{"Test Cert"},
		},
		NotBefore:             start,
		NotAfter:              stop,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		key.(crypto.Signer).Public(),
		key,
	)
	Expect(err).ShouldNot(HaveOccurred())

	newCert, err := x509.ParseCertificate(certDER)
	Expect(err).ShouldNot(HaveOccurred())

	// remove old certificate
	os.Remove(tempConfCaRootPath)

	// save new certificate
	err = auth.SaveCert(tempConfCaRootPath, newCert)
	Expect(err).ShouldNot(HaveOccurred())
}

func replaceEAACert(start time.Time, stop time.Time) {

	rootCaCert, err := auth.LoadCert(tempConfCaRootPath)
	Expect(err).ShouldNot(HaveOccurred())
	eaaKey, err := auth.LoadKey(tempConfServerKeyPath)
	Expect(err).ShouldNot(HaveOccurred())
	rootCaKey, err := auth.LoadKey(tempConfCaRootKeyPath)
	Expect(err).ShouldNot(HaveOccurred())

	// Prepare certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization: []string{"Test Authority"},
			CommonName:   "test.eaa.openness",
		},
		NotBefore:    start,
		NotAfter:     stop,
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Sign the certificate
	signedDerCert, err := x509.CreateCertificate(
		rand.Reader,
		cert,
		rootCaCert,
		eaaKey.(crypto.Signer).Public(),
		rootCaKey)
	Expect(err).ShouldNot(HaveOccurred())

	newCert, err := x509.ParseCertificate(signedDerCert)
	Expect(err).ShouldNot(HaveOccurred())

	// remove old certificate
	os.Remove(tempConfServerCertPath)

	// save new certificate
	err = auth.SaveCert(tempConfServerCertPath, newCert)
	Expect(err).ShouldNot(HaveOccurred())
}

func initCerts() {
	ci := eaa.CertsInfo{
		tempConfCaRootKeyPath,
		tempConfCaRootPath,
		tempConfServerCertPath,
		tempConfServerKeyPath,
		EaaCommonName}

	_, err := eaa.InitRootCA(ci)
	Expect(err).ShouldNot(HaveOccurred())

	_, err = eaa.InitEaaCert(ci)
	Expect(err).ShouldNot(HaveOccurred())
}

func removeCerts() {
	os.Remove(tempConfCaRootPath)
	os.Remove(tempConfServerCertPath)
}

var _ = Describe("CertsValidation", func() {

	Describe("Validate RCA", func() {

		Context("RCA cert is not rootCA", func() {
			Specify("Init of Applicance should fail", func() {

				initCerts()

				// replace certificate
				isCA := false
				start := time.Now().Add(-1 * time.Minute)
				stop := time.Now().Add(1 * time.Minute)
				replaceRCACert(isCA, start, stop)
				startStopCh := make(chan bool)
				err := runEaa(startStopCh) //should fail
				Expect(err).Should(HaveOccurred())
				exitCode := stopEaa(startStopCh)
				Expect(exitCode).NotTo(Equal(0))

				removeCerts()
			})
		})

		Context("RCA cert with start date set in the future", func() {
			Specify("Init of Applicance should fail", func() {

				initCerts()

				// replace certificate
				isCA := false
				start := time.Now().Add(1 * time.Minute)
				stop := time.Now().Add(1 * time.Minute)
				replaceRCACert(isCA, start, stop)
				startStopCh := make(chan bool)
				err := runEaa(startStopCh) //should fail
				Expect(err).Should(HaveOccurred())

				exitCode := stopEaa(startStopCh)
				Expect(exitCode).NotTo(Equal(0))

				removeCerts()
			})
		})

		Context("RCA cert with expiration date set in the past", func() {
			Specify("Init of Applicance should fail", func() {

				initCerts()

				// replace certificate
				isCA := false
				start := time.Now().Add(-1 * time.Minute)
				stop := time.Now().Add(-1 * time.Minute)
				replaceRCACert(isCA, start, stop)
				startStopCh := make(chan bool)
				err := runEaa(startStopCh) //should fail
				Expect(err).Should(HaveOccurred())

				exitCode := stopEaa(startStopCh)
				Expect(exitCode).NotTo(Equal(0))

				removeCerts()
			})
		})
	})

	Describe("Validate EAA Cert", func() {

		Context("EAA cert with start date set in the future", func() {
			Specify("Init of Applicance should fail", func() {

				initCerts()

				// replace certificate
				start := time.Now().Add(1 * time.Minute)
				stop := time.Now().Add(2 * time.Minute)
				replaceEAACert(start, stop)
				startStopCh := make(chan bool)
				err := runEaa(startStopCh)
				Expect(err).Should(HaveOccurred())

				exitCode := stopEaa(startStopCh)
				Expect(exitCode).NotTo(Equal(0))

				removeCerts()
			})
		})

		Context("EAA cert with expiration date set in the past", func() {
			Specify("Init of Applicance should fail", func() {
				initCerts()

				// replace certificate
				start := time.Now().Add(-2 * time.Minute)
				stop := time.Now().Add(-1 * time.Minute)
				replaceEAACert(start, stop)
				startStopCh := make(chan bool)
				err := runEaa(startStopCh) //should fail
				Expect(err).Should(HaveOccurred())

				exitCode := stopEaa(startStopCh)
				Expect(exitCode).NotTo(Equal(0))

				removeCerts()
			})
		})
	})
})
