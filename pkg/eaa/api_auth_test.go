// Copyright 2019 Intel Corporation and Smart-Edge.com, Inc. All rights reserved
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
	"net/http"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/smartedgemec/appliance-ce/pkg/eaa"
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

	BeforeEach(func() {
		runAppliance()
	})

	BeforeEach(func() {
		clientPriv, err = ecdsa.GenerateKey(
			elliptic.P256(),
			rand.Reader,
		)
		Expect(err).ShouldNot(HaveOccurred())
	})

	AfterEach(func() {
		stopAppliance()
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
