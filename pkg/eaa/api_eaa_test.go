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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/smartedgemec/appliance-ce/pkg/eaa"
)

func RequestCredentials(prvKey *ecdsa.PrivateKey) eaa.AuthCredentials {

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.org.com",
			Organization: []string{"TestOrg"},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		EmailAddresses:     []string{"test@test.org"},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template,
		prvKey)
	Expect(err).ShouldNot(HaveOccurred())

	m := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST",
		Bytes: csrBytes})

	var identity eaa.AuthIdentity
	identity.Csr = string(m)

	reqBody, err := json.Marshal(identity)
	Expect(err).ShouldNot(HaveOccurred())

	resp, err := http.Post("http://"+cfg.OpenEndpoint+"/auth", "",
		bytes.NewBuffer(reqBody))
	Expect(err).ShouldNot(HaveOccurred())

	var creds eaa.AuthCredentials
	err = json.NewDecoder(resp.Body).Decode(&creds)
	Expect(err).ShouldNot(HaveOccurred())

	return creds
}

func GetValidTLSClient(prvKey *ecdsa.PrivateKey) *http.Client {

	creds := RequestCredentials(prvKey)

	x509Encoded, err := x509.MarshalECPrivateKey(prvKey)
	Expect(err).ShouldNot(HaveOccurred())

	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY",
		Bytes: x509Encoded})

	cert, err := tls.X509KeyPair([]byte(creds.Certificate), pemEncoded)
	Expect(err).ShouldNot(HaveOccurred())

	certPool := x509.NewCertPool()
	for _, c := range creds.CaPool {
		ok := certPool.AppendCertsFromPEM([]byte(c))
		Expect(ok).To(BeTrue())
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: certPool,
				Certificates: []tls.Certificate{cert},
				ServerName:   EaaCommonName,
			},
		}}

	return client
}

var _ = Describe("ApiEaa", func() {
	BeforeEach(func() {
		runAppliance()
	})

	AfterEach(func() {
		stopAppliance()
	})

	Describe("GET", func() {
		Context("when client owns signed certificate", func() {
			Specify("will return no error and valid response", func() {

				clientPriv, err := ecdsa.GenerateKey(
					elliptic.P256(),
					rand.Reader,
				)
				Expect(err).ShouldNot(HaveOccurred())

				client := GetValidTLSClient(clientPriv)

				tlsResp, err := client.Get("https://" + cfg.TLSEndpoint)
				Expect(err).ShouldNot(HaveOccurred())
				defer tlsResp.Body.Close()

				body, err := ioutil.ReadAll(tlsResp.Body)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(string(body)).To(Equal("404 page not found\n"))
			})
		})
		Context("when client owns unsigned certificate", func() {
			Specify("will return error", func() {

				// create cert pool with rootCA
				certPool := x509.NewCertPool()
				c, err := ioutil.ReadFile(tempConfCaRootPath)
				Expect(err).ShouldNot(HaveOccurred())
				ok := certPool.AppendCertsFromPEM(c)
				Expect(ok).To(BeTrue())

				// generate key for client
				clientPriv, err := ecdsa.GenerateKey(elliptic.P256(),
					rand.Reader)
				Expect(err).ShouldNot(HaveOccurred())

				certTempl := GetCertTempl()
				clientTLSCert := GenerateTLSCert(&certTempl, &certTempl,
					clientPriv, clientPriv)

				// create client with certificate created above
				client := &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{RootCAs: certPool,
							Certificates: []tls.Certificate{clientTLSCert},
							ServerName:   EaaCommonName,
						},
					}}

				_, err = client.Get("https://" + cfg.TLSEndpoint)
				Expect(err).Should(HaveOccurred())
			})
		})
	})

	Describe("Producer registration", func() {
		var (
			prodClient   *http.Client
			prodCert     tls.Certificate
			prodCertPool *x509.CertPool
		)

		BeforeEach(func() {
			prodCertTempl := GetCertTempl()
			prodCertTempl.Subject.CommonName = "namespace-1:producer-1"
			prodCert, prodCertPool = generateSignedClientCert(
				&prodCertTempl)
		})

		BeforeEach(func() {
			prodClient = createHTTPClient(prodCert, prodCertPool)
		})

		Specify("Register: Sanity Case", func() {
			var (
				receivedServList eaa.ServiceList
				expectedServList eaa.ServiceList
			)

			sampleService := eaa.Service{
				Description: "The Sanity Producer",
				EndpointURI: "https://1.2.3.4",
				Notifications: []eaa.NotificationDescriptor{
					{
						Name:    "Event #1",
						Version: "1.0.0",
						Description: "Description for " +
							"Event #1 by Producer #1",
					},
				},
			}

			expectedOutput := strings.NewReader(
				"{\"services\":[{\"urn\":{\"id\"" +
					":\"producer-1\",\"namespace\":\"namespace-1\"}," +
					"\"description\":\"The Sanity Producer\"," +
					"\"endpoint_uri\":\"https://1.2.3.4\"," +
					"\"notifications\":[{\"name\":\"Event #1\"," +
					"\"version\":\"1.0.0\",\"description\"" +
					":\"Description for Event #1 by Producer #1\"}]}]}")

			By("Service struct encoding")
			payload, err := json.Marshal(sampleService)
			Expect(err).ShouldNot(HaveOccurred())

			By("Sending service registration POST request")
			respPost, err := prodClient.Post(
				"https://"+cfg.TLSEndpoint+"/services",
				"application/json; charset=UTF-8",
				bytes.NewBuffer(payload))
			Expect(err).ShouldNot(HaveOccurred())

			By("Comparing POST response code")
			defer respPost.Body.Close()
			Expect(respPost.Status).To(Equal("200 OK"))

			By("Sending service list GET request")
			respGet, err := prodClient.Get(
				"https://" + cfg.TLSEndpoint + "/services")
			Expect(err).ShouldNot(HaveOccurred())

			By("Comparing GET response code")
			defer respGet.Body.Close()
			Expect(respGet.Status).To(Equal("200 OK"))

			By("Service list decoding")
			err = json.NewDecoder(respGet.Body).
				Decode(&receivedServList)
			Expect(err).ShouldNot(HaveOccurred())

			By("Service list encoding")
			err = json.NewDecoder(expectedOutput).
				Decode(&expectedServList)
			Expect(err).ShouldNot(HaveOccurred())

			By("Comparing GET response data")
			Expect(receivedServList).To(Equal(expectedServList))
		})

		Context("two producers", func() {
			var (
				prodClient2   *http.Client
				prodCert2     tls.Certificate
				prodCertPool2 *x509.CertPool
			)

			BeforeEach(func() {
				prodCertTempl2 := GetCertTempl()
				prodCertTempl2.Subject.CommonName = "namespace-2:producer-2"
				prodCert2, prodCertPool2 = generateSignedClientCert(
					&prodCertTempl2)
			})

			BeforeEach(func() {
				prodClient2 = createHTTPClient(prodCert2, prodCertPool2)
			})

			Specify("Register: Two producers", func() {
				var (
					receivedServList eaa.ServiceList
					expectedServList eaa.ServiceList
				)

				sampleService := eaa.Service{
					Description: "example description",
					EndpointURI: "https://1.2.3.4",
					Notifications: []eaa.NotificationDescriptor{
						{
							Name:        "Event #1",
							Version:     "1.0.0",
							Description: "example description",
						},
					},
				}

				sampleService2 := eaa.Service{
					Description: "example description",
					EndpointURI: "https://1.2.3.4",
					Notifications: []eaa.NotificationDescriptor{
						{
							Name:        "Event #2",
							Version:     "1.0.0",
							Description: "example description",
						},
					},
				}

				expectedOutput := strings.NewReader(
					"{\"services\":[" +
						"{\"urn\":{\"id\"" +
						":\"producer-1\",\"namespace\":\"namespace-1\"}," +
						"\"description\":\"example description\"," +
						"\"endpoint_uri\":\"https://1.2.3.4\"," +
						"\"notifications\":[{\"name\":\"Event #1\"," +
						"\"version\":\"1.0.0\",\"description\"" +
						":\"example description\"}]}," +
						"{\"urn\":{\"id\"" +
						":\"producer-2\",\"namespace\":\"namespace-2\"}," +
						"\"description\":\"example description\"," +
						"\"endpoint_uri\":\"https://1.2.3.4\"," +
						"\"notifications\":[{\"name\":\"Event #2\"," +
						"\"version\":\"1.0.0\",\"description\"" +
						":\"example description\"}]}" +
						"]}")

				By("Service struct 1 encoding")
				payload, err := json.Marshal(sampleService)
				Expect(err).ShouldNot(HaveOccurred())

				By("Sending service 1 registration POST request")
				respPost, err := prodClient.Post(
					"https://"+cfg.TLSEndpoint+"/services",
					"application/json; charset=UTF-8",
					bytes.NewBuffer(payload))
				Expect(err).ShouldNot(HaveOccurred())

				By("Comparing POST 1 response code")
				defer respPost.Body.Close()
				Expect(respPost.Status).To(Equal("200 OK"))

				By("Service struct 2 encoding")
				payload2, err := json.Marshal(sampleService2)
				Expect(err).ShouldNot(HaveOccurred())

				By("Sending service 2 registration POST request")
				respPost2, err := prodClient2.Post(
					"https://"+cfg.TLSEndpoint+"/services",
					"application/json; charset=UTF-8",
					bytes.NewBuffer(payload2))
				Expect(err).ShouldNot(HaveOccurred())

				By("Comparing POST 2 response code")
				defer respPost2.Body.Close()
				Expect(respPost2.Status).To(Equal("200 OK"))

				By("Sending service list GET request")
				respGet, err := prodClient.Get(
					"https://" + cfg.TLSEndpoint + "/services")
				Expect(err).ShouldNot(HaveOccurred())

				By("Comparing GET response code")
				defer respGet.Body.Close()
				Expect(respGet.Status).To(Equal("200 OK"))

				By("Service list decoding")
				err = json.NewDecoder(respGet.Body).
					Decode(&receivedServList)
				Expect(err).ShouldNot(HaveOccurred())

				By("Service list encoding")
				err = json.NewDecoder(expectedOutput).
					Decode(&expectedServList)
				Expect(err).ShouldNot(HaveOccurred())

				By("Comparing response data")
				Expect(receivedServList).To(Equal(expectedServList))
			})
		})
	})
})
