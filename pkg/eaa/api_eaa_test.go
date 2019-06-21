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
	"sort"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/smartedgemec/appliance-ce/pkg/eaa"
)

// notifLess is a comparison function for NotificationDescriptor structs
func notifLess(a, b eaa.NotificationDescriptor) bool {
	if a.Name < b.Name {
		return true
	}
	if a.Name == b.Name {
		if a.Version < b.Version {
			return true
		}
	}

	return false
}

// servLess is a comparison function for Service structs
func servLess(a, b eaa.Service) bool {
	if a.URN.ID < b.URN.ID {
		return true
	}
	if a.URN.ID == b.URN.ID {
		if a.URN.Namespace < b.URN.Namespace {
			return true
		}
	}

	return false
}

// sortServiceSlices sorts a lists of Service slices and the Notifications
// slice within all Service structs to help accommodate equality assertions
func sortServiceSlices(slices ...[]eaa.Service) {
	for _, serviceSlice := range slices {
		sort.Slice(serviceSlice,
			func(i, j int) bool {
				return servLess(serviceSlice[i], serviceSlice[j])
			},
		)
		for _, service := range serviceSlice {
			sort.Slice(service.Notifications,
				func(i, j int) bool {
					return notifLess(service.Notifications[i],
						service.Notifications[j])
				},
			)
		}
	}
}

// registerProducer sends a registration POST request to the appliance
func registerProducer(c *http.Client, service eaa.Service,
	subject string) {
	By("Service struct list " + subject + "encoding")
	payload, err := json.Marshal(service)
	Expect(err).ShouldNot(HaveOccurred())

	By("Sending service registration POST " + subject + "request")
	req, _ := http.NewRequest("POST", "https://"+cfg.TLSEndpoint+"/services",
		bytes.NewBuffer(payload))
	respPost, err := c.Do(req)
	Expect(err).ShouldNot(HaveOccurred())

	By("Comparing POST " + subject + "response code")
	defer respPost.Body.Close()
	Expect(respPost.Status).To(Equal("200 OK"))
}

// getServiceList sends a GET request to the appliance and retrieves
// a list of currently registered services
func getServiceList(c *http.Client, list *eaa.ServiceList) {
	By("Sending service list GET request")
	respGet, err := c.Get(
		"https://" + cfg.TLSEndpoint + "/services")
	Expect(err).ShouldNot(HaveOccurred())

	By("Comparing GET response code")
	defer respGet.Body.Close()
	Expect(respGet.Status).To(Equal("200 OK"))

	By("Received service list decoding")
	err = json.NewDecoder(respGet.Body).
		Decode(list)
	Expect(err).ShouldNot(HaveOccurred())
}

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
		err := runAppliance()
		Expect(err).ShouldNot(HaveOccurred())
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
			prodClient       *http.Client
			prodCert         tls.Certificate
			prodCertPool     *x509.CertPool
			accessClient     *http.Client
			receivedServList eaa.ServiceList
			expectedServList eaa.ServiceList
		)

		BeforeEach(func() {
			clientPriv, err := ecdsa.GenerateKey(
				elliptic.P256(),
				rand.Reader,
			)
			Expect(err).ShouldNot(HaveOccurred())
			accessClient = GetValidTLSClient(clientPriv)
		})

		BeforeEach(func() {
			prodCertTempl := GetCertTempl()
			prodCertTempl.Subject.CommonName = "namespace-1:producer-1"
			prodCert, prodCertPool = generateSignedClientCert(
				&prodCertTempl)
		})

		BeforeEach(func() {
			prodClient = createHTTPClient(prodCert, prodCertPool)
		})

		Context("one producer", func() {
			Specify("Register: Sanity Case", func() {
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

				registerProducer(prodClient, sampleService, "")

				getServiceList(accessClient, &receivedServList)

				By("Expected service list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedServList)
				Expect(err).ShouldNot(HaveOccurred())

				sortServiceSlices(expectedServList.Services,
					receivedServList.Services)

				By("Comparing GET response data")
				Expect(receivedServList).To(Equal(expectedServList))
			})

			Specify("Register: Producer registers twice", func() {
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

				expectedOutput := strings.NewReader(
					"{\"services\":[{\"urn\":{\"id\"" +
						":\"producer-1\",\"namespace\":\"namespace-1\"}," +
						"\"description\":\"example description\"," +
						"\"endpoint_uri\":\"https://1.2.3.4\"," +
						"\"notifications\":[{\"name\":\"Event #1\"," +
						"\"version\":\"1.0.0\",\"description\"" +
						":\"example description\"}]}]}")

				registerProducer(prodClient, sampleService, "1 ")
				registerProducer(prodClient, sampleService, "1 (second time) ")

				getServiceList(accessClient, &receivedServList)

				By("Expected service list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedServList)
				Expect(err).ShouldNot(HaveOccurred())

				sortServiceSlices(expectedServList.Services,
					receivedServList.Services)

				By("Comparing GET response data")
				Expect(receivedServList).To(Equal(expectedServList))
			})

			Specify("Register: Producer registers twice"+
				" with different notification", func() {
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
					"{\"services\":[{\"urn\":{\"id\"" +
						":\"producer-1\",\"namespace\":\"namespace-1\"}," +
						"\"description\":\"example description\"," +
						"\"endpoint_uri\":\"https://1.2.3.4\"," +
						"\"notifications\":[{\"name\":\"Event #2\"," +
						"\"version\":\"1.0.0\",\"description\"" +
						":\"example description\"}]}]}")

				registerProducer(prodClient, sampleService, "1 ")
				registerProducer(prodClient, sampleService2,
					"1 (different notification) ")

				getServiceList(accessClient, &receivedServList)

				By("Expected service list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedServList)
				Expect(err).ShouldNot(HaveOccurred())

				sortServiceSlices(expectedServList.Services,
					receivedServList.Services)

				By("Comparing GET response data")
				Expect(receivedServList).To(Equal(expectedServList))
			})

			Specify("Register: Producer registers"+
				" with more than one notification", func() {
				sampleService := eaa.Service{
					Description: "example description",
					EndpointURI: "https://1.2.3.4",
					Notifications: []eaa.NotificationDescriptor{
						{
							Name:        "Event #1",
							Version:     "1.0.0",
							Description: "example description",
						},
						{
							Name:        "Event #2",
							Version:     "1.0.0",
							Description: "example description",
						},
					},
				}

				expectedOutput := strings.NewReader(
					"{\"services\":[{\"urn\":{\"id\"" +
						":\"producer-1\",\"namespace\":\"namespace-1\"}," +
						"\"description\":\"example description\"," +
						"\"endpoint_uri\":\"https://1.2.3.4\"," +
						"\"notifications\":[" +
						"{\"name\":\"Event #1\"," +
						"\"version\":\"1.0.0\",\"description\"" +
						":\"example description\"}," +
						"{\"name\":\"Event #2\"," +
						"\"version\":\"1.0.0\",\"description\"" +
						":\"example description\"}" +
						"]}]}")

				registerProducer(prodClient, sampleService, "")

				getServiceList(accessClient, &receivedServList)

				By("Expected service list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedServList)
				Expect(err).ShouldNot(HaveOccurred())

				sortServiceSlices(expectedServList.Services,
					receivedServList.Services)

				By("Comparing GET response data")
				Expect(receivedServList).To(Equal(expectedServList))
			})

			Specify("Register: Producer registers two notifications"+
				" that vary just by version number", func() {
				sampleService := eaa.Service{
					Description: "example description",
					EndpointURI: "https://1.2.3.4",
					Notifications: []eaa.NotificationDescriptor{
						{
							Name:        "Event #1",
							Version:     "1.0.0",
							Description: "example description",
						},
						{
							Name:        "Event #1",
							Version:     "2.0.0",
							Description: "example description",
						},
					},
				}

				expectedOutput := strings.NewReader(
					"{\"services\":[{\"urn\":{\"id\"" +
						":\"producer-1\",\"namespace\":\"namespace-1\"}," +
						"\"description\":\"example description\"," +
						"\"endpoint_uri\":\"https://1.2.3.4\"," +
						"\"notifications\":[" +
						"{\"name\":\"Event #1\"," +
						"\"version\":\"1.0.0\",\"description\"" +
						":\"example description\"}," +
						"{\"name\":\"Event #1\"," +
						"\"version\":\"2.0.0\",\"description\"" +
						":\"example description\"}" +
						"]}]}")

				registerProducer(prodClient, sampleService, "")

				getServiceList(accessClient, &receivedServList)

				By("Expected service list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedServList)
				Expect(err).ShouldNot(HaveOccurred())

				sortServiceSlices(expectedServList.Services,
					receivedServList.Services)

				By("Comparing GET response data")
				Expect(receivedServList).To(Equal(expectedServList))
			})

			Specify("Register: Producer registers two identical notifications",
				func() {
					// skip test due to the functionality not implemented yet
					Skip("functionality not implemented yet")
					sampleService := eaa.Service{
						Description: "example description",
						EndpointURI: "https://1.2.3.4",
						Notifications: []eaa.NotificationDescriptor{
							{
								Name:        "Event #1",
								Version:     "1.0.0",
								Description: "example description",
							},
							{
								Name:        "Event #1",
								Version:     "1.0.0",
								Description: "example description",
							},
						},
					}

					expectedOutput := strings.NewReader(
						"{\"services\":[{\"urn\":{\"id\"" +
							":\"producer-1\",\"namespace\":\"namespace-1\"}," +
							"\"description\":\"example description\"," +
							"\"endpoint_uri\":\"https://1.2.3.4\"," +
							"\"notifications\":[" +
							"{\"name\":\"Event #1\"," +
							"\"version\":\"1.0.0\",\"description\"" +
							":\"example description\"}" +
							"]}]}")

					registerProducer(prodClient, sampleService, "")

					getServiceList(accessClient, &receivedServList)

					By("Expected service list decoding")
					err := json.NewDecoder(expectedOutput).
						Decode(&expectedServList)
					Expect(err).ShouldNot(HaveOccurred())

					sortServiceSlices(expectedServList.Services,
						receivedServList.Services)

					By("Comparing GET response data")
					Expect(receivedServList).To(Equal(expectedServList))
				})
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

				registerProducer(prodClient, sampleService, "1 ")
				registerProducer(prodClient2, sampleService2, "2 ")

				getServiceList(accessClient, &receivedServList)

				By("Expected service list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedServList)
				Expect(err).ShouldNot(HaveOccurred())

				sortServiceSlices(expectedServList.Services,
					receivedServList.Services)

				By("Comparing response data")
				Expect(receivedServList).To(Equal(expectedServList))
			})

			Specify("Register: Two producers register"+
				" the same notification", func() {
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
							Name:        "Event #1",
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
						"\"notifications\":[{\"name\":\"Event #1\"," +
						"\"version\":\"1.0.0\",\"description\"" +
						":\"example description\"}]}" +
						"]}")

				registerProducer(prodClient, sampleService, "1 ")
				registerProducer(prodClient2, sampleService2, "2 ")

				getServiceList(accessClient, &receivedServList)

				By("Expected service list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedServList)
				Expect(err).ShouldNot(HaveOccurred())

				sortServiceSlices(expectedServList.Services,
					receivedServList.Services)

				By("Comparing response data")
				Expect(receivedServList).To(Equal(expectedServList))
			})
		})
	})
})
