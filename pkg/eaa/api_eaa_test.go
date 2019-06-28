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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/gorilla/websocket"
	"github.com/smartedgemec/appliance-ce/pkg/eaa"
)

const Name1Prod1 = "namespace-1:producer-1"

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

// subscribeConsumer sends a consumer subscription POST request to the appliance
func subscribeConsumer(c *http.Client, notifs []eaa.NotificationDescriptor,
	path string, subject string) {
	By("NotificationDescriptor list " + subject + "encoding")
	payload, err := json.Marshal(notifs)
	Expect(err).ShouldNot(HaveOccurred())

	By("Sending consumer subscription POST " + subject + "request")
	req, _ := http.NewRequest("POST", "https://"+cfg.TLSEndpoint+
		"/subscriptions/"+path, bytes.NewBuffer(payload))
	respPost, err := c.Do(req)
	Expect(err).ShouldNot(HaveOccurred())

	By("Comparing POST " + subject + "response code")
	defer respPost.Body.Close()
	Expect(respPost.Status).To(Equal("201 Created"))
}

// unsubscribeConsumer sends a consumer subscription POST request
// to the appliance
func unsubscribeConsumer(c *http.Client, notifs []eaa.NotificationDescriptor,
	path string, subject string) {
	By("NotificationDescriptor list " + subject + "encoding")
	payload, err := json.Marshal(notifs)
	Expect(err).ShouldNot(HaveOccurred())

	By("Sending consumer unsubscription DELETE " + subject + "request")
	req, _ := http.NewRequest("DELETE", "https://"+cfg.TLSEndpoint+
		"/subscriptions/"+path, bytes.NewBuffer(payload))
	respPost, err := c.Do(req)
	Expect(err).ShouldNot(HaveOccurred())

	By("Comparing DELETE " + subject + "response code")
	defer respPost.Body.Close()
	Expect(respPost.Status).To(Equal("204 No Content"))
}

// connectConsumer sends a consumer notifications GET request to the appliance
func connectConsumer(socket *websocket.Dialer, hostHeader *http.Header,
	subject string) *websocket.Conn {
	By("Sending consumer notification GET " + subject + "request")
	conn, resp, err := socket.Dial("wss://"+cfg.TLSEndpoint+
		"/notifications", *hostHeader)
	Expect(err).ShouldNot(HaveOccurred())

	By("Comparing GET " + subject + "response code")
	defer resp.Body.Close()
	Expect(resp.Status).To(Equal("101 Switching Protocols"))

	return conn
}

// produceEvent sends a notification POST request to the appliance
func produceEvent(c *http.Client, notif eaa.NotificationFromProducer,
	subject string) {
	By("NotificationToConsumer struct " + subject + "encoding")
	payload, err := json.Marshal(notif)
	Expect(err).ShouldNot(HaveOccurred())

	By("Sending produce event POST " + subject + "request")
	req, _ := http.NewRequest("POST", "https://"+cfg.TLSEndpoint+
		"/notifications", bytes.NewBuffer(payload))
	respPost, err := c.Do(req)
	Expect(err).ShouldNot(HaveOccurred())

	By("Comparing POST " + subject + "response code")
	defer respPost.Body.Close()
	Expect(respPost.Status).To(Equal("202 Accepted"))
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

// getMsgFromConn retrieves a message from a connection and parses
// it to a notification struct
func getMsgFromConn(conn *websocket.Conn, response *eaa.NotificationToConsumer,
	subject string) {
	conn.SetReadDeadline(time.Now().Add(time.Second * 3))
	By("Reading message from web socket " + subject + "connection")
	_, message, err := conn.ReadMessage()
	Expect(err).ShouldNot(HaveOccurred())

	output := bytes.NewReader(message)

	By("Received notification struct " + subject + "decoding")
	err = json.NewDecoder(output).
		Decode(response)
	Expect(err).ShouldNot(HaveOccurred())
}

// checkNoMsgFromConn checks that not message has been received
// from the connection
func checkNoMsgFromConn(conn *websocket.Conn, subject string) {
	conn.SetReadDeadline(time.Now().Add(time.Second * 3))
	By("Reading message from web socket " + subject + "connection")
	_, _, err := conn.ReadMessage()
	Expect(err).Should(HaveOccurred())
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
			prodCertTempl.Subject.CommonName = Name1Prod1
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

	Describe("Namespace notification dispatch", func() {
		var (
			prodClient    *http.Client
			prodCert      tls.Certificate
			prodCertPool  *x509.CertPool
			consClient    *http.Client
			consCert      tls.Certificate
			consCertPool  *x509.CertPool
			consSocket    *websocket.Dialer
			consHeader    http.Header
			receivedNotif eaa.NotificationToConsumer
			expectedNotif eaa.NotificationToConsumer
		)

		BeforeEach(func() {
			prodCertTempl := GetCertTempl()
			prodCertTempl.Subject.CommonName = Name1Prod1
			prodCert, prodCertPool = generateSignedClientCert(
				&prodCertTempl)
			consCommonName := "namespace-1:testAppID-1"
			consHeader = http.Header{}
			consHeader.Add("Host", consCommonName)
			consCertTempl := GetCertTempl()
			consCertTempl.Subject.CommonName = consCommonName
			consCert, consCertPool = generateSignedClientCert(
				&consCertTempl)
		})

		BeforeEach(func() {
			prodClient = createHTTPClient(prodCert, prodCertPool)
			consClient = createHTTPClient(consCert, consCertPool)
			consSocket = createWebSocDialer(consCert, consCertPool)
		})

		Context("one consumer", func() {
			Specify("Namespace Notification: 1 Event from 1 Producer"+
				" to 1 Consumer", func() {
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

				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "Event #1",
						Version: "1.0.0",
					},
				}

				sampleEvent := eaa.NotificationFromProducer{
					Name:    "Event #1",
					Version: "1.0.0",
					Payload: json.RawMessage(`{"msg":"PING"}`),
				}

				expectedOutput := strings.NewReader(
					"{\"producer\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"name\":\"Event #1\",\"version\":\"1.0.0\"," +
						"\"payload\":{\"msg\":\"PING\"}}")

				registerProducer(prodClient, sampleService, "")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1", "")

				conn := connectConsumer(consSocket, &consHeader, "")
				defer conn.Close()

				produceEvent(prodClient, sampleEvent, "")

				By("Expected notification struct decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedNotif)
				Expect(err).ShouldNot(HaveOccurred())

				getMsgFromConn(conn, &receivedNotif, "")

				By("Comparing web socket response data")
				Expect(receivedNotif).To(Equal(expectedNotif))
			})

			Specify("Namespace Notification after canceling subscription"+
				" (1 Consumer)", func() {
				sampleService := eaa.Service{
					Description: "The Example Producer #1",
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

				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "Event #1",
						Version: "1.0.0",
					},
				}

				sampleEvent := eaa.NotificationFromProducer{
					Name:    "Event #1",
					Version: "1.0.0",
					Payload: json.RawMessage(`{"msg":"PING"}`),
				}

				expectedOutput := strings.NewReader(
					"{\"producer\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"name\":\"Event #1\",\"version\":\"1.0.0\"," +
						"\"payload\":{\"msg\":\"PING\"}}")

				registerProducer(prodClient, sampleService, "")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1", "")

				conn := connectConsumer(consSocket, &consHeader, "")
				defer conn.Close()

				produceEvent(prodClient, sampleEvent, "")

				By("Expected notification struct decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedNotif)
				Expect(err).ShouldNot(HaveOccurred())

				getMsgFromConn(conn, &receivedNotif, "")

				By("Comparing web socket response data")
				Expect(receivedNotif).To(Equal(expectedNotif))

				unsubscribeConsumer(consClient, sampleNotifications,
					"namespace-1", "")

				produceEvent(prodClient, sampleEvent, "")

				checkNoMsgFromConn(conn, "")
			})

			Specify("Consumer gets Notification if it is subscribed"+
				" before producer registered", func() {
				sampleService := eaa.Service{
					Description: "The Sanity Producer",
					EndpointURI: "https://1.2.3.4",
					Notifications: []eaa.NotificationDescriptor{
						{
							Name:    "Event #100",
							Version: "7.1.0",
							Description: "Description for " +
								"Event #1 by Producer #1",
						},
					},
				}

				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "Event #100",
						Version: "7.1.0",
					},
				}

				sampleEvent := eaa.NotificationFromProducer{
					Name:    "Event #100",
					Version: "7.1.0",
					Payload: json.RawMessage(`{"msg":"PING"}`),
				}

				expectedOutput := strings.NewReader(
					"{\"producer\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"name\":\"Event #100\",\"version\":\"7.1.0\"," +
						"\"payload\":{\"msg\":\"PING\"}}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1", "")

				conn := connectConsumer(consSocket, &consHeader, "")
				defer conn.Close()

				registerProducer(prodClient, sampleService, "")

				produceEvent(prodClient, sampleEvent, "")

				By("Expected notification struct decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedNotif)
				Expect(err).ShouldNot(HaveOccurred())

				getMsgFromConn(conn, &receivedNotif, "")

				By("Comparing web socket response data")
				Expect(receivedNotif).To(Equal(expectedNotif))
			})

			Context("two producers", func() {
				var (
					prodClient2    *http.Client
					prodCert2      tls.Certificate
					prodCertPool2  *x509.CertPool
					prodCertTempl2 x509.Certificate
					receivedNotif2 eaa.NotificationToConsumer
					expectedNotif2 eaa.NotificationToConsumer
				)

				JustBeforeEach(func() {
					prodCert2, prodCertPool2 = generateSignedClientCert(
						&prodCertTempl2)
					prodClient2 = createHTTPClient(prodCert2, prodCertPool2)
				})

				Context("one namespace", func() {
					BeforeEach(func() {
						prodCertTempl2 = GetCertTempl()
						prodCertTempl2.Subject.CommonName =
							"namespace-1:producer-2"
					})

					Specify("Namespace Notification: 1 Event from 2 Producers"+
						" to 1 Consumer", func() {
						sampleService := eaa.Service{
							Description: "The Example producer #1",
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

						sampleService2 := eaa.Service{
							Description: "The Example producer #2",
							EndpointURI: "https://1.2.3.5",
							Notifications: []eaa.NotificationDescriptor{
								{
									Name:    "Event #1",
									Version: "1.0.0",
									Description: "Description for " +
										"Event #1 by Producer #2",
								},
							},
						}

						sampleNotifications := []eaa.NotificationDescriptor{
							{
								Name:    "Event #1",
								Version: "1.0.0",
							},
						}

						sampleEvent := eaa.NotificationFromProducer{
							Name:    "Event #1",
							Version: "1.0.0",
							Payload: json.RawMessage(`{"msg":"PING"}`),
						}

						expectedOutput := strings.NewReader(
							"{\"producer\":" +
								"{\"id\":\"producer-1\"," +
								"\"namespace\":\"namespace-1\"}," +
								"\"name\":\"Event #1\",\"version\":\"1.0.0\"," +
								"\"payload\":{\"msg\":\"PING\"}}")

						expectedOutput2 := strings.NewReader(
							"{\"producer\":" +
								"{\"id\":\"producer-2\"," +
								"\"namespace\":\"namespace-1\"}," +
								"\"name\":\"Event #1\",\"version\":\"1.0.0\"," +
								"\"payload\":{\"msg\":\"PING\"}}")

						registerProducer(prodClient, sampleService, "1 ")
						registerProducer(prodClient2, sampleService2, "2 ")

						subscribeConsumer(consClient, sampleNotifications,
							"namespace-1", "")

						conn := connectConsumer(consSocket, &consHeader, "")
						defer conn.Close()

						produceEvent(prodClient, sampleEvent, "1 ")

						By("Expected notification struct 1 decoding")
						err := json.NewDecoder(expectedOutput).
							Decode(&expectedNotif)
						Expect(err).ShouldNot(HaveOccurred())

						getMsgFromConn(conn, &receivedNotif, "1 ")

						By("Comparing web socket response data (1/2)")
						Expect(receivedNotif).To(Equal(expectedNotif))

						produceEvent(prodClient2, sampleEvent, "2 ")

						By("Expected notification struct 2 decoding")
						err = json.NewDecoder(expectedOutput2).
							Decode(&expectedNotif2)
						Expect(err).ShouldNot(HaveOccurred())

						getMsgFromConn(conn, &receivedNotif2, "2 ")

						By("Comparing web socket response data (2/2)")
						Expect(receivedNotif2).To(Equal(expectedNotif2))
					})
				})
				Context("two namespaces", func() {
					BeforeEach(func() {
						prodCertTempl2 = GetCertTempl()
						prodCertTempl2.Subject.CommonName =
							"namespace-2:producer-2"
					})

					Specify("Two Namespaces notify single Consumer", func() {
						sampleService := eaa.Service{
							Description: "The Example producer #1",
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

						sampleService2 := eaa.Service{
							Description: "The Example producer #2",
							EndpointURI: "https://1.2.3.4",
							Notifications: []eaa.NotificationDescriptor{
								{
									Name:    "Event #1",
									Version: "1.0.0",
									Description: "Description for " +
										"Event #1 by Producer #2",
								},
							},
						}

						sampleNotifications := []eaa.NotificationDescriptor{
							{
								Name:    "Event #1",
								Version: "1.0.0",
							},
						}

						sampleEvent := eaa.NotificationFromProducer{
							Name:    "Event #1",
							Version: "1.0.0",
							Payload: json.RawMessage(`{"msg":"PING"}`),
						}

						expectedOutput := strings.NewReader(
							"{\"producer\":" +
								"{\"id\":\"producer-1\"," +
								"\"namespace\":\"namespace-1\"}," +
								"\"name\":\"Event #1\",\"version\":\"1.0.0\"," +
								"\"payload\":{\"msg\":\"PING\"}}")

						expectedOutput2 := strings.NewReader(
							"{\"producer\":" +
								"{\"id\":\"producer-2\"," +
								"\"namespace\":\"namespace-2\"}," +
								"\"name\":\"Event #1\",\"version\":\"1.0.0\"," +
								"\"payload\":{\"msg\":\"PING\"}}")

						registerProducer(prodClient, sampleService, "1 ")
						registerProducer(prodClient2, sampleService2, "2 ")

						subscribeConsumer(consClient, sampleNotifications,
							"namespace-1", "")
						subscribeConsumer(consClient, sampleNotifications,
							"namespace-2", "")

						conn := connectConsumer(consSocket, &consHeader, "")
						defer conn.Close()

						produceEvent(prodClient, sampleEvent, "1 ")

						By("Expected notification struct 1 decoding")
						err := json.NewDecoder(expectedOutput).
							Decode(&expectedNotif)
						Expect(err).ShouldNot(HaveOccurred())

						getMsgFromConn(conn, &receivedNotif, "1 ")

						By("Comparing web socket response data (1/2)")
						Expect(receivedNotif).To(Equal(expectedNotif))

						produceEvent(prodClient2, sampleEvent, "2 ")

						By("Expected notification struct 2 decoding")
						err = json.NewDecoder(expectedOutput2).
							Decode(&expectedNotif2)
						Expect(err).ShouldNot(HaveOccurred())

						getMsgFromConn(conn, &receivedNotif2, "2 ")

						By("Comparing web socket response data (2/2)")
						Expect(receivedNotif2).To(Equal(expectedNotif2))
					})

					Specify("Consumer doesn't get Notification from Namespace"+
						" it did't subscribe to", func() {
						sampleService := eaa.Service{
							Description: "The Example producer #1",
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

						sampleService2 := eaa.Service{
							Description: "The Example producer #2",
							EndpointURI: "https://1.2.3.4",
							Notifications: []eaa.NotificationDescriptor{
								{
									Name:    "Event #100",
									Version: "7.1.0",
									Description: "Description for " +
										"Event #100 by Producer #2",
								},
							},
						}

						sampleNotifications := []eaa.NotificationDescriptor{
							{
								Name:    "Event #100",
								Version: "7.1.0",
							},
						}

						sampleEvent := eaa.NotificationFromProducer{
							Name:    "Event #1",
							Version: "1.0.0",
							Payload: json.RawMessage(`{"msg":"PING"}`),
						}

						sampleEvent2 := eaa.NotificationFromProducer{
							Name:    "Event #100",
							Version: "7.1.0",
							Payload: json.RawMessage(`{"msg":"PING"}`),
						}

						expectedOutput := strings.NewReader(
							"{\"producer\":" +
								"{\"id\":\"producer-2\"," +
								"\"namespace\":\"namespace-2\"}," +
								"\"name\":\"Event #100\"," +
								"\"version\":\"7.1.0\"," +
								"\"payload\":{\"msg\":\"PING\"}}")

						registerProducer(prodClient, sampleService, "1 ")
						registerProducer(prodClient2, sampleService2, "2 ")

						subscribeConsumer(consClient, sampleNotifications,
							"namespace-2", "")

						conn := connectConsumer(consSocket, &consHeader, "")
						defer conn.Close()

						produceEvent(prodClient2, sampleEvent2, "2 ")

						By("Expected notification struct 2 decoding")
						err := json.NewDecoder(expectedOutput).
							Decode(&expectedNotif)
						Expect(err).ShouldNot(HaveOccurred())

						getMsgFromConn(conn, &receivedNotif, "2 ")

						By("Comparing web socket response data")
						Expect(receivedNotif).To(Equal(expectedNotif))

						produceEvent(prodClient, sampleEvent, "1 ")

						checkNoMsgFromConn(conn, "1 ")
					})
				})
			})
		})

		Context("two consumers", func() {
			var (
				consClient2    *http.Client
				consCert2      tls.Certificate
				consCertPool2  *x509.CertPool
				consSocket2    *websocket.Dialer
				consHeader2    http.Header
				receivedNotif2 eaa.NotificationToConsumer
			)

			BeforeEach(func() {
				consCommonName2 := "namespace-1:testAppID-2"
				consHeader2 = http.Header{}
				consHeader2.Add("Host", consCommonName2)
				consCertTempl2 := GetCertTempl()
				consCertTempl2.Subject.CommonName = consCommonName2
				consCert2, consCertPool2 = generateSignedClientCert(
					&consCertTempl2)
			})

			BeforeEach(func() {
				consClient2 = createHTTPClient(consCert2, consCertPool2)
				consSocket2 = createWebSocDialer(consCert2, consCertPool2)
			})

			Specify("Namespace Notification: 1 Event from 1 Producer"+
				" to 2 Consumers", func() {
				sampleService := eaa.Service{
					Description: "The Example Producer",
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

				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "Event #1",
						Version: "1.0.0",
					},
				}

				sampleEvent := eaa.NotificationFromProducer{
					Name:    "Event #1",
					Version: "1.0.0",
					Payload: json.RawMessage(`{"msg":"PING"}`),
				}

				expectedOutput := strings.NewReader(
					"{\"producer\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"name\":\"Event #1\",\"version\":\"1.0.0\"," +
						"\"payload\":{\"msg\":\"PING\"}}")

				registerProducer(prodClient, sampleService, "")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1", "1 ")
				subscribeConsumer(consClient2, sampleNotifications,
					"namespace-1", "2 ")

				conn := connectConsumer(consSocket, &consHeader, "1 ")
				defer conn.Close()

				conn2 := connectConsumer(consSocket2, &consHeader2, "2 ")
				defer conn2.Close()

				produceEvent(prodClient, sampleEvent, "")

				By("Expected notification struct decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedNotif)
				Expect(err).ShouldNot(HaveOccurred())

				getMsgFromConn(conn, &receivedNotif, "1 ")

				By("Comparing web socket 1 response data")
				Expect(receivedNotif).To(Equal(expectedNotif))

				getMsgFromConn(conn2, &receivedNotif2, "2 ")

				By("Comparing web socket 2 response data")
				Expect(receivedNotif2).To(Equal(expectedNotif))
			})

			Specify("Namespace Notification after canceling subscription"+
				" (2 Consumers)", func() {
				sampleService := eaa.Service{
					Description: "The Example Producer #1",
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

				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "Event #1",
						Version: "1.0.0",
					},
				}

				sampleEvent := eaa.NotificationFromProducer{
					Name:    "Event #1",
					Version: "1.0.0",
					Payload: json.RawMessage(`{"msg":"PING"}`),
				}

				expectedOutput := strings.NewReader(
					"{\"producer\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"name\":\"Event #1\",\"version\":\"1.0.0\"," +
						"\"payload\":{\"msg\":\"PING\"}}")

				registerProducer(prodClient, sampleService, "")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1", "1 ")
				subscribeConsumer(consClient2, sampleNotifications,
					"namespace-1", "2 ")

				conn := connectConsumer(consSocket, &consHeader, "1 ")
				defer conn.Close()
				conn2 := connectConsumer(consSocket2, &consHeader2, "2 ")
				defer conn2.Close()

				produceEvent(prodClient, sampleEvent, "")

				By("Expected notification struct decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedNotif)
				Expect(err).ShouldNot(HaveOccurred())

				getMsgFromConn(conn, &receivedNotif, "1 ")
				getMsgFromConn(conn2, &receivedNotif2, "2 ")

				By("Comparing web socket 1 response data")
				Expect(receivedNotif).To(Equal(expectedNotif))

				By("Comparing web socket 2 response data (1/2)")
				Expect(receivedNotif2).To(Equal(expectedNotif))

				unsubscribeConsumer(consClient, sampleNotifications,
					"namespace-1", "1 ")

				produceEvent(prodClient, sampleEvent, "")

				checkNoMsgFromConn(conn, "1 ")
				getMsgFromConn(conn2, &receivedNotif2, "2 ")

				By("Comparing web socket 2 response data (2/2)")
				Expect(receivedNotif2).To(Equal(expectedNotif))
			})

			Context("two producers", func() {
				var (
					prodClient2    *http.Client
					prodCert2      tls.Certificate
					prodCertPool2  *x509.CertPool
					receivedNotif2 eaa.NotificationToConsumer
					expectedNotif2 eaa.NotificationToConsumer
				)

				BeforeEach(func() {
					prodCertTempl2 := GetCertTempl()
					prodCertTempl2.Subject.CommonName = "namespace-1:producer-2"
					prodCert2, prodCertPool2 = generateSignedClientCert(
						&prodCertTempl2)
				})

				BeforeEach(func() {
					prodClient2 = createHTTPClient(prodCert2, prodCertPool2)
				})

				Specify("Namespace Notification: 1 Event from 2 Producers"+
					" to 2 Consumers", func() {
					sampleService := eaa.Service{
						Description: "The Example producer #1",
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

					sampleService2 := eaa.Service{
						Description: "The Example producer #2",
						EndpointURI: "https://1.2.3.5",
						Notifications: []eaa.NotificationDescriptor{
							{
								Name:    "Event #1",
								Version: "1.0.0",
								Description: "Description for " +
									"Event #1 by Producer #2",
							},
						},
					}

					sampleNotifications := []eaa.NotificationDescriptor{
						{
							Name:    "Event #1",
							Version: "1.0.0",
						},
					}

					sampleEvent := eaa.NotificationFromProducer{
						Name:    "Event #1",
						Version: "1.0.0",
						Payload: json.RawMessage(`{"msg":"PING"}`),
					}

					expectedOutput := strings.NewReader(
						"{\"producer\":" +
							"{\"id\":\"producer-1\"," +
							"\"namespace\":\"namespace-1\"}," +
							"\"name\":\"Event #1\",\"version\":\"1.0.0\"," +
							"\"payload\":{\"msg\":\"PING\"}}")

					expectedOutput2 := strings.NewReader(
						"{\"producer\":" +
							"{\"id\":\"producer-2\"," +
							"\"namespace\":\"namespace-1\"}," +
							"\"name\":\"Event #1\",\"version\":\"1.0.0\"," +
							"\"payload\":{\"msg\":\"PING\"}}")

					registerProducer(prodClient, sampleService, "1 ")
					registerProducer(prodClient2, sampleService2, "2 ")

					subscribeConsumer(consClient, sampleNotifications,
						"namespace-1", "1 ")
					subscribeConsumer(consClient2, sampleNotifications,
						"namespace-1", "2 ")

					conn := connectConsumer(consSocket, &consHeader, "1 ")
					defer conn.Close()

					conn2 := connectConsumer(consSocket2, &consHeader2, "2 ")
					defer conn2.Close()

					produceEvent(prodClient, sampleEvent, "1 ")
					produceEvent(prodClient2, sampleEvent, "2 ")

					By("Expected notification struct 1 decoding")
					err := json.NewDecoder(expectedOutput).
						Decode(&expectedNotif)
					Expect(err).ShouldNot(HaveOccurred())

					getMsgFromConn(conn, &receivedNotif, "1 ")

					By("Comparing web socket 1 response data")
					Expect(receivedNotif).To(Equal(expectedNotif))

					By("Expected notification struct 2 decoding")
					err = json.NewDecoder(expectedOutput2).
						Decode(&expectedNotif2)
					Expect(err).ShouldNot(HaveOccurred())

					getMsgFromConn(conn, &receivedNotif2, "2 ")

					By("Comparing web socket 2 response data")
					Expect(receivedNotif2).To(Equal(expectedNotif2))
				})
			})
		})
	})
})

var _ = Describe("Eaa Data Validation", func() {
	Describe("Register producer", func() {

		BeforeEach(func() {
			err := runAppliance()
			Expect(err).ShouldNot(HaveOccurred())
		})

		AfterEach(func() {
			stopAppliance()
		})

		Context("Providing a new producer data", func() {
			var (
				prodClient   *http.Client
				prodCert     tls.Certificate
				prodCertPool *x509.CertPool
				accessClient *http.Client
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
				prodCertTempl.Subject.CommonName = Name1Prod1
				prodCert, prodCertPool = generateSignedClientCert(
					&prodCertTempl)
			})

			BeforeEach(func() {
				prodClient = createHTTPClient(prodCert, prodCertPool)
			})
			Specify("With no ID Provided", func() {

				var (
					receivedServList eaa.ServiceList
					expectedServList eaa.ServiceList
				)

				producer := eaa.Service{
					URN: &eaa.URN{
						Namespace: "namespace-1",
					},
					Description: "The Sanity Producer",
					EndpointURI: "https://1.2.3.4",
					Notifications: []eaa.NotificationDescriptor{
						{
							Name:    "Event #1",
							Version: "1.0.0",
							Description: "Description for Event #1 by " +
								"Producer #1",
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

				registerProducer(prodClient, producer, "")
				getServiceList(accessClient, &receivedServList)

				By("Expected service struct decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedServList)
				Expect(err).ShouldNot(HaveOccurred())

				By("Comparing GET response data")
				Expect(receivedServList).To(Equal(expectedServList))

			})

			Specify("With no Namespace provided", func() {

				var (
					receivedServList eaa.ServiceList
					expectedServList eaa.ServiceList
				)

				producer := eaa.Service{
					URN: &eaa.URN{
						ID: "namespace-1",
					},
					Description: "The Sanity Producer",
					EndpointURI: "https://1.2.3.4",
					Notifications: []eaa.NotificationDescriptor{
						{
							Name:    "Event #1",
							Version: "1.0.0",
							Description: "Description for Event #1 by " +
								"Producer #1",
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

				registerProducer(prodClient, producer, "")
				getServiceList(accessClient, &receivedServList)

				By("Expected service list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedServList)
				Expect(err).ShouldNot(HaveOccurred())

				By("Comparing GET response data")
				Expect(receivedServList).To(Equal(expectedServList))

			})
			Specify("With no Description provided", func() {

				var (
					receivedServList eaa.ServiceList
					expectedServList eaa.ServiceList
				)
				producer := eaa.Service{
					URN: &eaa.URN{
						ID:        "producer-1",
						Namespace: "namespace-1",
					},
					EndpointURI: "https://1.2.3.4",
					Notifications: []eaa.NotificationDescriptor{
						{
							Name:    "Event #1",
							Version: "1.0.0",
							Description: "Description for Event #1 by " +
								"Producer #1",
						},
					},
				}

				expectedOutput := strings.NewReader(
					"{\"services\":[{\"urn\":{\"id\"" +
						":\"producer-1\",\"namespace\":\"namespace-1\"}," +
						"\"description\":\"\"," +
						"\"endpoint_uri\":\"https://1.2.3.4\"," +
						"\"notifications\":[{\"name\":\"Event #1\"," +
						"\"version\":\"1.0.0\",\"description\"" +
						":\"Description for Event #1 by Producer #1\"}]}]}")

				registerProducer(prodClient, producer, "")
				getServiceList(accessClient, &receivedServList)

				By("Expected service list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedServList)
				Expect(err).ShouldNot(HaveOccurred())

				By("Comparing GET response data")
				Expect(receivedServList).To(Equal(expectedServList))

			})
			Specify("With no Notifications provided", func() {

				var (
					receivedServList eaa.ServiceList
					expectedServList eaa.ServiceList
				)

				producer := eaa.Service{
					URN: &eaa.URN{
						ID:        "producer-1",
						Namespace: "namespace-1",
					},
					Description: "example description",
					EndpointURI: "https://1.2.3.4",
				}
				expectedOutput := strings.NewReader(
					"{\"services\":[{\"urn\":{\"id\"" +
						":\"producer-1\",\"namespace\":\"namespace-1\"}," +
						"\"description\":\"example description\"," +
						"\"endpoint_uri\":\"https://1.2.3.4\"," +
						"\"notifications\":null}]}")

				registerProducer(prodClient, producer, "")
				getServiceList(accessClient, &receivedServList)

				By("Expected service list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedServList)
				Expect(err).ShouldNot(HaveOccurred())

				By("Comparing GET response data")
				Expect(receivedServList).To(Equal(expectedServList))

			})

			Specify("With no Endpoint URI provided", func() {

				var (
					receivedServList eaa.ServiceList
					expectedServList eaa.ServiceList
				)
				producer := eaa.Service{
					URN: &eaa.URN{
						ID:        "producer-1",
						Namespace: "namespace-1",
					},
					Description: "example description",
					Notifications: []eaa.NotificationDescriptor{
						{
							Name:    "Event #1",
							Version: "1.0.0",
							Description: "Description for Event #1 by" +
								" Producer #1",
						},
					},
				}

				expectedOutput := strings.NewReader(
					"{\"services\":[{\"urn\":{\"id\"" +
						":\"producer-1\",\"namespace\":\"namespace-1\"}," +
						"\"description\":\"example description\"," +
						"\"endpoint_uri\":\"\"," +
						"\"notifications\":[{\"name\":\"Event #1\"," +
						"\"version\":\"1.0.0\",\"description\"" +
						":\"Description for Event #1 by Producer #1\"}]}]}")

				registerProducer(prodClient, producer, "")
				getServiceList(accessClient, &receivedServList)

				By("Expected service list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedServList)
				Expect(err).ShouldNot(HaveOccurred())

				By("Comparing GET response data")
				Expect(receivedServList).To(Equal(expectedServList))
			})

			Specify("With no Notification's Name provided", func() {

				var (
					receivedServList eaa.ServiceList
					expectedServList eaa.ServiceList
				)

				producer := eaa.Service{
					URN: &eaa.URN{
						ID:        "producer-1",
						Namespace: "namespace-1",
					},
					Description: "example description",
					EndpointURI: "https://1.2.3.4",
					Notifications: []eaa.NotificationDescriptor{
						{
							Version: "1.0.0",
							Description: "Description for Event #1 by " +
								"Producer #1",
						},
					},
				}
				expectedOutput := strings.NewReader(
					"{\"services\":[{\"urn\":{\"id\"" +
						":\"producer-1\",\"namespace\":\"namespace-1\"}," +
						"\"description\":\"example description\"," +
						"\"endpoint_uri\":\"https://1.2.3.4\"," +
						"\"notifications\":null}]}")

				registerProducer(prodClient, producer, "")
				getServiceList(accessClient, &receivedServList)

				By("Expected service list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedServList)
				Expect(err).ShouldNot(HaveOccurred())

				By("Comparing GET response data")
				Expect(receivedServList).To(Equal(expectedServList))
			})

			Specify("With no Notification's Version ID provided", func() {

				var (
					receivedServList eaa.ServiceList
					expectedServList eaa.ServiceList
				)
				producer := eaa.Service{
					URN: &eaa.URN{
						ID:        "producer-1",
						Namespace: "namespace-1",
					},
					Description: "example description",
					EndpointURI: "https://1.2.3.4",
					Notifications: []eaa.NotificationDescriptor{
						{
							Name: "Event #1",
							Description: "Description for Event #1 by " +
								"Producer #1",
						},
					},
				}
				expectedOutput := strings.NewReader(
					"{\"services\":[{\"urn\":{\"id\"" +
						":\"producer-1\",\"namespace\":\"namespace-1\"}," +
						"\"description\":\"example description\"," +
						"\"endpoint_uri\":\"https://1.2.3.4\"," +
						"\"notifications\":null}]}")

				registerProducer(prodClient, producer, "")
				getServiceList(accessClient, &receivedServList)

				By("Expected service list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedServList)
				Expect(err).ShouldNot(HaveOccurred())

				By("Comparing GET response data")
				Expect(receivedServList).To(Equal(expectedServList))
			})

			Specify("With no Notification's Description provided", func() {

				var (
					receivedServList eaa.ServiceList
					expectedServList eaa.ServiceList
				)
				producer := eaa.Service{
					URN: &eaa.URN{
						ID:        "producer-1",
						Namespace: "namespace-1",
					},
					Description: "example description",
					EndpointURI: "https://1.2.3.4",
					Notifications: []eaa.NotificationDescriptor{
						{
							Name:    "Event #1",
							Version: "1.0.0",
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
						":\"\"}]}]}")

				registerProducer(prodClient, producer, "")
				getServiceList(accessClient, &receivedServList)

				By("Expected service list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedServList)
				Expect(err).ShouldNot(HaveOccurred())

				By("Comparing GET response data")
				Expect(receivedServList).To(Equal(expectedServList))
			})

			Specify("With two Notifications provided - one invalid", func() {

				var (
					receivedServList eaa.ServiceList
					expectedServList eaa.ServiceList
				)
				producer := eaa.Service{
					URN: &eaa.URN{
						ID:        "producer-1",
						Namespace: "namespace-1",
					},
					Description: "example description",
					EndpointURI: "https://1.2.3.4",
					Notifications: []eaa.NotificationDescriptor{
						{
							Name:    "Event #1",
							Version: "1.0.0",
							Description: "Description for Event #1 by " +
								"Producer #1",
						},
						{
							Name: "Event #2",
							Description: "Description for Event #2 by " +
								"Producer #1",
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
						":\"Description for Event #1 by Producer #1\"}]}]}")

				registerProducer(prodClient, producer, "")
				getServiceList(accessClient, &receivedServList)

				By("Expected service list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedServList)
				Expect(err).ShouldNot(HaveOccurred())

				By("Comparing GET response data")
				Expect(receivedServList).To(Equal(expectedServList))
			})
		})
	})
})
