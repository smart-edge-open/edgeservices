// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

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
	"github.com/open-ness/edgenode/pkg/eaa"
)

const (
	Name1Prod1 = "namespace-1:producer-1"
	Name1Prod2 = "namespace-1:producer-2"
	Name1Cons1 = "namespace-1:testAppID-1"
	Name1Cons2 = "namespace-1:testAppID-2"
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

// subLess is a comparison function for Subscription structs
func subLess(a, b eaa.Subscription) bool {
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

// sortSubscriptionSlices sorts a lists of Subscription slices
// and the Notifications slice within all Subscription structs
//to help accommodate equality assertions
func sortSubscriptionSlices(slices ...[]eaa.Subscription) {
	for _, subSlice := range slices {
		sort.Slice(subSlice,
			func(i, j int) bool {
				return subLess(subSlice[i], subSlice[j])
			},
		)
		for _, sub := range subSlice {
			sort.Slice(sub.Notifications,
				func(i, j int) bool {
					return notifLess(sub.Notifications[i],
						sub.Notifications[j])
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

// deregisterProducer sends a deregistration DELETE request to the appliance
func deregisterProducer(c *http.Client, subject string) {
	By("Sending service deregistration DELETE " + subject + "request")
	req, _ := http.NewRequest("DELETE", "https://"+cfg.TLSEndpoint+"/services",
		nil)
	respPost, err := c.Do(req)
	Expect(err).ShouldNot(HaveOccurred())

	By("Comparing DELETE " + subject + "response code")
	defer respPost.Body.Close()
	Expect(respPost.Status).To(Equal("204 No Content"))
}

// failToDeregisterProducer sends an unsuccessful deregistration DELETE request
// to the appliance
func failToDeregisterProducer(c *http.Client, subject string) {
	By("Sending service deregistration DELETE " + subject + "request")
	req, _ := http.NewRequest("DELETE", "https://"+cfg.TLSEndpoint+"/services",
		nil)
	respPost, err := c.Do(req)
	Expect(err).ShouldNot(HaveOccurred())

	By("Comparing DELETE " + subject + "response code")
	defer respPost.Body.Close()
	Expect(respPost.Status).To(Equal("404 Not Found"))
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

// getSubscriptionList sends a GET request to the appliance and retrieves
// a list of current consumer subscriptions
func getSubscriptionList(c *http.Client, list *eaa.SubscriptionList) {
	By("Sending subscription list GET request")
	respGet, err := c.Get(
		"https://" + cfg.TLSEndpoint + "/subscriptions")
	Expect(err).ShouldNot(HaveOccurred())

	By("Comparing GET response code")
	defer respGet.Body.Close()
	Expect(respGet.Status).To(Equal("200 OK"))

	By("Received subscription list decoding")
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
	startStopCh := make(chan bool)
	BeforeEach(func() {
		err := runEaa(startStopCh)
		Expect(err).ShouldNot(HaveOccurred())
	})

	AfterEach(func() {
		stopEaa(startStopCh)
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

	Describe("Producer deregistration", func() {
		var (
			prodClient        *http.Client
			prodCert          tls.Certificate
			prodCertPool      *x509.CertPool
			accessClient      *http.Client
			receivedServList  eaa.ServiceList
			receivedServList2 eaa.ServiceList
			expectedServList  eaa.ServiceList
			expectedServList2 eaa.ServiceList
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

		AfterEach(func() {
			receivedServList = eaa.ServiceList{}
			receivedServList2 = eaa.ServiceList{}
			expectedServList = eaa.ServiceList{}
			expectedServList2 = eaa.ServiceList{}
		})

		Context("one producer", func() {
			Specify("Deregister: 1 Producer with 1 Notification", func() {
				sampleService := eaa.Service{
					Description: "Sample description for Producer #1",
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
						"\"description\":\"Sample description for Producer #1\"," +
						"\"endpoint_uri\":\"https://1.2.3.4\"," +
						"\"notifications\":[{\"name\":\"Event #1\"," +
						"\"version\":\"1.0.0\",\"description\"" +
						":\"Description for Event #1 by Producer #1\"}]}]}")

				expectedOutput2 := strings.NewReader(
					"{\"services\":	null}")

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

				deregisterProducer(prodClient, "")

				getServiceList(accessClient, &receivedServList2)

				By("Expected service list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedServList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortServiceSlices(expectedServList2.Services,
					receivedServList2.Services)

				By("Comparing GET 2 response data")
				Expect(receivedServList2).To(Equal(expectedServList2))
			})

			Specify("Deregister: 1 Producer with 2 Notification", func() {
				sampleService := eaa.Service{
					Description: "Sample description for Producer #1",
					EndpointURI: "https://1.2.3.4",
					Notifications: []eaa.NotificationDescriptor{
						{
							Name:    "Event #1",
							Version: "1.0.0",
							Description: "Description for " +
								"Event #1 by Producer #1",
						},
						{
							Name:    "Event #2",
							Version: "1.0.0",
							Description: "Description for " +
								"Event #2 by Producer #1",
						},
					},
				}

				expectedOutput := strings.NewReader(
					"{\"services\":[{" +
						"\"urn\":{\"id\"" +
						":\"producer-1\",\"namespace\":\"namespace-1\"}," +
						"\"description\":\"Sample description for Producer #1\"," +
						"\"endpoint_uri\":\"https://1.2.3.4\"," +
						"\"notifications\":[" +
						"{\"name\":\"Event #1\"," +
						"\"version\":\"1.0.0\",\"description\"" +
						":\"Description for Event #1 by Producer #1\"}," +
						"{\"name\":\"Event #2\"," +
						"\"version\":\"1.0.0\",\"description\"" +
						":\"Description for Event #2 by Producer #1\"}" +
						"]}]}")

				expectedOutput2 := strings.NewReader(
					"{\"services\":	null}")

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

				deregisterProducer(prodClient, "")

				getServiceList(accessClient, &receivedServList2)

				By("Expected service list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedServList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortServiceSlices(expectedServList2.Services,
					receivedServList2.Services)

				By("Comparing GET 2 response data")
				Expect(receivedServList2).To(Equal(expectedServList2))
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
				prodCertTempl2.Subject.CommonName = Name1Prod2
				prodCert2, prodCertPool2 = generateSignedClientCert(
					&prodCertTempl2)
			})

			BeforeEach(func() {
				prodClient2 = createHTTPClient(prodCert2, prodCertPool2)
			})

			Specify("Deregister: An Unregistered Producer", func() {
				sampleService := eaa.Service{
					Description: "Sample description for Producer #1",
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
						"\"description\":\"Sample description for Producer #1\"," +
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

				failToDeregisterProducer(prodClient2, "2 ")

				getServiceList(accessClient, &receivedServList2)

				sortServiceSlices(receivedServList2.Services)

				By("Comparing GET 2 response data")
				Expect(receivedServList2).To(Equal(expectedServList))
			})

			Specify("Deregister: 2 Producers with 2 Unique Notifications",
				func() {
					sampleService := eaa.Service{
						Description: "Sample description for Producer #1",
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
						Description: "Sample description for Producer #2",
						EndpointURI: "https://1.2.3.5",
						Notifications: []eaa.NotificationDescriptor{
							{
								Name:    "Event #2",
								Version: "1.0.0",
								Description: "Description for " +
									"Event #2 by Producer #2",
							},
						},
					}

					expectedOutput := strings.NewReader(
						"{\"services\":[" +
							"{\"urn\":{\"id\"" +
							":\"producer-1\",\"namespace\":\"namespace-1\"}," +
							"\"description\":\"Sample description for Producer #1\"," +
							"\"endpoint_uri\":\"https://1.2.3.4\"," +
							"\"notifications\":[{\"name\":\"Event #1\"," +
							"\"version\":\"1.0.0\",\"description\"" +
							":\"Description for Event #1 by Producer #1\"}]}," +
							"{\"urn\":{\"id\"" +
							":\"producer-2\",\"namespace\":\"namespace-1\"}," +
							"\"description\":\"Sample description for Producer #2\"," +
							"\"endpoint_uri\":\"https://1.2.3.5\"," +
							"\"notifications\":[{\"name\":\"Event #2\"," +
							"\"version\":\"1.0.0\",\"description\"" +
							":\"Description for Event #2 by Producer #2\"}]}" +
							"]}")

					expectedOutput2 := strings.NewReader(
						"{\"services\":	null}")

					registerProducer(prodClient, sampleService, "1 ")
					registerProducer(prodClient2, sampleService2, "2 ")

					getServiceList(accessClient, &receivedServList)

					By("Expected service list 1 decoding")
					err := json.NewDecoder(expectedOutput).
						Decode(&expectedServList)
					Expect(err).ShouldNot(HaveOccurred())

					sortServiceSlices(expectedServList.Services,
						receivedServList.Services)

					By("Comparing GET response data")
					Expect(receivedServList).To(Equal(expectedServList))

					deregisterProducer(prodClient, "1 ")
					deregisterProducer(prodClient2, "2 ")

					getServiceList(accessClient, &receivedServList2)

					By("Expected service list 2 decoding")
					err = json.NewDecoder(expectedOutput2).
						Decode(&expectedServList2)
					Expect(err).ShouldNot(HaveOccurred())

					sortServiceSlices(receivedServList2.Services,
						expectedServList2.Services)

					By("Comparing GET 2 response data")
					Expect(receivedServList2).To(Equal(expectedServList2))
				})

			Specify("Deregister: 2 Producers with the Same Notification",
				func() {
					sampleService := eaa.Service{
						Description: "Sample description for Producer #1",
						EndpointURI: "https://1.2.3.4",
						Notifications: []eaa.NotificationDescriptor{
							{
								Name:        "Event #1",
								Version:     "1.0.0",
								Description: "Sample description",
							},
						},
					}

					sampleService2 := eaa.Service{
						Description: "Sample description for Producer #2",
						EndpointURI: "https://1.2.3.5",
						Notifications: []eaa.NotificationDescriptor{
							{
								Name:        "Event #1",
								Version:     "1.0.0",
								Description: "Sample description",
							},
						},
					}

					expectedOutput := strings.NewReader(
						"{\"services\":[" +
							"{\"urn\":{\"id\"" +
							":\"producer-1\",\"namespace\":\"namespace-1\"}," +
							"\"description\":\"Sample description for Producer #1\"," +
							"\"endpoint_uri\":\"https://1.2.3.4\"," +
							"\"notifications\":[{\"name\":\"Event #1\"," +
							"\"version\":\"1.0.0\",\"description\"" +
							":\"Sample description\"}]}," +
							"{\"urn\":{\"id\"" +
							":\"producer-2\",\"namespace\":\"namespace-1\"}," +
							"\"description\":\"Sample description for Producer #2\"," +
							"\"endpoint_uri\":\"https://1.2.3.5\"," +
							"\"notifications\":[{\"name\":\"Event #1\"," +
							"\"version\":\"1.0.0\",\"description\"" +
							":\"Sample description\"}]}" +
							"]}")

					expectedOutput2 := strings.NewReader(
						"{\"services\":	null}")

					registerProducer(prodClient, sampleService, "1 ")
					registerProducer(prodClient2, sampleService2, "2 ")

					getServiceList(accessClient, &receivedServList)

					By("Expected service list 1 decoding")
					err := json.NewDecoder(expectedOutput).
						Decode(&expectedServList)
					Expect(err).ShouldNot(HaveOccurred())

					sortServiceSlices(expectedServList.Services,
						receivedServList.Services)

					By("Comparing GET response data")
					Expect(receivedServList).To(Equal(expectedServList))

					deregisterProducer(prodClient, "1 ")
					deregisterProducer(prodClient2, "2 ")

					getServiceList(accessClient, &receivedServList2)

					By("Expected service list 2 decoding")
					err = json.NewDecoder(expectedOutput2).
						Decode(&expectedServList2)
					Expect(err).ShouldNot(HaveOccurred())

					sortServiceSlices(receivedServList2.Services,
						expectedServList2.Services)

					By("Comparing GET 2 response data")
					Expect(receivedServList2).To(Equal(expectedServList2))
				})

			Specify("Deregister: Only 1 out of 2 Producers with 2"+
				" Unique Notifications",
				func() {
					sampleService := eaa.Service{
						Description: "Sample description for Producer #1",
						EndpointURI: "https://1.2.3.4",
						Notifications: []eaa.NotificationDescriptor{
							{
								Name:    "Event #1",
								Version: "1.0.0",
								Description: "Description for Event #1" +
									" by Producer #1",
							},
						},
					}

					sampleService2 := eaa.Service{
						Description: "Sample description for Producer #2",
						EndpointURI: "https://1.2.3.5",
						Notifications: []eaa.NotificationDescriptor{
							{
								Name:    "Event #2",
								Version: "1.0.0",
								Description: "Description for Event #2" +
									" by Producer #2",
							},
						},
					}

					expectedOutput := strings.NewReader(
						"{\"services\":[" +
							"{\"urn\":{\"id\"" +
							":\"producer-1\",\"namespace\":\"namespace-1\"}," +
							"\"description\":\"Sample description for Producer #1\"," +
							"\"endpoint_uri\":\"https://1.2.3.4\"," +
							"\"notifications\":[{\"name\":\"Event #1\"," +
							"\"version\":\"1.0.0\",\"description\"" +
							":\"Description for Event #1 by Producer #1\"}]}," +
							"{\"urn\":{\"id\"" +
							":\"producer-2\",\"namespace\":\"namespace-1\"}," +
							"\"description\":\"Sample description for Producer #2\"," +
							"\"endpoint_uri\":\"https://1.2.3.5\"," +
							"\"notifications\":[{\"name\":\"Event #2\"," +
							"\"version\":\"1.0.0\",\"description\"" +
							":\"Description for Event #2 by Producer #2\"}]}" +
							"]}")

					expectedOutput2 := strings.NewReader(
						"{\"services\":[" +
							"{\"urn\":{\"id\"" +
							":\"producer-2\",\"namespace\":\"namespace-1\"}," +
							"\"description\":\"Sample description for Producer #2\"," +
							"\"endpoint_uri\":\"https://1.2.3.5\"," +
							"\"notifications\":[{\"name\":\"Event #2\"," +
							"\"version\":\"1.0.0\",\"description\"" +
							":\"Description for Event #2 by Producer #2\"}]}" +
							"]}")

					registerProducer(prodClient, sampleService, "1 ")
					registerProducer(prodClient2, sampleService2, "2 ")

					getServiceList(accessClient, &receivedServList)

					By("Expected service list 1 decoding")
					err := json.NewDecoder(expectedOutput).
						Decode(&expectedServList)
					Expect(err).ShouldNot(HaveOccurred())

					sortServiceSlices(expectedServList.Services,
						receivedServList.Services)

					By("Comparing GET response data")
					Expect(receivedServList).To(Equal(expectedServList))

					deregisterProducer(prodClient, "")

					getServiceList(accessClient, &receivedServList2)

					By("Expected service list 2 decoding")
					err = json.NewDecoder(expectedOutput2).
						Decode(&expectedServList2)
					Expect(err).ShouldNot(HaveOccurred())

					sortServiceSlices(receivedServList2.Services,
						expectedServList2.Services)

					By("Comparing GET 2 response data")
					Expect(receivedServList2).To(Equal(expectedServList2))
				})

			Specify("Deregister: Only 1 out of 2 Producers with"+
				" the Same Notification",
				func() {
					sampleService := eaa.Service{
						Description: "Sample description for Producer #1",
						EndpointURI: "https://1.2.3.4",
						Notifications: []eaa.NotificationDescriptor{
							{
								Name:        "Event #1",
								Version:     "1.0.0",
								Description: "Sample description",
							},
						},
					}

					sampleService2 := eaa.Service{
						Description: "Sample description for Producer #2",
						EndpointURI: "https://1.2.3.5",
						Notifications: []eaa.NotificationDescriptor{
							{
								Name:        "Event #1",
								Version:     "1.0.0",
								Description: "Sample description",
							},
						},
					}

					expectedOutput := strings.NewReader(
						"{\"services\":[" +
							"{\"urn\":{\"id\"" +
							":\"producer-1\",\"namespace\":\"namespace-1\"}," +
							"\"description\":\"Sample description for Producer #1\"," +
							"\"endpoint_uri\":\"https://1.2.3.4\"," +
							"\"notifications\":[{\"name\":\"Event #1\"," +
							"\"version\":\"1.0.0\",\"description\"" +
							":\"Sample description\"}]}," +
							"{\"urn\":{\"id\"" +
							":\"producer-2\",\"namespace\":\"namespace-1\"}," +
							"\"description\":\"Sample description for Producer #2\"," +
							"\"endpoint_uri\":\"https://1.2.3.5\"," +
							"\"notifications\":[{\"name\":\"Event #1\"," +
							"\"version\":\"1.0.0\",\"description\"" +
							":\"Sample description\"}]}" +
							"]}")

					expectedOutput2 := strings.NewReader(
						"{\"services\":[" +
							"{\"urn\":{\"id\"" +
							":\"producer-2\",\"namespace\":\"namespace-1\"}," +
							"\"description\":\"Sample description for Producer #2\"," +
							"\"endpoint_uri\":\"https://1.2.3.5\"," +
							"\"notifications\":[{\"name\":\"Event #1\"," +
							"\"version\":\"1.0.0\",\"description\"" +
							":\"Sample description\"}]}" +
							"]}")

					registerProducer(prodClient, sampleService, "1 ")
					registerProducer(prodClient2, sampleService2, "2 ")

					getServiceList(accessClient, &receivedServList)

					By("Expected service list 1 decoding")
					err := json.NewDecoder(expectedOutput).
						Decode(&expectedServList)
					Expect(err).ShouldNot(HaveOccurred())

					sortServiceSlices(expectedServList.Services,
						receivedServList.Services)

					By("Comparing GET response data")
					Expect(receivedServList).To(Equal(expectedServList))

					deregisterProducer(prodClient, "")

					getServiceList(accessClient, &receivedServList2)

					By("Expected service list 2 decoding")
					err = json.NewDecoder(expectedOutput2).
						Decode(&expectedServList2)
					Expect(err).ShouldNot(HaveOccurred())

					sortServiceSlices(receivedServList2.Services,
						expectedServList2.Services)

					By("Comparing GET 2 response data")
					Expect(receivedServList2).To(Equal(expectedServList2))
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
			consCommonName := Name1Cons1
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

			Specify("Namespace Notification not registered by Producer"+
				"(1 Consumer)", func() {
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
						Name:    "Event #2",
						Version: "1.2.3",
					},
				}

				sampleEvent := eaa.NotificationFromProducer{
					Name:    "Event #2",
					Version: "1.2.3",
					Payload: json.RawMessage(`{"msg":"PING"}`),
				}

				expectedOutput := strings.NewReader(
					"{\"producer\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"name\":\"Event #2\",\"version\":\"1.2.3\"," +
						"\"payload\":{\"msg\":\"PING\"}}")

				registerProducer(prodClient, sampleService, "")
				// Subscribe notification that is not registered by Producer
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

			Specify("Producer Notification (not registered) (1 consumer)",
				func() {
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
							Name:    "Event #2",
							Version: "1.2.3",
						},
					}

					sampleEvent := eaa.NotificationFromProducer{
						Name:    "Event #2",
						Version: "1.2.3",
						Payload: json.RawMessage(`{"msg":"PING"}`),
					}

					expectedOutput := strings.NewReader(
						"{\"producer\":" +
							"{\"id\":\"producer-1\"," +
							"\"namespace\":\"namespace-1\"}," +
							"\"name\":\"Event #2\",\"version\":\"1.2.3\"," +
							"\"payload\":{\"msg\":\"PING\"}}")

					registerProducer(prodClient, sampleService, "")
					// Subscribe notification that is not registered by Producer
					subscribeConsumer(consClient, sampleNotifications,
						"namespace-1/producer-1", "")

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
						prodCertTempl2.Subject.CommonName = Name1Prod2
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
				consCommonName2 := Name1Cons2
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
					prodCertTempl2.Subject.CommonName = Name1Prod2
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

	Describe("Namespace notification subscription", func() {
		var (
			consClient      *http.Client
			consCert        tls.Certificate
			consCertPool    *x509.CertPool
			receivedSubList eaa.SubscriptionList
			expectedSubList eaa.SubscriptionList
		)

		BeforeEach(func() {
			consCertTempl := GetCertTempl()
			consCertTempl.Subject.CommonName = Name1Cons1
			consCert, consCertPool = generateSignedClientCert(
				&consCertTempl)
		})

		BeforeEach(func() {
			consClient = createHTTPClient(consCert, consCertPool)
		})

		Context("one consumer", func() {
			Specify("Namespace Notification: 1 Event", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "0.1.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[{\"urn\":{\"id\" : null," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":" +
						"[{\"name\":\"event_1\"," +
						"\"version\":\"0.1.0\",\"description\"" +
						":null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data")
				Expect(receivedSubList).To(Equal(expectedSubList))
			})

			Specify("Namespace Notification: 2 Events in 1 Request", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "0.1.0",
					},
					{
						Name:    "event_2",
						Version: "0.2.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":{" +
						"\"id\" : null," +
						"\"namespace\":\"namespace-2\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"0.1.0\"," +
						"\"description\": null}," +
						"{\"name\":\"event_2\"," +
						"\"version\":\"0.2.0\"," +
						"\"description\": null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-2", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data")
				Expect(receivedSubList).To(Equal(expectedSubList))
			})

			Specify("Namespace Subscribe: 2 Same Name Different Version"+
				" Events in 1 Request", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event",
						Version: "1.0.1",
					},
					{
						Name:    "event",
						Version: "1.0.2",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":{" +
						"\"id\" : null," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event\"," +
						"\"version\":\"1.0.1\"," +
						"\"description\": null}," +
						"{\"name\":\"event\"," +
						"\"version\":\"1.0.2\"," +
						"\"description\": null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data")
				Expect(receivedSubList).To(Equal(expectedSubList))
			})

			Specify("Namespace Subscribe: 2 Duplicate Events"+
				" in 1 Request", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "The Event",
						Version: "1.0.0",
					},
					{
						Name:    "The Event",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":{" +
						"\"id\" : null," +
						"\"namespace\":\"the-namespace\"}," +
						"\"notifications\":[" +
						"{\"name\":\"The Event\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\": null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"the-namespace", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data")
				Expect(receivedSubList).To(Equal(expectedSubList))
			})

			Specify("Namespace Notification: 2 Events in 2 Request", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.1",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event_2",
						Version: "1.0.2",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":{" +
						"\"id\" : null," +
						"\"namespace\":\"namespace-2\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.1\"," +
						"\"description\": null}," +
						"{\"name\":\"event_2\"," +
						"\"version\":\"1.0.2\"," +
						"\"description\": null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-2", "1 ")
				subscribeConsumer(consClient, sampleNotifications2,
					"namespace-2", "2 ")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data")
				Expect(receivedSubList).To(Equal(expectedSubList))
			})

			Specify("Namespace Subscribe: 2 Same Name Different Version"+
				" Events in 2 Request", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event",
						Version: "1.0.1",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event",
						Version: "1.0.2",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":{" +
						"\"id\" : null," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event\"," +
						"\"version\":\"1.0.1\"," +
						"\"description\": null}," +
						"{\"name\":\"event\"," +
						"\"version\":\"1.0.2\"," +
						"\"description\": null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1", "1 ")
				subscribeConsumer(consClient, sampleNotifications2,
					"namespace-1", "2 ")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data")
				Expect(receivedSubList).To(Equal(expectedSubList))
			})

			Specify("Namespace Subscribe: 2 Duplicate Events"+
				" in 2 Request", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "The Event",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":{" +
						"\"id\" : null," +
						"\"namespace\":\"the-namespace\"}," +
						"\"notifications\":[" +
						"{\"name\":\"The Event\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\": null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"the-namespace", "1 ")
				subscribeConsumer(consClient, sampleNotifications,
					"the-namespace", "2 ")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data")
				Expect(receivedSubList).To(Equal(expectedSubList))
			})

			Specify("Namespace Notification: 2 Events in 2 Namespaces",
				func() {
					sampleNotifications := []eaa.NotificationDescriptor{
						{
							Name:    "event_1",
							Version: "1.0.1",
						},
					}

					sampleNotifications2 := []eaa.NotificationDescriptor{
						{
							Name:    "event_2",
							Version: "1.0.2",
						},
					}

					expectedOutput := strings.NewReader(
						"{\"subscriptions\":[" +
							"{\"urn\":{" +
							"\"id\" : null," +
							"\"namespace\":\"namespace-1\"}," +
							"\"notifications\":[" +
							"{\"name\":\"event_1\"," +
							"\"version\":\"1.0.1\"," +
							"\"description\": null}]}," +
							"{\"urn\":{" +
							"\"id\" : null," +
							"\"namespace\":\"namespace-2\"}," +
							"\"notifications\":[" +
							"{\"name\":\"event_2\"," +
							"\"version\":\"1.0.2\"," +
							"\"description\": null}]}]}")

					subscribeConsumer(consClient, sampleNotifications,
						"namespace-1", "1 ")
					subscribeConsumer(consClient, sampleNotifications2,
						"namespace-2", "2 ")

					getSubscriptionList(consClient, &receivedSubList)

					By("Expected subscription list decoding")
					err := json.NewDecoder(expectedOutput).
						Decode(&expectedSubList)
					Expect(err).ShouldNot(HaveOccurred())

					sortSubscriptionSlices(receivedSubList.Subscriptions,
						expectedSubList.Subscriptions)

					By("Comparing response data")
					Expect(receivedSubList).To(Equal(expectedSubList))
				})
		})

		Context("two consumers", func() {
			var (
				consClient2      *http.Client
				consCert2        tls.Certificate
				consCertPool2    *x509.CertPool
				receivedSubList2 eaa.SubscriptionList
				expectedSubList2 eaa.SubscriptionList
			)

			BeforeEach(func() {
				consCertTempl2 := GetCertTempl()
				consCertTempl2.Subject.CommonName = Name1Cons2
				consCert2, consCertPool2 = generateSignedClientCert(
					&consCertTempl2)
			})

			BeforeEach(func() {
				consClient2 = createHTTPClient(consCert2, consCertPool2)
			})

			Specify("Namespace Notification: 2 Events in 1 Namespace"+
				" for 2 Consumers", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event_2",
						Version: "1.1.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":{" +
						"\"id\" : null," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\": null}]}]}")

				expectedOutput2 := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":{" +
						"\"id\" : null," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_2\"," +
						"\"version\":\"1.1.0\"," +
						"\"description\": null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1", "1 ")
				subscribeConsumer(consClient2, sampleNotifications2,
					"namespace-1", "2 ")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data 1")
				Expect(receivedSubList).To(Equal(expectedSubList))

				getSubscriptionList(consClient2, &receivedSubList2)

				By("Expected subscription list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedSubList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList2.Subscriptions)

				By("Comparing response data 2")
				Expect(receivedSubList2).To(Equal(expectedSubList2))
			})

			Specify("Namespace Notification: 2 Events in 2 Namespaces"+
				" for 2 Consumers", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}
				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event_2",
						Version: "2.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":{" +
						"\"id\" : null," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\": null}]}]}")

				expectedOutput2 := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":{" +
						"\"id\" : null," +
						"\"namespace\":\"namespace-2\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_2\"," +
						"\"version\":\"2.0.0\"," +
						"\"description\": null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1", "1 ")
				subscribeConsumer(consClient2, sampleNotifications2,
					"namespace-2", "2 ")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data 1")
				Expect(receivedSubList).To(Equal(expectedSubList))

				getSubscriptionList(consClient2, &receivedSubList2)

				By("Expected subscription list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedSubList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList2.Subscriptions)

				By("Comparing response data 2")
				Expect(receivedSubList2).To(Equal(expectedSubList2))
			})

			Specify("Namespace Notification: Same Event in Same Namespaces"+
				" for 2 Consumers", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":{" +
						"\"id\" : null," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\": null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1", "1 ")
				subscribeConsumer(consClient2, sampleNotifications,
					"namespace-1", "2 ")

				By("Expected subscription list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				getSubscriptionList(consClient, &receivedSubList)

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data 1")
				Expect(receivedSubList).To(Equal(expectedSubList))

				getSubscriptionList(consClient2, &receivedSubList2)

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data 2")
				Expect(receivedSubList2).To(Equal(expectedSubList))
			})
		})
	})

	Describe("Producer notification subscription", func() {
		var (
			consClient      *http.Client
			consCert        tls.Certificate
			consCertPool    *x509.CertPool
			receivedSubList eaa.SubscriptionList
			expectedSubList eaa.SubscriptionList
		)

		BeforeEach(func() {
			consCertTempl := GetCertTempl()
			consCertTempl.Subject.CommonName = Name1Cons1
			consCert, consCertPool = generateSignedClientCert(
				&consCertTempl)
		})

		BeforeEach(func() {
			consClient = createHTTPClient(consCert, consCertPool)
		})

		Context("one consumer", func() {
			Specify("1 Event Subscribe", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data")
				Expect(receivedSubList).To(Equal(expectedSubList))
			})

			Specify("2 Events in 1 Subscribe Request", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.1",
					},
					{
						Name:    "event_2",
						Version: "1.0.2",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.1\"," +
						"\"description\":null}," +
						"{\"name\":\"event_2\"," +
						"\"version\":\"1.0.2\"," +
						"\"description\":null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data")
				Expect(receivedSubList).To(Equal(expectedSubList))
			})

			Specify("2 Same Name, Different Version Events"+
				" in 1 Subscribe Request", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event",
						Version: "1.0.1",
					},
					{
						Name:    "event",
						Version: "1.0.2",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event\"," +
						"\"version\":\"1.0.1\"," +
						"\"description\":null}," +
						"{\"name\":\"event\"," +
						"\"version\":\"1.0.2\"," +
						"\"description\":null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data")
				Expect(receivedSubList).To(Equal(expectedSubList))
			})

			Specify("2 Duplicate Events in 1 Subscribe Request", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "The Event",
						Version: "1.0.0",
					},
					{
						Name:    "The Event",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"the-producer\"," +
						"\"namespace\":\"the-namespace\"}," +
						"\"notifications\":[" +
						"{\"name\":\"The Event\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"the-namespace/the-producer", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data")
				Expect(receivedSubList).To(Equal(expectedSubList))
			})

			Specify("2 Events in 2 Subscribe Request", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.1",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event_2",
						Version: "1.0.2",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-2\"," +
						"\"namespace\":\"namespace-2\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.1\"," +
						"\"description\":null}," +
						"{\"name\":\"event_2\"," +
						"\"version\":\"1.0.2\"," +
						"\"description\":null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-2/producer-2", "")
				subscribeConsumer(consClient, sampleNotifications2,
					"namespace-2/producer-2", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data")
				Expect(receivedSubList).To(Equal(expectedSubList))
			})

			Specify("2 Same Name Different Version Events"+
				" in 2 Subscribe Request", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event",
						Version: "1.0.1",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event",
						Version: "1.0.2",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event\"," +
						"\"version\":\"1.0.1\"," +
						"\"description\":null}," +
						"{\"name\":\"event\"," +
						"\"version\":\"1.0.2\"," +
						"\"description\":null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "")
				subscribeConsumer(consClient, sampleNotifications2,
					"namespace-1/producer-1", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data")
				Expect(receivedSubList).To(Equal(expectedSubList))
			})

			Specify("2 Duplicate Events in 2 Subscribe Request", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "The Event",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"the-producer\"," +
						"\"namespace\":\"the-namespace\"}," +
						"\"notifications\":[" +
						"{\"name\":\"The Event\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"the-namespace/the-producer", "")
				subscribeConsumer(consClient, sampleNotifications,
					"the-namespace/the-producer", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data")
				Expect(receivedSubList).To(Equal(expectedSubList))
			})

			Specify("2 Events by 2 Producers in 1 Namespace", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.1",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event_2",
						Version: "1.0.2",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.1\"," +
						"\"description\":null}]}," +
						"{\"urn\":" +
						"{\"id\":\"producer-2\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_2\"," +
						"\"version\":\"1.0.2\"," +
						"\"description\":null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "")
				subscribeConsumer(consClient, sampleNotifications2,
					"namespace-1/producer-2", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data")
				Expect(receivedSubList).To(Equal(expectedSubList))
			})

			Specify("2 Events by 2 Producers in 2 Namespace", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.1",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event_2",
						Version: "1.0.2",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"the-producer\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.1\"," +
						"\"description\":null}]}," +
						"{\"urn\":" +
						"{\"id\":\"the-producer\"," +
						"\"namespace\":\"namespace-2\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_2\"," +
						"\"version\":\"1.0.2\"," +
						"\"description\":null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/the-producer", "")
				subscribeConsumer(consClient, sampleNotifications2,
					"namespace-2/the-producer", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data")
				Expect(receivedSubList).To(Equal(expectedSubList))
			})

			Specify("2 Events by Same Named Producers in 2 Namespaces", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.1",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event_2",
						Version: "1.0.2",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.1\"," +
						"\"description\":null}]}," +
						"{\"urn\":" +
						"{\"id\":\"producer-2\"," +
						"\"namespace\":\"namespace-2\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_2\"," +
						"\"version\":\"1.0.2\"," +
						"\"description\":null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "")
				subscribeConsumer(consClient, sampleNotifications2,
					"namespace-2/producer-2", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data")
				Expect(receivedSubList).To(Equal(expectedSubList))
			})
		})

		Context("two consumers", func() {
			var (
				consClient2      *http.Client
				consCert2        tls.Certificate
				consCertPool2    *x509.CertPool
				receivedSubList2 eaa.SubscriptionList
				expectedSubList2 eaa.SubscriptionList
			)

			BeforeEach(func() {
				consCertTempl2 := GetCertTempl()
				consCertTempl2.Subject.CommonName = Name1Cons2
				consCert2, consCertPool2 = generateSignedClientCert(
					&consCertTempl2)
			})

			BeforeEach(func() {
				consClient2 = createHTTPClient(consCert2, consCertPool2)
			})

			Specify("2 Events by 1 Producer for 2 Consumers", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event_2",
						Version: "1.1.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\": null}]}]}")

				expectedOutput2 := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_2\"," +
						"\"version\":\"1.1.0\"," +
						"\"description\": null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "1 ")
				subscribeConsumer(consClient2, sampleNotifications2,
					"namespace-1/producer-1", "2 ")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data 1")
				Expect(receivedSubList).To(Equal(expectedSubList))

				getSubscriptionList(consClient2, &receivedSubList2)

				By("Expected subscription list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedSubList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList2.Subscriptions)

				By("Comparing response data 2")
				Expect(receivedSubList2).To(Equal(expectedSubList2))
			})

			Specify("2 Events by 2 Producers in 1 Namespace"+
				" for 2 Consumers", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event_2",
						Version: "2.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\": null}]}]}")

				expectedOutput2 := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-2\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_2\"," +
						"\"version\":\"2.0.0\"," +
						"\"description\": null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "1 ")
				subscribeConsumer(consClient2, sampleNotifications2,
					"namespace-1/producer-2", "2 ")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data 1")
				Expect(receivedSubList).To(Equal(expectedSubList))

				getSubscriptionList(consClient2, &receivedSubList2)

				By("Expected subscription list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedSubList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList2.Subscriptions)

				By("Comparing response data 2")
				Expect(receivedSubList2).To(Equal(expectedSubList2))
			})

			Specify("2 Events by 2 Producers in 2 Namespaces"+
				" for 2 Consumers", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event_2",
						Version: "2.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\": null}]}]}")

				expectedOutput2 := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-2\"," +
						"\"namespace\":\"namespace-2\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_2\"," +
						"\"version\":\"2.0.0\"," +
						"\"description\": null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "1 ")
				subscribeConsumer(consClient2, sampleNotifications2,
					"namespace-2/producer-2", "2 ")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data 1")
				Expect(receivedSubList).To(Equal(expectedSubList))

				getSubscriptionList(consClient2, &receivedSubList2)

				By("Expected subscription list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedSubList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList2.Subscriptions)

				By("Comparing response data 2")
				Expect(receivedSubList2).To(Equal(expectedSubList2))
			})

			Specify("Same Event by Same Producer for 2 Consumers", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\": null}]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "1 ")
				subscribeConsumer(consClient2, sampleNotifications,
					"namespace-1/producer-1", "2 ")

				By("Expected subscription list decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				getSubscriptionList(consClient, &receivedSubList)

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response data 1")
				Expect(receivedSubList).To(Equal(expectedSubList))

				getSubscriptionList(consClient2, &receivedSubList2)

				sortSubscriptionSlices(receivedSubList2.Subscriptions)

				By("Comparing response data 2")
				Expect(receivedSubList2).To(Equal(expectedSubList))
			})
		})
	})

	Describe("Complex Notification Subscription Suite", func() {
		var (
			consClient       *http.Client
			consCert         tls.Certificate
			consCertPool     *x509.CertPool
			consClient2      *http.Client
			consCert2        tls.Certificate
			consCertPool2    *x509.CertPool
			consClient3      *http.Client
			consCert3        tls.Certificate
			consCertPool3    *x509.CertPool
			receivedSubList  eaa.SubscriptionList
			receivedSubList2 eaa.SubscriptionList
			receivedSubList3 eaa.SubscriptionList
			expectedSubList  eaa.SubscriptionList
			expectedSubList2 eaa.SubscriptionList
			expectedSubList3 eaa.SubscriptionList
		)

		BeforeEach(func() {
			consCertTempl := GetCertTempl()
			consCertTempl.Subject.CommonName = Name1Cons1
			consCert, consCertPool = generateSignedClientCert(
				&consCertTempl)
			consCertTempl2 := GetCertTempl()
			consCertTempl2.Subject.CommonName = Name1Cons2
			consCert2, consCertPool2 = generateSignedClientCert(
				&consCertTempl2)
			consCertTempl3 := GetCertTempl()
			consCertTempl3.Subject.CommonName = "namespace-1:testAppID-3"
			consCert3, consCertPool3 = generateSignedClientCert(
				&consCertTempl3)
		})

		BeforeEach(func() {
			consClient = createHTTPClient(consCert, consCertPool)
			consClient2 = createHTTPClient(consCert2, consCertPool2)
			consClient3 = createHTTPClient(consCert3, consCertPool3)
		})

		Specify("3 Consumer Complex Subscribe", func() {
			sampleNotifications := []eaa.NotificationDescriptor{
				{
					Name:    "event_1",
					Version: "1.1.0",
				},
				{
					Name:    "event_2",
					Version: "1.2.0",
				},
				{
					Name:    "event_3",
					Version: "1.3.0",
				},
			}

			sampleNotifications2 := []eaa.NotificationDescriptor{
				{
					Name:    "event_1",
					Version: "1.1.0",
				},
				{
					Name:    "event_2",
					Version: "1.2.0",
				},
			}

			sampleNotifications3 := []eaa.NotificationDescriptor{
				{
					Name:    "event_2",
					Version: "1.2.0",
				},
				{
					Name:    "event_3",
					Version: "1.3.0",
				},
			}

			sampleNotifications4 := []eaa.NotificationDescriptor{
				{
					Name:    "event_4",
					Version: "2.4.0",
				},
			}

			sampleNotifications5 := []eaa.NotificationDescriptor{
				{
					Name:    "event_1",
					Version: "1.1.0",
				},
				{
					Name:    "event_2",
					Version: "1.2.0",
				},
				{
					Name:    "event_3",
					Version: "1.3.0",
				},
				{
					Name:    "event_4",
					Version: "1.4.0",
				},
			}

			sampleNotifications6 := []eaa.NotificationDescriptor{
				{
					Name:    "event_4",
					Version: "2.4.0",
				},
				{
					Name:    "event_5",
					Version: "2.5.0",
				},
			}

			expectedOutput := strings.NewReader(
				"{\"subscriptions\":" +
					"[{\"urn\":{\"id\":null,\"namespace\":\"namespace-1\"}," +
					"\"notifications\":[{\"name\":\"event_1\"," +
					"\"version\":\"1.1.0\",\"description\":null}," +
					"{\"name\":\"event_2\",\"version\":\"1.2.0\"," +
					"\"description\":null},{\"name\":\"event_3\"," +
					"\"version\":\"1.3.0\",\"description\":null}]}]}")

			expectedOutput2 := strings.NewReader(
				"{\"subscriptions\":[" +
					"{\"urn\":{\"id\":\"producer-1\"," +
					"\"namespace\":\"namespace-1\"}," +
					"\"notifications\":[{\"name\":\"event_1\"," +
					"\"version\":\"1.1.0\",\"description\":null}," +
					"{\"name\":\"event_2\",\"version\":\"1.2.0\"," +
					"\"description\":null}]}," +
					"{\"urn\":{\"id\":\"producer-2\"," +
					"\"namespace\":\"namespace-1\"}," +
					"\"notifications\":[{\"name\":\"event_2\"," +
					"\"version\":\"1.2.0\",\"description\":null}," +
					"{\"name\":\"event_3\",\"version\":\"1.3.0\"," +
					"\"description\":null}]}," +
					"{\"urn\":{\"id\":null," +
					"\"namespace\":\"namespace-2\"}," +
					"\"notifications\":[{\"name\":\"event_4\"," +
					"\"version\":\"2.4.0\",\"description\":null}]}]}")

			expectedOutput3 := strings.NewReader(
				"{\"subscriptions\":[" +
					"{\"urn\":{\"id\":null," +
					"\"namespace\":\"namespace-1\"}," +
					"\"notifications\":[{\"name\":\"event_1\"," +
					"\"version\":\"1.1.0\",\"description\":null}," +
					"{\"name\":\"event_2\",\"version\":\"1.2.0\"," +
					"\"description\":null},{\"name\":\"event_3\"," +
					"\"version\":\"1.3.0\",\"description\":null}," +
					"{\"name\":\"event_4\",\"version\":\"1.4.0\"," +
					"\"description\":null}]}," +
					"{\"urn\":{\"id\":\"producer-1\"," +
					"\"namespace\":\"namespace-1\"}," +
					"\"notifications\":[{\"name\":\"event_1\"," +
					"\"version\":\"1.1.0\",\"description\":null}," +
					"{\"name\":\"event_2\",\"version\":\"1.2.0\"," +
					"\"description\":null},{\"name\":\"event_3\"," +
					"\"version\":\"1.3.0\",\"description\":null}]}," +
					"{\"urn\":{\"id\":\"producer-2\"," +
					"\"namespace\":\"namespace-1\"}," +
					"\"notifications\":[{\"name\":\"event_1\"," +
					"\"version\":\"1.1.0\",\"description\":null}," +
					"{\"name\":\"event_2\",\"version\":\"1.2.0\"," +
					"\"description\":null},{\"name\":\"event_3\"," +
					"\"version\":\"1.3.0\",\"description\":null}]}," +
					"{\"urn\":{\"id\":null," +
					"\"namespace\":\"namespace-2\"}," +
					"\"notifications\":[{\"name\":\"event_4\"," +
					"\"version\":\"2.4.0\",\"description\":null}," +
					"{\"name\":\"event_5\",\"version\":\"2.5.0\"," +
					"\"description\":null}]}," +
					"{\"urn\":{\"id\":\"producer-3\"," +
					"\"namespace\":\"namespace-2\"}," +
					"\"notifications\":[{\"name\":\"event_4\"," +
					"\"version\":\"2.4.0\",\"description\":null}," +
					"{\"name\":\"event_5\",\"version\":\"2.5.0\"," +
					"\"description\":null}]}]}")

			subscribeConsumer(consClient, sampleNotifications,
				"namespace-1", "1 ")

			subscribeConsumer(consClient2, sampleNotifications2,
				"namespace-1/producer-1", "2 (1/3) ")

			subscribeConsumer(consClient2, sampleNotifications3,
				"namespace-1/producer-2", "2 (2/3) ")

			subscribeConsumer(consClient2, sampleNotifications4,
				"namespace-2", "2 (3/3) ")

			subscribeConsumer(consClient3, sampleNotifications5,
				"namespace-1", "3 (1/5) ")

			subscribeConsumer(consClient3, sampleNotifications,
				"namespace-1/producer-1", "3 (2/5) ")

			subscribeConsumer(consClient3, sampleNotifications,
				"namespace-1/producer-2", "3 (3/5) ")

			subscribeConsumer(consClient3, sampleNotifications6,
				"namespace-2", "3 (4/5) ")

			subscribeConsumer(consClient3, sampleNotifications6,
				"namespace-2/producer-3", "3 (5/5)")

			getSubscriptionList(consClient, &receivedSubList)

			By("Expected subscription list 1 decoding")
			err := json.NewDecoder(expectedOutput).
				Decode(&expectedSubList)
			Expect(err).ShouldNot(HaveOccurred())

			sortSubscriptionSlices(receivedSubList.Subscriptions,
				expectedSubList.Subscriptions)

			By("Comparing response data 1")
			Expect(receivedSubList).To(Equal(expectedSubList))

			getSubscriptionList(consClient2, &receivedSubList2)

			By("Expected subscription list 2 decoding")
			err = json.NewDecoder(expectedOutput2).
				Decode(&expectedSubList2)
			Expect(err).ShouldNot(HaveOccurred())

			sortSubscriptionSlices(receivedSubList2.Subscriptions,
				expectedSubList2.Subscriptions)

			By("Comparing response data 2")
			Expect(receivedSubList2).To(Equal(expectedSubList2))

			getSubscriptionList(consClient3, &receivedSubList3)

			By("Expected subscription list 3 decoding")
			err = json.NewDecoder(expectedOutput3).
				Decode(&expectedSubList3)
			Expect(err).ShouldNot(HaveOccurred())

			sortSubscriptionSlices(receivedSubList3.Subscriptions,
				expectedSubList3.Subscriptions)

			By("Comparing response data 3")
			Expect(receivedSubList3).To(Equal(expectedSubList3))
		})
	})

	Describe("Service notification unsubscription", func() {
		var (
			consClient       *http.Client
			consCert         tls.Certificate
			consCertPool     *x509.CertPool
			receivedSubList  eaa.SubscriptionList
			receivedSubList2 eaa.SubscriptionList
			expectedSubList  eaa.SubscriptionList
			expectedSubList2 eaa.SubscriptionList
		)

		BeforeEach(func() {
			consCertTempl := GetCertTempl()
			consCertTempl.Subject.CommonName = Name1Cons1
			consCert, consCertPool = generateSignedClientCert(
				&consCertTempl)
		})

		BeforeEach(func() {
			consClient = createHTTPClient(consCert, consCertPool)
		})

		AfterEach(func() {
			receivedSubList = eaa.SubscriptionList{}
			receivedSubList2 = eaa.SubscriptionList{}
			expectedSubList = eaa.SubscriptionList{}
			expectedSubList2 = eaa.SubscriptionList{}
		})

		Context("one consumer", func() {
			Specify("Unsubscribe: 1 Event in 1 Request", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}]}")

				expectedOutput2 := strings.NewReader(
					"{\"subscriptions\":null}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response 1 data")
				Expect(receivedSubList).To(Equal(expectedSubList))

				unsubscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "")

				getSubscriptionList(consClient, &receivedSubList2)

				By("Expected subscription list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedSubList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList2.Subscriptions)

				By("Comparing response 2 data")
				Expect(receivedSubList2).To(Equal(expectedSubList2))
			})

			Specify("Unsubscribe: An Unsubscribed Event", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event_2",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response 1 data")
				Expect(receivedSubList).To(Equal(expectedSubList))

				unsubscribeConsumer(consClient, sampleNotifications2,
					"namespace-1/producer-1", "")

				getSubscriptionList(consClient, &receivedSubList2)

				sortSubscriptionSlices(receivedSubList2.Subscriptions)

				By("Comparing response 2 data")
				Expect(receivedSubList2).To(Equal(expectedSubList))
			})

			Specify("Unsubscribe: 2 Events in 1 Request", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
					{
						Name:    "event_2",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}," +
						"{\"name\":\"event_2\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}]}")

				expectedOutput2 := strings.NewReader(
					"{\"subscriptions\":null}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response 1 data")
				Expect(receivedSubList).To(Equal(expectedSubList))

				unsubscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "")

				getSubscriptionList(consClient, &receivedSubList2)

				By("Expected subscription list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedSubList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList2.Subscriptions)

				By("Comparing response 2 data")
				Expect(receivedSubList2).To(Equal(expectedSubList2))
			})

			Specify("Unsubscribe: 2 Events with Identical Names"+
				" in 1 Request", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
					{
						Name:    "event_1",
						Version: "2.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}," +
						"{\"name\":\"event_1\"," +
						"\"version\":\"2.0.0\"," +
						"\"description\":null}" +
						"]}]}")

				expectedOutput2 := strings.NewReader(
					"{\"subscriptions\":null}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response 1 data")
				Expect(receivedSubList).To(Equal(expectedSubList))

				unsubscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "")

				getSubscriptionList(consClient, &receivedSubList2)

				By("Expected subscription list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedSubList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList2.Subscriptions)

				By("Comparing response 2 data")
				Expect(receivedSubList2).To(Equal(expectedSubList2))
			})

			Specify("Unsubscribe: 2 Duplicate Events in 1 Request", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}]}")

				expectedOutput2 := strings.NewReader(
					"{\"subscriptions\":null}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response 1 data")
				Expect(receivedSubList).To(Equal(expectedSubList))

				unsubscribeConsumer(consClient, sampleNotifications2,
					"namespace-1/producer-1", "")

				getSubscriptionList(consClient, &receivedSubList2)

				By("Expected subscription list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedSubList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList2.Subscriptions)

				By("Comparing response 2 data")
				Expect(receivedSubList2).To(Equal(expectedSubList2))
			})

			Specify("Unsubscribe: 2 Events in 2 Requests", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
					{
						Name:    "event_2",
						Version: "1.0.0",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				sampleNotifications3 := []eaa.NotificationDescriptor{
					{
						Name:    "event_2",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}," +
						"{\"name\":\"event_2\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}]}")

				expectedOutput2 := strings.NewReader(
					"{\"subscriptions\":null}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response 1 data")
				Expect(receivedSubList).To(Equal(expectedSubList))

				unsubscribeConsumer(consClient, sampleNotifications2,
					"namespace-1/producer-1", "1 ")

				unsubscribeConsumer(consClient, sampleNotifications3,
					"namespace-1/producer-1", "2 ")

				getSubscriptionList(consClient, &receivedSubList2)

				By("Expected subscription list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedSubList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList2.Subscriptions)

				By("Comparing response 2 data")
				Expect(receivedSubList2).To(Equal(expectedSubList2))
			})

			Specify("Unsubscribe: 2 Events with Identical Names"+
				" in 2 Requests", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
					{
						Name:    "event_1",
						Version: "2.0.0",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				sampleNotifications3 := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "2.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}," +
						"{\"name\":\"event_1\"," +
						"\"version\":\"2.0.0\"," +
						"\"description\":null}" +
						"]}]}")

				expectedOutput2 := strings.NewReader(
					"{\"subscriptions\":null}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response 1 data")
				Expect(receivedSubList).To(Equal(expectedSubList))

				unsubscribeConsumer(consClient, sampleNotifications2,
					"namespace-1/producer-1", "1 ")

				unsubscribeConsumer(consClient, sampleNotifications3,
					"namespace-1/producer-1", "2 ")

				getSubscriptionList(consClient, &receivedSubList2)

				By("Expected subscription list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedSubList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList2.Subscriptions)

				By("Comparing response 2 data")
				Expect(receivedSubList2).To(Equal(expectedSubList2))
			})

			Specify("Unsubscribe: 2 Duplicate Events in 2 Requests", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}]}")

				expectedOutput2 := strings.NewReader(
					"{\"subscriptions\":null}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response 1 data")
				Expect(receivedSubList).To(Equal(expectedSubList))

				unsubscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "1 ")

				unsubscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "2 ")

				getSubscriptionList(consClient, &receivedSubList2)

				By("Expected subscription list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedSubList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList2.Subscriptions)

				By("Comparing response 2 data")
				Expect(receivedSubList2).To(Equal(expectedSubList2))
			})

			Specify("Unsubscribe: 2 Events by 2 Producers"+
				" in 1 Namespace", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event_2",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}," +
						"{\"urn\":" +
						"{\"id\":\"producer-2\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_2\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}" +
						"]}")

				expectedOutput2 := strings.NewReader(
					"{\"subscriptions\":null}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "1 ")

				subscribeConsumer(consClient, sampleNotifications2,
					"namespace-1/producer-2", "2 ")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response 1 data")
				Expect(receivedSubList).To(Equal(expectedSubList))

				unsubscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "1 ")

				unsubscribeConsumer(consClient, sampleNotifications2,
					"namespace-1/producer-2", "2 ")

				getSubscriptionList(consClient, &receivedSubList2)

				By("Expected subscription list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedSubList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList2.Subscriptions)

				By("Comparing response 2 data")
				Expect(receivedSubList2).To(Equal(expectedSubList2))
			})

			Specify("Unsubscribe: 2 Events by 2 Producers"+
				" in 2 Namespaces", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event_2",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}," +
						"{\"urn\":" +
						"{\"id\":\"producer-2\"," +
						"\"namespace\":\"namespace-2\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_2\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}" +
						"]}")

				expectedOutput2 := strings.NewReader(
					"{\"subscriptions\":null}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "1 ")

				subscribeConsumer(consClient, sampleNotifications2,
					"namespace-2/producer-2", "2 ")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response 1 data")
				Expect(receivedSubList).To(Equal(expectedSubList))

				unsubscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "1 ")

				unsubscribeConsumer(consClient, sampleNotifications2,
					"namespace-2/producer-2", "2 ")

				getSubscriptionList(consClient, &receivedSubList2)

				By("Expected subscription list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedSubList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList2.Subscriptions)

				By("Comparing response 2 data")
				Expect(receivedSubList2).To(Equal(expectedSubList2))
			})

			Specify("Unsubscribe: 2 Events by 1 Producer"+
				" in 2 Namespaces", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event_2",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}," +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-2\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_2\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}" +
						"]}")

				expectedOutput2 := strings.NewReader(
					"{\"subscriptions\":null}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "1 ")

				subscribeConsumer(consClient, sampleNotifications2,
					"namespace-2/producer-1", "2 ")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response 1 data")
				Expect(receivedSubList).To(Equal(expectedSubList))

				unsubscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "1 ")

				unsubscribeConsumer(consClient, sampleNotifications2,
					"namespace-2/producer-1", "2 ")

				getSubscriptionList(consClient, &receivedSubList2)

				By("Expected subscription list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedSubList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList2.Subscriptions)

				By("Comparing response 2 data")
				Expect(receivedSubList2).To(Equal(expectedSubList2))
			})

			Specify("Unsubscribe: 2 Events by 2 Producers"+
				" in 2 Request", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event_2",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}," +
						"{\"urn\":" +
						"{\"id\":\"producer-2\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_2\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}" +
						"]}")

				expectedOutput2 := strings.NewReader(
					"{\"subscriptions\":null}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "1 ")

				subscribeConsumer(consClient, sampleNotifications2,
					"namespace-1/producer-2", "2 ")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response 1 data")
				Expect(receivedSubList).To(Equal(expectedSubList))

				unsubscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "1 ")

				unsubscribeConsumer(consClient, sampleNotifications2,
					"namespace-1/producer-2", "2 ")

				getSubscriptionList(consClient, &receivedSubList2)

				By("Expected subscription list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedSubList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList2.Subscriptions)

				By("Comparing response 2 data")
				Expect(receivedSubList2).To(Equal(expectedSubList2))
			})

			Specify("Unsubscribe: 2 Events by 2 Producers with Identical"+
				" Names in 2 Namespaces", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				sampleNotifications2 := []eaa.NotificationDescriptor{
					{
						Name:    "event_2",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}," +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-2\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_2\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}" +
						"]}")

				expectedOutput2 := strings.NewReader(
					"{\"subscriptions\":null}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "1 ")

				subscribeConsumer(consClient, sampleNotifications2,
					"namespace-2/producer-1", "2 ")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response 1 data")
				Expect(receivedSubList).To(Equal(expectedSubList))

				unsubscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "1 ")

				unsubscribeConsumer(consClient, sampleNotifications2,
					"namespace-2/producer-1", "2 ")

				getSubscriptionList(consClient, &receivedSubList2)

				By("Expected subscription list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedSubList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList2.Subscriptions)

				By("Comparing response 2 data")
				Expect(receivedSubList2).To(Equal(expectedSubList2))
			})

			Specify("Unsubscribe: 1 Event by 2 Producers", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}," +
						"{\"urn\":" +
						"{\"id\":\"producer-2\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}" +
						"]}")

				expectedOutput2 := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-2\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}" +
						"]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "1 ")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-2", "2 ")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response 1 data")
				Expect(receivedSubList).To(Equal(expectedSubList))

				unsubscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "")

				getSubscriptionList(consClient, &receivedSubList2)

				By("Expected subscription list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedSubList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList2.Subscriptions)

				By("Comparing response 2 data")
				Expect(receivedSubList2).To(Equal(expectedSubList2))
			})

			Specify("Unsubscribe: 1 Event by 2 Producers"+
				" in 2 Namespaces", func() {
				sampleNotifications := []eaa.NotificationDescriptor{
					{
						Name:    "event_1",
						Version: "1.0.0",
					},
				}

				expectedOutput := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-1\"," +
						"\"namespace\":\"namespace-1\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}," +
						"{\"urn\":" +
						"{\"id\":\"producer-2\"," +
						"\"namespace\":\"namespace-2\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}" +
						"]}")

				expectedOutput2 := strings.NewReader(
					"{\"subscriptions\":[" +
						"{\"urn\":" +
						"{\"id\":\"producer-2\"," +
						"\"namespace\":\"namespace-2\"}," +
						"\"notifications\":[" +
						"{\"name\":\"event_1\"," +
						"\"version\":\"1.0.0\"," +
						"\"description\":null}" +
						"]}" +
						"]}")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "1 ")

				subscribeConsumer(consClient, sampleNotifications,
					"namespace-2/producer-2", "2 ")

				getSubscriptionList(consClient, &receivedSubList)

				By("Expected subscription list 1 decoding")
				err := json.NewDecoder(expectedOutput).
					Decode(&expectedSubList)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList.Subscriptions,
					expectedSubList.Subscriptions)

				By("Comparing response 1 data")
				Expect(receivedSubList).To(Equal(expectedSubList))

				unsubscribeConsumer(consClient, sampleNotifications,
					"namespace-1/producer-1", "")

				getSubscriptionList(consClient, &receivedSubList2)

				By("Expected subscription list 2 decoding")
				err = json.NewDecoder(expectedOutput2).
					Decode(&expectedSubList2)
				Expect(err).ShouldNot(HaveOccurred())

				sortSubscriptionSlices(receivedSubList2.Subscriptions,
					expectedSubList2.Subscriptions)

				By("Comparing response 2 data")
				Expect(receivedSubList2).To(Equal(expectedSubList2))
			})
		})
	})
})

var _ = Describe("Eaa Data Validation", func() {
	Describe("Register producer", func() {
		startStopCh := make(chan bool)
		BeforeEach(func() {
			err := runEaa(startStopCh)
			Expect(err).ShouldNot(HaveOccurred())
		})

		AfterEach(func() {
			stopEaa(startStopCh)
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
