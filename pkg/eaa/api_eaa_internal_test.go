// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"

	"github.com/ThreeDotsLabs/watermill/message"
	g "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/undefinedlabs/go-mpatch"
)

type brokerMock struct {
	addPublisherError  []error
	publishError       []error
	addSubscriberError []error
	removeAllError     []error
}

func nextResult(e *[]error) error {
	if len(*e) > 0 {
		r := (*e)[0]

		*e = (*e)[1:]

		return r
	}

	return nil

}

func (b *brokerMock) addPublisher(_ publisherType, _ string, _ *http.Request) error {
	return nextResult(&b.addPublisherError)
}

func (b *brokerMock) publish(_ string, _ *message.Message) error {
	return nextResult(&b.publishError)
}

func (b *brokerMock) addSubscriber(_ subscriberType, _ string, _ *http.Request) error {
	return nextResult(&b.addSubscriberError)
}

func (b *brokerMock) removeAll() error {
	return nextResult(&b.removeAllError)
}

var _ = g.Describe("ApiEaa internal errors", func() {
	var (
		request    *http.Request
		response   *httptest.ResponseRecorder
		eaaContext *Context
		broker     brokerMock
	)

	const serviceName = "some:name"

	unitTestError := errors.New("unit test error")

	g.BeforeEach(func() {
		eaaContext = &Context{}
		eaaContext.serviceInfo.m = make(map[string]Service)
		eaaContext.serviceInfo.m[serviceName] = Service{}
		eaaContext.consumerConnections = consumerConns{m: make(map[string]ConsumerConnection)}
		eaaContext.subscriptionInfo = NotificationSubscriptions{m: make(map[UniqueNotif]*ConsumerSubscription)}

		broker = brokerMock{}
		eaaContext.MsgBrokerCtx = &broker

		request = httptest.NewRequest("GET", "/foo", nil)
		response = httptest.NewRecorder()

		ctx := context.WithValue(
			request.Context(),
			contextKey("appliance-ctx"),
			eaaContext)
		request = request.WithContext(ctx)

		tls := tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: serviceName}}},
		}

		request.TLS = &tls

		request.Body = ioutil.NopCloser(strings.NewReader("{}"))
	})

	g.Describe("DeregisterApplication", func() {
		g.When("URN is bad", func() {
			g.It("should fail with an error", func() {

				request.TLS.PeerCertificates[0].Subject = pkix.Name{CommonName: "bad name"}
				DeregisterApplication(response, request)

				Expect(response.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		g.When("json marshaling fails", func() {
			g.It("should fail with an error", func() {

				p, e := PatchMethod(json.Marshal, func(v interface{}) ([]byte, error) {
					return nil, unitTestError
				})

				Expect(e).NotTo(HaveOccurred())

				defer p.Unpatch()

				DeregisterApplication(response, request)

				Expect(response.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		g.When("broker fails to publish", func() {
			g.It("should fail with an error", func() {

				broker.publishError = []error{unitTestError}
				DeregisterApplication(response, request)

				Expect(response.Code).To(Equal(http.StatusInternalServerError))
			})
		})
	})

	g.Describe("GetNotifications", func() {
		g.When("context is broken", func() {
			g.It("should fail", func() {

				eaaContext.serviceInfo.m = nil

				GetNotifications(response, request)

				Expect(response.Code).To(Equal(http.StatusInternalServerError))
			})
		})
		g.When("when broker fails to add subscriber", func() {
			g.It("should fail", func() {
				p, e := PatchMethod(createWsConn, func(w http.ResponseWriter, r *http.Request) (int, error) {
					return 0, nil
				})

				defer p.Unpatch()

				Expect(e).NotTo(HaveOccurred())

				broker.addSubscriberError = []error{unitTestError}

				GetNotifications(response, request)

				Expect(response.Code).To(Equal(http.StatusInternalServerError))
			})
		})
	})

	g.Describe("GetServices", func() {
		g.When("context is broken", func() {
			g.It("should fail", func() {
				eaaContext.serviceInfo.m = nil

				GetServices(response, request)

				Expect(response.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		g.When("json encoder fails", func() {
			g.It("should fail", func() {
				p, e := PatchInstanceMethodByName(reflect.TypeOf(&json.Encoder{}), "Encode",
					func(_ *json.Encoder, _ interface{}) error {
						return unitTestError
					})

				defer p.Unpatch()

				Expect(e).NotTo(HaveOccurred())

				GetServices(response, request)

				Expect(response.Code).To(Equal(http.StatusInternalServerError))
			})
		})
	})

	g.Describe("GetSubscriptions", func() {
		g.When("context is broken", func() {
			g.It("should fail", func() {
				eaaContext.subscriptionInfo.m = nil

				GetSubscriptions(response, request)

				Expect(response.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		g.When("json encoder fails", func() {
			g.It("should fail", func() {
				p, e := PatchInstanceMethodByName(reflect.TypeOf(&json.Encoder{}), "Encode",
					func(_ *json.Encoder, _ interface{}) error {
						return unitTestError
					})

				defer p.Unpatch()

				Expect(e).NotTo(HaveOccurred())

				GetSubscriptions(response, request)

				Expect(response.Code).To(Equal(http.StatusInternalServerError))
			})
		})
	})

	g.Describe("PushNotificationToSubscribers", func() {
		g.When("broker fails to add a publisher", func() {
			g.It("should fail", func() {

				broker.addPublisherError = []error{unitTestError}
				request.Body = ioutil.NopCloser(strings.NewReader("{}"))

				PushNotificationToSubscribers(response, request)

				Expect(response.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		g.When("json encoder fails", func() {
			g.It("should fail", func() {
				p, e := PatchMethodByReflectValue(reflect.ValueOf(json.Marshal),
					func(_ interface{}) ([]byte, error) {
						return nil, unitTestError
					})

				defer p.Unpatch()

				Expect(e).NotTo(HaveOccurred())

				request.Body = ioutil.NopCloser(strings.NewReader("{}"))
				PushNotificationToSubscribers(response, request)

				Expect(response.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		g.When("broker fails to publish a message", func() {
			g.It("should fail", func() {

				broker.publishError = []error{unitTestError}
				request.Body = ioutil.NopCloser(strings.NewReader("{}"))

				PushNotificationToSubscribers(response, request)

				Expect(response.Code).To(Equal(http.StatusInternalServerError))
			})
		})
	})

	g.Describe("RegisterApplication", func() {
		g.When("json marshal fails", func() {
			g.It("should fail", func() {
				p, e := PatchMethodByReflectValue(reflect.ValueOf(json.Marshal),
					func(_ interface{}) ([]byte, error) {
						return nil, unitTestError
					})

				defer p.Unpatch()
				Expect(e).NotTo(HaveOccurred())

				RegisterApplication(response, request)

				Expect(response.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		g.When("broker fails to publish a message", func() {
			g.It("should fail", func() {

				broker.publishError = []error{unitTestError}

				RegisterApplication(response, request)

				Expect(response.Code).To(Equal(http.StatusInternalServerError))
			})
		})
	})

	g.Describe("SubscribeNamespaceNotifications", func() {
		g.When("broker fails to subscribe to a topic", func() {
			g.It("should fail", func() {

				broker.addSubscriberError = []error{unitTestError}

				request.Body = ioutil.NopCloser(strings.NewReader("[]"))
				SubscribeNamespaceNotifications(response, request)

				Expect(response.Code).To(Equal(http.StatusInternalServerError))
			})
		})
	})

	g.Describe("SubscribeServiceNotifications", func() {
		g.When("broker fails to subscribe to a topic", func() {
			g.It("should fail", func() {

				broker.addSubscriberError = []error{unitTestError}

				request.Body = ioutil.NopCloser(strings.NewReader("[]"))
				SubscribeServiceNotifications(response, request)

				Expect(response.Code).To(Equal(http.StatusInternalServerError))
			})
		})
	})

	g.Describe("UnsubscribeAllNotifications", func() {
		g.When("broker fails to subscribe to a topic", func() {
			g.It("should fail", func() {

				broker.addSubscriberError = []error{unitTestError}

				UnsubscribeAllNotifications(response, request)

				Expect(response.Code).To(Equal(http.StatusInternalServerError))
			})
		})
	})

	g.Describe("UnsubscribeNamespaceNotifications", func() {
		g.When("broker fails to subscribe to a topic", func() {
			g.It("should fail", func() {

				broker.addSubscriberError = []error{unitTestError}
				request.Body = ioutil.NopCloser(strings.NewReader("[]"))

				UnsubscribeNamespaceNotifications(response, request)

				Expect(response.Code).To(Equal(http.StatusInternalServerError))
			})
		})
	})

	g.Describe("UnsubscribeServiceNotifications", func() {
		g.When("broker fails to subscribe to a topic", func() {
			g.It("should fail", func() {

				broker.addSubscriberError = []error{unitTestError}
				request.Body = ioutil.NopCloser(strings.NewReader("[]"))

				UnsubscribeServiceNotifications(response, request)

				Expect(response.Code).To(Equal(http.StatusInternalServerError))
			})
		})
	})

	g.Describe("processSubscriptionRequest", func() {
		urn := &URN{Namespace: "namespace", ID: "id"}

		g.When("URN is nil", func() {
			g.It("should fail", func() {

				e := processSubscriptionRequest(subscriptionActionSubscribe, "scope", "", nil, nil, nil, eaaContext)

				Expect(e).To(HaveOccurred())
			})
		})

		g.When("second broker addsubscriber fail", func() {
			g.It("should fail", func() {

				broker.addSubscriberError = []error{nil, unitTestError}
				e := processSubscriptionRequest(subscriptionActionSubscribe, "scope", "", urn, nil, nil, eaaContext)

				Expect(e).To(HaveOccurred())
			})
		})

		g.When("broker addpublisher fail", func() {
			g.It("should fail", func() {

				broker.addPublisherError = []error{unitTestError}
				e := processSubscriptionRequest(subscriptionActionSubscribe, "scope", "", urn, nil, nil, eaaContext)

				Expect(e).To(HaveOccurred())
			})
		})

		g.When("json marshal fails", func() {
			g.It("should fail", func() {

				p, e := PatchMethodByReflectValue(reflect.ValueOf(json.Marshal),
					func(_ interface{}) ([]byte, error) {
						return nil, unitTestError
					})

				defer p.Unpatch()
				Expect(e).NotTo(HaveOccurred())

				e = processSubscriptionRequest(subscriptionActionSubscribe, "scope", "", urn, nil, nil, eaaContext)

				Expect(e).To(HaveOccurred())
			})
		})

		g.When("broker publish fails", func() {
			g.It("should fail", func() {

				broker.publishError = []error{unitTestError}
				e := processSubscriptionRequest(subscriptionActionSubscribe, "scope", "", urn, nil, nil, eaaContext)

				Expect(e).To(HaveOccurred())
			})
		})
	})
})
