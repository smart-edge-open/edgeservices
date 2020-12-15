// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa

import (
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/gorilla/websocket"

	g "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/undefinedlabs/go-mpatch"
)

var _ = g.Describe("api_procuder internal errors", func() {
	var (
		eaaContext *Context
	)

	const serviceName = "service"

	var p *Patch
	var e error

	g.BeforeEach(func() {
		eaaContext = &Context{}
		eaaContext.serviceInfo.m = make(map[string]Service)
		eaaContext.serviceInfo.m[serviceName] = Service{}

		eaaContext.consumerConnections = consumerConns{m: make(map[string]ConsumerConnection)}

		cc := ConsumerConnection{&websocket.Conn{}}
		eaaContext.consumerConnections.m["aa"] = cc
		eaaContext.consumerConnections.m["bb"] = cc
		eaaContext.consumerConnections.m["cc"] = cc
		eaaContext.consumerConnections.m["dd"] = cc

		eaaContext.subscriptionInfo = NotificationSubscriptions{m: make(map[UniqueNotif]*ConsumerSubscription)}

		p, e = PatchInstanceMethodByName(reflect.TypeOf(websocket.Conn{}), "WriteMessage",
			func(_ *websocket.Conn, _ int, _ []byte) error {
				g.Fail("WriteMessage call, this should not happen")

				return nil
			})

		Expect(e).NotTo(HaveOccurred())
	})

	g.AfterEach(func() {
		p.Unpatch()
	})

	g.Describe("addService", func() {
		g.When("eaa context is broken", func() {
			g.It("should fail", func() {
				eaaContext.serviceInfo.m = nil

				e := addService("", Service{}, eaaContext)

				Expect(e).To(HaveOccurred())
			})
		})

		g.Describe("removeService", func() {
			g.When("eaa context is broken", func() {
				g.It("should fail", func() {
					eaaContext.serviceInfo.m = nil

					e := removeService("", eaaContext)

					Expect(e).To(HaveOccurred())
				})
			})
		})

		g.Describe("sendNotificationToAllSubscribers", func() {

			n := &NotificationFromProducer{
				Name:    "name",
				Version: "1.0",
				Payload: []byte("{}"),
			}

			prod := "ns:prodID"

			g.BeforeEach(func() {
				urn, err := CommonNameStringToURN(prod)
				Expect(err).NotTo(HaveOccurred())

				key := UniqueNotif{urn.Namespace, "name", "1.0"}

				cs := &ConsumerSubscription{
					namespaceSubscriptions: SubscriberIds{"aa", "bb"},
					serviceSubscriptions:   make(map[string]SubscriberIds),
					notification:           NotificationDescriptor{"name", "1.0", "description"},
				}

				cs.serviceSubscriptions[urn.ID] = SubscriberIds{"bb", "cc"}

				eaaContext.subscriptionInfo.m[key] = cs

				eaaContext.serviceInfo.m[prod] = Service{}
			})

			g.When("everything is ok", func() {
				g.It("messages should be sent", func() {
					p.Unpatch()

					var e error

					var calls int
					p, e = PatchInstanceMethodByName(reflect.TypeOf(websocket.Conn{}), "WriteMessage",
						func(_ *websocket.Conn, _ int, _ []byte) error {
							calls++

							return nil
						})

					Expect(e).NotTo(HaveOccurred())

					e = sendNotificationToAllSubscribers(prod, n, eaaContext)

					Expect(e).NotTo(HaveOccurred())
					Expect(calls).To(Equal(3))
				})
			})

			g.When("eaa context is broken", func() {
				g.It("should fail", func() {
					eaaContext.serviceInfo.m = nil

					e := sendNotificationToAllSubscribers(prod, n, eaaContext)

					Expect(e).To(HaveOccurred())
				})
			})

			g.When("common name is broken", func() {
				g.It("should fail", func() {
					e := sendNotificationToAllSubscribers("bad common name", n, eaaContext)

					Expect(e).To(HaveOccurred())
				})
			})

			g.When("jsonmarshaling fails", func() {
				g.It("should fail", func() {
					patch, e := PatchMethod(json.Marshal, func(v interface{}) ([]byte, error) {
						return nil, errors.New("unit test error")
					})

					defer patch.Unpatch()

					Expect(e).NotTo(HaveOccurred())

					e = sendNotificationToAllSubscribers(prod, n, eaaContext)

					Expect(e).To(HaveOccurred())
				})
			})

			g.When("there is no service with provided common name", func() {
				g.It("should fail", func() {
					// remove the service/producer
					eaaContext.serviceInfo.m = make(map[string]Service)

					e := sendNotificationToAllSubscribers(prod, n, eaaContext)

					Expect(e).To(HaveOccurred())
				})
			})

			g.When("there is no subscription on a given namespace", func() {
				g.It("should not send notifications to subscriber", func() {
					// clear subscriptions
					eaaContext.subscriptionInfo.m = make(map[UniqueNotif]*ConsumerSubscription)

					e := sendNotificationToAllSubscribers(prod, n, eaaContext)

					Expect(e).NotTo(HaveOccurred())
				})
			})
		})
	})

	g.Describe("sendNotificationToSubscriber", func() {
		g.When("there is a consumer connection but no websocket connection established", func() {
			subscriptionID := "xxx"

			g.BeforeEach(func() {
				eaaContext.consumerConnections.m[subscriptionID] = ConsumerConnection{}
			})

			g.When("and websocket is created in time", func() {
				g.It("should wait for consumer connection, return no error and send message through the websocket",
					func() {
						p.Unpatch()

						var e error

						var calls int
						p, e = PatchInstanceMethodByName(reflect.TypeOf(websocket.Conn{}), "WriteMessage",
							func(_ *websocket.Conn, _ int, _ []byte) error {
								calls++

								return nil
							})

						Expect(e).NotTo(HaveOccurred())

						go func() {
							time.Sleep(500 * time.Millisecond)

							eaaContext.consumerConnections.RLock()
							eaaContext.consumerConnections.m[subscriptionID] = ConsumerConnection{&websocket.Conn{}}
							eaaContext.consumerConnections.RUnlock()
						}()

						e = sendNotificationToSubscriber(subscriptionID, []byte{1, 2, 3}, eaaContext)

						Expect(e).NotTo(HaveOccurred())
						Expect(calls).To(Equal(1))
					})
			})

			g.When("and websocket is not created in time", func() {
				g.It("should fail with an error", func() {
					e := sendNotificationToSubscriber(subscriptionID, []byte{1, 2, 3}, eaaContext)

					Expect(e).To(HaveOccurred())
				})
			})
		})
	})
})
