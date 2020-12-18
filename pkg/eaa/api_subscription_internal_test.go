// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa

import (
	"github.com/gorilla/websocket"

	g "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = g.Describe("api_subscription internal errors", func() {
	var (
		eaaContext *Context
	)

	const serviceName = "service"

	cn := "aa:bb"
	ns := "aa"
	serviceID := "aa"

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
	})

	g.Describe("addSubscriptionToNamespace", func() {
		g.When("eaa context is broken", func() {
			g.It("should fail", func() {
				eaaContext.subscriptionInfo.m = nil

				e := addSubscriptionToNamespace(cn, ns, []NotificationDescriptor{}, eaaContext)

				Expect(e).To(HaveOccurred())
			})
		})
	})

	g.Describe("removeSubscriptionToService", func() {
		g.When("eaa context is broken", func() {
			g.It("should fail", func() {
				eaaContext.subscriptionInfo.m = nil

				e := removeSubscriptionToService(cn, ns, serviceID, []NotificationDescriptor{}, eaaContext)

				Expect(e).To(HaveOccurred())
			})
		})
	})

	g.Describe("removeAllSubscriptionsToService", func() {
		g.When("eaa context is broken", func() {
			g.It("should fail", func() {
				eaaContext.subscriptionInfo.m = nil

				e := removeAllSubscriptionsToService(cn, ns, serviceID, eaaContext)

				Expect(e).To(HaveOccurred())
			})
		})
	})

	g.Describe("removeSubscriptionToNamespace", func() {
		g.When("eaa context is broken", func() {
			g.It("should fail", func() {
				eaaContext.subscriptionInfo.m = nil

				e := removeSubscriptionToNamespace(cn, ns, []NotificationDescriptor{}, eaaContext)

				Expect(e).To(HaveOccurred())
			})
		})
	})

	g.Describe("addSubscriptionToService", func() {
		g.When("eaa context is broken", func() {
			g.It("should fail", func() {
				eaaContext.subscriptionInfo.m = nil

				e := addSubscriptionToService(cn, ns, serviceID, []NotificationDescriptor{}, eaaContext)

				Expect(e).To(HaveOccurred())
			})
		})
	})

	g.Describe("removeAllSubscriptionsToNamespace", func() {
		g.When("eaa context is broken", func() {
			g.It("should fail", func() {
				eaaContext.subscriptionInfo.m = nil

				e := removeAllSubscriptionsToNamespace(cn, ns, eaaContext)

				Expect(e).To(HaveOccurred())
			})
		})
	})

	g.Describe("removeAllSubscriptions", func() {
		g.When("eaa context is broken", func() {
			g.It("should fail", func() {
				eaaContext.subscriptionInfo.m = nil

				e := removeAllSubscriptions("", eaaContext)

				Expect(e).To(HaveOccurred())
			})
		})
	})
})
