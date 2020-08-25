// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package eaa

import (
	"net/http"

	"github.com/ThreeDotsLabs/watermill/message"
)

// Publisher type enum
type publisherType int

const (
	// Notification Publisher is used to post Notifications from Services
	notificationPublisher publisherType = iota
	// Services Publisher is used to post Services (un)subscriptions
	servicesPublisher
	// Services Publisher is used to post Client Notification (de)registrations
	clientPublisher
)

func (p publisherType) String() string {
	return [...]string{"Notification Publisher", "Services Publisher", "Client Publisher"}[p]
}

// Subscriber type enum
type subscriberType int

const (
	// Notification Subscriber receives Notifications of a given type
	notificationSubscriber subscriberType = iota
	// Services Subscriber receives Services (un)subscriptions
	servicesSubscriber
	// Services Publisher receives Client Notification (de)registrations
	clientSubscriber
)

func (s subscriberType) String() string {
	return [...]string{"Notification Subscriber", "Services Subscriber", "Client Subscriber"}[s]
}

// msgBroker specifies the Message Broker interface.
type msgBroker interface {
	addPublisher(t publisherType, id string, r *http.Request) error
	removePublisher(id string) error
	publish(publisherID string, msg *message.Message) error
	addSubscriber(t subscriberType, id string, r *http.Request) error
	removeSubscriber(id string) error
}
