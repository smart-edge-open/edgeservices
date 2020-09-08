// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package eaa

import (
	"encoding/json"
	"net/http"

	"github.com/ThreeDotsLabs/watermill/message"
)

// Topic types
const (
	notificationsTopicPrefix = "ns_"
	servicesTopic            = "services"
	clientTopicPrefix        = "client_"
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

// Object already exists error is returned when trying to add a publisher/subscriber that already
// exists.
type objectAlreadyExistsError struct {
	error
}

// msgBroker specifies the Message Broker interface.
type msgBroker interface {
	addPublisher(t publisherType, id string, r *http.Request) error
	removePublisher(id string) error
	publish(publisherID string, topic string, msg *message.Message) error
	addSubscriber(t subscriberType, id string, r *http.Request) error
	removeSubscriber(id string) error
}

// --------
// Callbacks

// All messages from notificationSubscriber topic should be handled by this callback.
func handleNotificationUpdates(messages <-chan *message.Message, eaaCtx *Context) {
	// TODO: Implement
}

// All messages from servicesSubscriber topic should be handled by this callback.
func handleServiceUpdates(messages <-chan *message.Message, eaaCtx *Context) {
	for msg := range messages {
		log.Debugf("received message: %s, payload: %s", msg.UUID, string(msg.Payload))

		var svcMsg ServiceMsg
		err := json.Unmarshal(msg.Payload, &svcMsg)
		if err != nil {
			log.Errf("Error Decoding: %s", err.Error())
			msg.Nack()
			continue
		}

		commonName := svcMsg.Svc.URN.String()

		switch svcMsg.Action {
		case serviceActionRegister:
			if err = addService(commonName, *svcMsg.Svc, eaaCtx); err != nil {
				log.Errf("Register Application error: %s", err.Error())
				msg.Ack()
				continue
			}
		case serviceActionDeregister:
			if err = removeService(commonName, eaaCtx); err != nil {
				log.Errf("Deregister Application error: %s", err.Error())
				msg.Ack()
				continue
			}
		default:
			log.Errf("Unknown Service Actions: %v", svcMsg.Action)
			msg.Ack()
			continue
		}

		// we need to Acknowledge that we received and processed the message,
		// otherwise, it will be resent over and over again.
		msg.Ack()
	}
}

// All messages from clientSubscriber topic should be handled by this callback.
func handleClientUpdates(messages <-chan *message.Message, eaaCtx *Context) {
	// TODO: Implement
}
