// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package eaa

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ThreeDotsLabs/watermill/message"
)

// Topic types
const (
	notificationsTopicPrefix = "ns_"
	servicesTopic            = "services"
	clientTopicPrefix        = "client_"
)

// Topic name generation functions
func getClientTopicName(commonName string) string {
	return clientTopicPrefix + strings.ReplaceAll(commonName, ":", ".")
}

func getNotificationTopicName(namespace string) string {
	return notificationsTopicPrefix + namespace
}

// Publisher type enum
type publisherType int

const (
	// Notification Publisher is used to post Notifications from Services
	notificationPublisher publisherType = iota
	// Services Publisher is used to post Services (un)subscriptions
	servicesPublisher publisherType = iota
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
	addPublisher(t publisherType, topic string, r *http.Request) error
	publish(topic string, msg *message.Message) error
	addSubscriber(t subscriberType, topic string, r *http.Request) error
	removeAll() error
}

// --------
// Message Handlers

// All messages from notificationSubscriber topics should be handled by this callback.
func handleNotificationUpdates(messages <-chan *message.Message, eaaCtx *Context) {
	log.Info("handleNotificationUpdates() starts")
	for msg := range messages {
		log.Debugf("received notification message: %s, payload: %s", msg.UUID, string(msg.Payload))

		var notifMsg NotificationMessage
		err := json.Unmarshal(msg.Payload, &notifMsg)
		if err != nil {
			log.Errf("Error Decoding: %s", err.Error())
			msg.Ack()
			continue
		}

		if notifMsg.Notification == nil {
			log.Err("Error: NotificationMessage.Notification is nil")
			msg.Ack()
			continue
		}
		if notifMsg.URN == nil {
			log.Err("Error: NotificationMessage.URN is nil")
			msg.Ack()
			continue
		}

		err = sendNotificationToAllSubscribers(notifMsg.URN.String(), notifMsg.Notification, eaaCtx)
		if err != nil {
			log.Errf("Error in Publish Notification: %s", err.Error())
		}

		msg.Ack()
	}
	log.Info("handleNotificationUpdates() finishes")
}

// All messages from servicesSubscriber topic should be handled by this callback.
func handleServiceUpdates(messages <-chan *message.Message, eaaCtx *Context) {
	log.Info("handleServiceUpdates() starts")
	for msg := range messages {
		log.Debugf("received service message: %s, payload: %s", msg.UUID, string(msg.Payload))

		var svcMsg ServiceMessage
		err := json.Unmarshal(msg.Payload, &svcMsg)
		if err != nil {
			log.Errf("Error Decoding: %s", err.Error())
			msg.Ack()
			continue
		}

		if svcMsg.Svc == nil {
			log.Err("Error: ServiceMessage.Svc is nil")
			msg.Ack()
			continue
		}
		if svcMsg.Svc.URN == nil {
			log.Err("Error: ServiceMessage.Svc.URN is nil")
			msg.Ack()
			continue
		}
		commonName := svcMsg.Svc.URN.String()

		switch svcMsg.Action {
		case serviceActionRegister:
			if err = addService(commonName, *svcMsg.Svc, eaaCtx); err != nil {
				log.Errf("Register Application error: %s", err.Error())
			}
		case serviceActionDeregister:
			if err = removeService(commonName, eaaCtx); err != nil {
				log.Errf("Deregister Application error: %s", err.Error())
			}
		default:
			log.Errf("Unknown Service Action: %v", svcMsg.Action)
		}

		// we need to Acknowledge that we received and processed the message,
		// otherwise, it will be resent over and over again.
		msg.Ack()
	}
	log.Info("handleServiceUpdates() finishes")
}

// All messages from clientSubscriber topics should be handled by this callback.
func handleClientUpdates(messages <-chan *message.Message, eaaCtx *Context) {
	log.Info("handleClientUpdates() starts")
	for msg := range messages {
		log.Debugf("received client sub message: %s, payload: %s", msg.UUID, string(msg.Payload))

		var subscriptionMsg SubscriptionMessage

		err := json.Unmarshal(msg.Payload, &subscriptionMsg)
		if err != nil {
			log.Errf("Error Decoding: %s", err.Error())
			msg.Ack()
			continue
		}

		// Retrieve all fields from the message
		var namespace, serviceID string
		var subs []NotificationDescriptor

		clientCommonName := subscriptionMsg.ClientCommonName
		if subscriptionMsg.Scope != subscriptionScopeAll {
			if subscriptionMsg.Subscription == nil {
				log.Err("Subscription can't be nil when SubscriptionMessage.Scope != subscriptionScopeAll")
				msg.Ack()
				continue
			}
			if subscriptionMsg.Subscription.URN == nil {
				log.Err("URN can't be nil when SubscriptionMessage.Scope != subscriptionScopeAll")
				msg.Ack()
				continue
			}
			namespace = subscriptionMsg.Subscription.URN.Namespace
			serviceID = subscriptionMsg.Subscription.URN.ID
			subs = subscriptionMsg.Subscription.Notifications
		}

		// (Un)subscribe to namespace/service notifications depending on Action and Scope fields
		switch subscriptionMsg.Action {
		case subscriptionActionSubscribe:
			subscribeClient(&subscriptionMsg, clientCommonName, namespace, serviceID, subs, eaaCtx)
		case subscriptionActionUnsubscribe:
			unsubscribeClient(&subscriptionMsg, clientCommonName, namespace, serviceID, subs,
				eaaCtx)
		default:
			log.Errf("Unknown SubscriptionMessage Action: %v", subscriptionMsg.Action)
		}

		msg.Ack()
	}
	log.Info("handleClientUpdates() finishes")
}

func subscribeClient(subscriptionMsg *SubscriptionMessage, clientCommonName string,
	namespace string, serviceID string, subs []NotificationDescriptor, eaaCtx *Context) {

	switch subscriptionMsg.Scope {
	case subscriptionScopeNamespace:
		// Remove all previous subscriptions to the Namespace notifs
		err := removeAllSubscriptionsToNamespace(clientCommonName, namespace, eaaCtx)
		if err != nil {
			log.Errf("removeAllSubscriptionsToNamespace() error: %s", err.Error())
		}
		// Add subscriptions to the Namespace notifs
		err = addSubscriptionToNamespace(clientCommonName, namespace, subs, eaaCtx)
		if err != nil {
			log.Errf("addSubscriptionToNamespace() error: %s", err.Error())
		}
	case subscriptionScopeService:
		// Remove all previous subscriptions to the Service notifs
		err := removeAllSubscriptionsToService(clientCommonName, namespace, serviceID,
			eaaCtx)
		if err != nil {
			log.Errf("removeAllSubscriptionsToService() error: %s", err.Error())
		}
		// Add subscriptions to the Service notifs
		err = addSubscriptionToService(clientCommonName, namespace, serviceID, subs, eaaCtx)
		if err != nil {
			log.Errf("addSubscriptionToService() error: %s", err.Error())
		}
	default:
		log.Errf("Unknown SubscriptionMessage Scope: %v", subscriptionMsg.Scope)
	}
}

func unsubscribeClient(subscriptionMsg *SubscriptionMessage, clientCommonName string,
	namespace string, serviceID string, subs []NotificationDescriptor, eaaCtx *Context) {

	switch subscriptionMsg.Scope {
	case subscriptionScopeNamespace:
		err := removeSubscriptionToNamespace(clientCommonName, namespace, subs, eaaCtx)
		if err != nil {
			log.Errf("removeSubscriptionToNamespace() error: %s", err.Error())
		}
	case subscriptionScopeService:
		err := removeSubscriptionToService(clientCommonName, namespace, serviceID, subs,
			eaaCtx)
		if err != nil {
			log.Errf("removeSubscriptionToService() error: %s", err.Error())
		}
	case subscriptionScopeAll:
		err := removeAllSubscriptions(clientCommonName, eaaCtx)
		if err != nil {
			log.Errf("removeAllSubscriptions() error: %s", err.Error())
		}
	default:
		log.Errf("Unknown SubscriptionMessage Scope: %v", subscriptionMsg.Scope)
	}
}
