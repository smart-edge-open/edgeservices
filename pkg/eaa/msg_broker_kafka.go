// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package eaa

import (
	"fmt"
	"net/http"

	"github.com/ThreeDotsLabs/watermill-kafka/v2/pkg/kafka"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/pkg/errors"
)

type lookupError struct {
	error
}

// kafkaMsgBroker is a Kafka-backed msgBroker
type kafkaMsgBroker struct {
	ConsumerGroup string
	publishers    map[string]*kafka.Publisher
	subscribers   map[string]*kafka.Subscriber
}

// Create Notification Publisher based on a HTTP request
func (b *kafkaMsgBroker) createNotificationPublisher(r *http.Request) *kafka.Publisher {
	// TODO: Implement
	return nil
}

// Create Services Publisher based on a HTTP request
func (b *kafkaMsgBroker) createServicesPublisher(r *http.Request) *kafka.Publisher {
	// TODO: Implement
	return nil
}

// Create Client Publisher based on a HTTP request
func (b *kafkaMsgBroker) createClientPublisher(r *http.Request) *kafka.Publisher {
	// TODO: Implement
	return nil
}

// Add a Publisher of type t based on a HTTP request.
// Later the Publisher can be accessed using its id.
// If a Publisher with given id already exists, lookupError is returned.
func (b *kafkaMsgBroker) addPublisher(t publisherType, id string, r *http.Request) error {
	// Only one Publisher per ID is permitted
	if _, found := b.publishers[id]; found {
		return lookupError{fmt.Errorf("Publisher with ID '%v' already exists", id)}
	}

	var publisher *kafka.Publisher

	switch t {
	case notificationPublisher:
		publisher = b.createNotificationPublisher(r)
	case servicesPublisher:
		publisher = b.createServicesPublisher(r)
	case clientPublisher:
		publisher = b.createClientPublisher(r)
	default:
		return fmt.Errorf("Unknown Publisher type: %v", t)
	}

	b.publishers[id] = publisher

	return nil
}

// Close and remove a Publisher with a given id.
func (b *kafkaMsgBroker) removePublisher(id string) error {
	if publisher, found := b.publishers[id]; found {
		err := publisher.Close()
		delete(b.publishers, id)
		if err != nil {
			err = errors.Wrapf(err, "Error when closing a Publisher with ID: %v", id)
		}
		return err
	}

	return fmt.Errorf("Invalid Publisher ID: %v", id)
}

// Publish a msg using a Publisher with given ID.
func (b *kafkaMsgBroker) publish(publisherID string, msg *message.Message) error {
	if publisher, found := b.publishers[publisherID]; found {
		if err := publisher.Publish(publisherID, msg); err != nil {
			return errors.Wrapf(err, "Error when Publishing a message with publisherID: %v",
				publisherID)
		}
	}

	return fmt.Errorf("Invalid Publisher ID: %v", publisherID)
}

// Create Notification Publisher based on a HTTP request
func (b *kafkaMsgBroker) createNotificationSubscriber(r *http.Request) *kafka.Subscriber {
	// TODO: Implement
	return nil
}

// Create Services Publisher based on a HTTP request
func (b *kafkaMsgBroker) createServicesSubscriber(r *http.Request) *kafka.Subscriber {
	// TODO: Implement
	return nil
}

// Create Client Publisher based on a HTTP request
func (b *kafkaMsgBroker) createClientSubscriber(r *http.Request) *kafka.Subscriber {
	// TODO: Implement
	return nil
}

// Add a Subscriber of type t based on a HTTP request.
// The Subsriber can be later accessed using its id.
// If a Subscriber with a given id already exists, lookupError is returned.
func (b *kafkaMsgBroker) addSubscriber(t subscriberType, id string, r *http.Request) error {
	// Only one Subscriber per ID is permitted
	if _, found := b.subscribers[id]; found {
		return lookupError{fmt.Errorf("Subscriber with ID '%v' already exists", id)}
	}

	var subscriber *kafka.Subscriber

	switch t {
	case notificationSubscriber:
		subscriber = b.createNotificationSubscriber(r)
	case servicesSubscriber:
		subscriber = b.createServicesSubscriber(r)
	case clientSubscriber:
		subscriber = b.createClientSubscriber(r)
	default:
		return fmt.Errorf("Unknown Subscriber type: %v", t)
	}

	b.subscribers[id] = subscriber

	return nil
}

// Close and remove a Subscriber with a given id.
func (b *kafkaMsgBroker) removeSubscriber(id string) error {
	if subscriber, found := b.subscribers[id]; found {
		err := subscriber.Close()
		delete(b.subscribers, id)
		if err != nil {
			err = errors.Wrapf(err, "Error when closing Subscriber with ID: %v", id)
		}
		return err
	}

	return fmt.Errorf("Invalid Subscriber ID: %v", id)
}
