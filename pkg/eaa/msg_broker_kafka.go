// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package eaa

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Shopify/sarama"
	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill-kafka/v2/pkg/kafka"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/pkg/errors"
)

type lookupError struct {
	error
}

// kafkaMsgBroker is a Kafka-backed msgBroker
type kafkaMsgBroker struct {
	eaaCtx        *eaaContext
	consumerGroup string
	marshaller    kafka.MarshalerUnmarshaler
	publishers    map[string]*kafka.Publisher
	subscribers   map[string]*kafka.Subscriber
}

// Creates and returns a Kafka-backed msgBroker
func newKafkaMsgBroker(eaaCtx *eaaContext, consumerGroup string) *kafkaMsgBroker {
	broker := kafkaMsgBroker{eaaCtx: eaaCtx, consumerGroup: consumerGroup}

	broker.publishers = make(map[string]*kafka.Publisher)
	broker.subscribers = make(map[string]*kafka.Subscriber)
	broker.marshaller = kafka.NewWithPartitioningMarshaler(keyGenerator)

	return &broker
}

// Generate a message primary key depending on a topic type
func keyGenerator(topic string, msg *message.Message) (string, error) {
	if strings.HasPrefix(topic, notificationsTopicPrefix) {
		// namespace notifications topic type
		// TODO: Add namespace notification messages handler
		return "", nil

	} else if strings.HasPrefix(topic, servicesTopic) {
		// 'services' topic type

		var svcMsg ServiceMsg
		err := json.Unmarshal(msg.Payload, &svcMsg)

		if err != nil {
			return "", errors.Wrap(err, "Couldn't unmarshal a message to generate its key!")
		}

		return svcMsg.Svc.URN.String(), nil

	} else if strings.HasPrefix(topic, clientTopicPrefix) {
		// client subscriptions topic type
		// TODO: Add client subscriptions messages handler
		return "", nil
	}

	return "", fmt.Errorf("Key generation failed for unknown topic type: %v", topic)
}

// Creates a Publisher with default configuration
func (b *kafkaMsgBroker) createDefaultPublisher() (*kafka.Publisher, error) {
	publisher, err := kafka.NewPublisher(
		kafka.PublisherConfig{
			Brokers:   []string{b.eaaCtx.cfg.KafkaBroker},
			Marshaler: b.marshaller,
		},
		watermill.NewStdLogger(false, false),
	)

	if err != nil {
		return nil, errors.Wrap(err, "Couldn't create a default Publisher")
	}
	return publisher, nil
}

// Create Notification Publisher based on a HTTP request
func (b *kafkaMsgBroker) createNotificationPublisher(r *http.Request) (*kafka.Publisher, error) {
	// TODO: Implement
	return nil, nil
}

// Create Services Publisher based on a HTTP request
func (b *kafkaMsgBroker) createServicesPublisher() (*kafka.Publisher, error) {
	return b.createDefaultPublisher()
}

// Create Client Publisher based on a HTTP request
func (b *kafkaMsgBroker) createClientPublisher(r *http.Request) (*kafka.Publisher, error) {
	// TODO: Implement
	return nil, nil
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
	var err error

	switch t {
	case notificationPublisher:
		publisher, err = b.createNotificationPublisher(r)
	case servicesPublisher:
		publisher, err = b.createServicesPublisher()
	case clientPublisher:
		publisher, err = b.createClientPublisher(r)
	default:
		return fmt.Errorf("Unknown Publisher type: %v", t)
	}

	if err != nil {
		return errors.Wrapf(err, "Couldn't create Publisher with ID: %v", id)
	}

	log.Errf("Added Publisher with ID: %v", id)

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
		var err error
		if err = publisher.Publish(publisherID, msg); err != nil {
			err = errors.Wrapf(err, "Error when Publishing a message with publisherID: %v",
				publisherID)
		}
		return err
	}

	return fmt.Errorf("Invalid Publisher ID: %v", publisherID)
}

// Create Notification Publisher based on a HTTP request
func (b *kafkaMsgBroker) createNotificationSubscriber(r *http.Request) (*kafka.Subscriber, error) {
	// TODO: Implement
	return nil, nil
}

// Create Services Publisher based on a HTTP request
func (b *kafkaMsgBroker) createServicesSubscriber() (*kafka.Subscriber, error) {
	saramaSubscriberConfig := kafka.DefaultSaramaSubscriberConfig()
	// equivalent of auto.offset.reset: earliest
	saramaSubscriberConfig.Consumer.Offsets.Initial = sarama.OffsetOldest

	log.Errln(b.eaaCtx.cfg.KafkaBroker)

	subscriber, err := kafka.NewSubscriber(
		kafka.SubscriberConfig{
			Brokers:               []string{b.eaaCtx.cfg.KafkaBroker},
			Unmarshaler:           kafka.DefaultMarshaler{},
			OverwriteSaramaConfig: saramaSubscriberConfig,
			ConsumerGroup:         b.consumerGroup,
		},
		watermill.NewStdLogger(false, false),
	)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create Kafka Subscriber!")
	}

	messages, err := subscriber.Subscribe(context.Background(), "services")
	if err != nil {
		return nil, errors.Wrap(err, "Namespace Notification Registration failure!")
	}

	go handleServiceUpdates(messages, b.eaaCtx)

	return subscriber, nil
}

// Create Client Publisher based on a HTTP request
func (b *kafkaMsgBroker) createClientSubscriber(r *http.Request) (*kafka.Subscriber, error) {
	// TODO: Implement
	return nil, nil
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
	var err error

	switch t {
	case notificationSubscriber:
		subscriber, err = b.createNotificationSubscriber(r)
	case servicesSubscriber:
		subscriber, err = b.createServicesSubscriber()
	case clientSubscriber:
		subscriber, err = b.createClientSubscriber(r)
	default:
		return fmt.Errorf("Unknown Subscriber type: %v", t)
	}

	if err != nil {
		return errors.Wrapf(err, "Couldn't create Subscriber with ID: %v", id)
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
