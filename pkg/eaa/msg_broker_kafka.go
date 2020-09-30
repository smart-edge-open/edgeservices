// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package eaa

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/Shopify/sarama"
	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill-kafka/v2/pkg/kafka"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type publishers struct {
	sync.RWMutex
	m map[string]*kafka.Publisher
}

type subscribers struct {
	sync.RWMutex
	m map[string]*kafka.Subscriber
}

// KafkaMsgBroker is a Kafka-backed msgBroker
type KafkaMsgBroker struct {
	eaaCtx           *Context
	consumerGroup    string
	defaultPublisher *kafka.Publisher
	pubs             publishers
	subs             subscribers
	tlsConfig        *tls.Config
}

// NewKafkaMsgBroker creates and returns a Kafka-backed msgBroker
func NewKafkaMsgBroker(eaaCtx *Context, consumerGroup string,
	tlsConfig *tls.Config) (*KafkaMsgBroker, error) {

	broker := KafkaMsgBroker{eaaCtx: eaaCtx, consumerGroup: consumerGroup}

	broker.tlsConfig = tlsConfig

	defaultPublisher, err := broker.createDefaultPublisher()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create a KafkaMsgBroker")
	}

	broker.defaultPublisher = defaultPublisher
	broker.pubs = publishers{m: make(map[string]*kafka.Publisher)}
	broker.subs = subscribers{m: make(map[string]*kafka.Subscriber)}

	return &broker, nil
}

// PUBLISHERS

// Generate a message primary key depending on a topic type
func keyGenerator(topic string, msg *message.Message) (string, error) {

	if strings.HasPrefix(topic, notificationsTopicPrefix) {
		// Each notification should get a different primary key to avoid log compaction
		return uuid.New().String(), nil

	} else if strings.HasPrefix(topic, servicesTopic) {
		var svcMsg ServiceMessage
		err := json.Unmarshal(msg.Payload, &svcMsg)
		if err != nil {
			return "", errors.Wrap(err, "Couldn't unmarshal a message to generate its key!")
		}

		if svcMsg.Svc.URN == nil {
			return "", fmt.Errorf("URN shouldn't be nil (topic: %v)", topic)
		}

		return svcMsg.Svc.URN.String(), nil

	} else if strings.HasPrefix(topic, clientTopicPrefix) {
		var subscriptionMsg SubscriptionMessage
		err := json.Unmarshal(msg.Payload, &subscriptionMsg)
		if err != nil {
			return "", errors.Wrap(err, "Couldn't unmarshal a message to generate its key!")
		}

		// Unsubscribe All message has no URN
		if subscriptionMsg.Action == subscriptionActionUnsubscribe &&
			subscriptionMsg.Scope == subscriptionScopeAll {
			return "", nil
		}

		if subscriptionMsg.Subscription.URN == nil {
			return "", fmt.Errorf("URN shouldn't be nil (topic: %v)", topic)
		}

		return subscriptionMsg.Subscription.URN.String(), nil
	}

	return "", fmt.Errorf("Key generation failed for unknown topic type: %v", topic)
}

// Creates a Publisher with default configuration
func (b *KafkaMsgBroker) createDefaultPublisher() (*kafka.Publisher, error) {
	config := kafka.DefaultSaramaSyncPublisherConfig()
	config.Net.TLS.Enable = true
	config.Net.TLS.Config = b.tlsConfig

	publisher, err := kafka.NewPublisher(
		kafka.PublisherConfig{
			Brokers:               []string{b.eaaCtx.cfg.KafkaBroker},
			Marshaler:             kafka.NewWithPartitioningMarshaler(keyGenerator),
			OverwriteSaramaConfig: config,
		},
		watermill.NewStdLogger(false, false),
	)

	if err != nil {
		return nil, errors.Wrap(err, "Couldn't create a default Publisher")
	}
	return publisher, nil
}

// Add a Publisher for a given topic.
// All messages can be currently handled by a single Publisher - the only thing that differs
// for different message types is the key generation process and keyGenerator() function can
// recognize the type of a message based on the topic prefix.
func (b *KafkaMsgBroker) addPublisher(t publisherType, topic string, r *http.Request) error {
	b.pubs.Lock()
	defer b.pubs.Unlock()

	// Only one Publisher per topic is permitted
	if _, found := b.pubs.m[topic]; found {
		return objectAlreadyExistsError{fmt.Errorf("Publisher with ID '%v' already exists", topic)}
	}

	// Default Publisher may have been removed in removeAll()
	if b.defaultPublisher == nil {
		defaultPublisher, err := b.createDefaultPublisher()
		if err != nil {
			return errors.Wrap(err, "Failed to create a KafkaMsgBroker")
		}
		b.defaultPublisher = defaultPublisher
	}

	b.pubs.m[topic] = b.defaultPublisher
	log.Infof("Added Publisher for a topic: %v", topic)

	return nil
}

// Publish a msg using a Publisher to a given topic.
func (b *KafkaMsgBroker) publish(topic string, msg *message.Message) error {
	// kafka.Publisher::Publish() method is thread-safe - we can use Reader lock
	b.pubs.RLock()
	defer b.pubs.RUnlock()

	if publisher, found := b.pubs.m[topic]; found {
		err := publisher.Publish(topic, msg)
		if err != nil {
			err = errors.Wrapf(err, "Error when Publishing a message to the topic: %v",
				topic)
		}
		return err
	}

	return fmt.Errorf("Invalid Publisher topic: %v", topic)
}

// SUBSCRIBERS

// Create a Kafka Subscriber with a Sarama config
func (b *KafkaMsgBroker) createSubscriber(config *sarama.Config) (*kafka.Subscriber, error) {
	subscriber, err := kafka.NewSubscriber(
		kafka.SubscriberConfig{
			Brokers:               []string{b.eaaCtx.cfg.KafkaBroker},
			Unmarshaler:           kafka.DefaultMarshaler{},
			OverwriteSaramaConfig: config,
			ConsumerGroup:         b.consumerGroup,
		},
		watermill.NewStdLogger(false, false),
	)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create Kafka Subscriber!")
	}
	return subscriber, nil
}

// Create Notification Publisher
func (b *KafkaMsgBroker) createNotificationSubscriber(topic string) (*kafka.Subscriber, error) {
	saramaSubscriberConfig := kafka.DefaultSaramaSubscriberConfig()
	saramaSubscriberConfig.Consumer.Offsets.Initial = sarama.OffsetNewest
	saramaSubscriberConfig.Net.TLS.Enable = true
	saramaSubscriberConfig.Net.TLS.Config = b.tlsConfig

	subscriber, err := b.createSubscriber(saramaSubscriberConfig)
	if err != nil {
		return nil, errors.Wrap(err, "Notifications Subscriber creation failure!")
	}

	messages, err := subscriber.Subscribe(context.Background(), topic)
	if err != nil {
		return nil, errors.Wrap(err, "Notifications Subscriptions Registration failure!")
	}

	go handleNotificationUpdates(messages, b.eaaCtx)

	return subscriber, nil
}

// Create Services Publisher
func (b *KafkaMsgBroker) createServicesSubscriber() (*kafka.Subscriber, error) {
	saramaSubscriberConfig := kafka.DefaultSaramaSubscriberConfig()
	// equivalent of auto.offset.reset: earliest
	saramaSubscriberConfig.Consumer.Offsets.Initial = sarama.OffsetOldest
	saramaSubscriberConfig.Net.TLS.Enable = true
	saramaSubscriberConfig.Net.TLS.Config = b.tlsConfig

	subscriber, err := b.createSubscriber(saramaSubscriberConfig)
	if err != nil {
		return nil, errors.Wrap(err, "Services Subscriber creation failure!")
	}

	messages, err := subscriber.Subscribe(context.Background(), servicesTopic)
	if err != nil {
		return nil, errors.Wrap(err, "Services Subscriptions Registration failure!")
	}

	go handleServiceUpdates(messages, b.eaaCtx)

	return subscriber, nil
}

// Create Client Publisher
func (b *KafkaMsgBroker) createClientSubscriber(topic string) (*kafka.Subscriber, error) {
	saramaSubscriberConfig := kafka.DefaultSaramaSubscriberConfig()
	// equivalent of auto.offset.reset: earliest
	saramaSubscriberConfig.Consumer.Offsets.Initial = sarama.OffsetOldest
	saramaSubscriberConfig.Net.TLS.Enable = true
	saramaSubscriberConfig.Net.TLS.Config = b.tlsConfig

	subscriber, err := b.createSubscriber(saramaSubscriberConfig)
	if err != nil {
		return nil, errors.Wrap(err, "Client Subscriber creation failure!")
	}

	messages, err := subscriber.Subscribe(context.Background(), topic)
	if err != nil {
		return nil, errors.Wrap(err, "Client Subscriptions Registration failure!")
	}

	go handleClientUpdates(messages, b.eaaCtx)

	return subscriber, nil
}

// Add a Subscriber of type t for a topic based on a HTTP request r.
// The Subsriber can be later accessed using its topic.
// If a Subscriber for a given topic already exists, objectAlreadyExistsError is returned.
func (b *KafkaMsgBroker) addSubscriber(t subscriberType, topic string, r *http.Request) error {
	b.subs.Lock()
	defer b.subs.Unlock()

	// Only one Subscriber per topic is permitted
	if _, found := b.subs.m[topic]; found {
		return objectAlreadyExistsError{fmt.Errorf("Subscriber for a topic '%v' already exists",
			topic)}
	}

	var subscriber *kafka.Subscriber
	var err error

	switch t {
	case notificationSubscriber:
		subscriber, err = b.createNotificationSubscriber(topic)
	case servicesSubscriber:
		subscriber, err = b.createServicesSubscriber()
	case clientSubscriber:
		subscriber, err = b.createClientSubscriber(topic)
	default:
		return fmt.Errorf("Unknown Subscriber type: %v", t)
	}

	if err != nil {
		return errors.Wrapf(err, "Couldn't create Subscriber of type '%v' for a topic: %v", t,
			topic)
	}

	b.subs.m[topic] = subscriber
	log.Infof("Added Subscriber for a topic: %v", topic)

	return nil
}

// Close and remove all Publishers and Subscribers
func (b *KafkaMsgBroker) removeAll() error {
	b.pubs.Lock()
	defer b.pubs.Unlock()

	b.subs.Lock()
	defer b.subs.Unlock()

	var errs []error
	for topic, subscriber := range b.subs.m {
		if subscriber != nil {
			err := subscriber.Close()
			if err != nil {
				errs = append(errs, errors.Wrapf(err,
					"Failed to remove a Subscriber for a topic '%v'", topic))
			}
		} else {
			errs = append(errs, fmt.Errorf("Subscriber '%v' is nil", topic))
		}
	}

	// Kafka Broker uses only one Publisher
	err := b.defaultPublisher.Close()
	if err != nil {
		errs = append(errs, errors.Wrapf(err,
			"Failed to remove the Default Publisher"))
	}

	b.defaultPublisher = nil

	// Clear the maps
	b.pubs.m = make(map[string]*kafka.Publisher)
	b.subs.m = make(map[string]*kafka.Subscriber)

	// Return concatenated errors
	if len(errs) > 0 {
		var errorStrings []string
		for _, err = range errs {
			errorStrings = append(errorStrings, err.Error())
		}
		return fmt.Errorf(strings.Join(errorStrings, "\n"))
	}

	return nil
}
