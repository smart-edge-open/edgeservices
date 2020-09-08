// // SPDX-License-Identifier: Apache-2.0
// // Copyright (c) 2020 Intel Corporation

package eaa

import (
	"context"
	"fmt"
	"net/http"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/ThreeDotsLabs/watermill/pubsub/gochannel"
	"github.com/pkg/errors"
)

// GoChannelMsgBroker is a GoChannel-backed msgBroker
type GoChannelMsgBroker struct {
	eaaCtx        *Context
	defaultConfig gochannel.Config
	goChannels    map[string]*gochannel.GoChannel
}

// NewGoChannelMsgBroker creates and returns a GoChannel-backed msgBroker
func NewGoChannelMsgBroker(eaaCtx *Context) *GoChannelMsgBroker {
	broker := GoChannelMsgBroker{eaaCtx: eaaCtx}
	broker.defaultConfig = gochannel.Config{
		OutputChannelBuffer:            10000,
		Persistent:                     false,
		BlockPublishUntilSubscriberAck: false,
	}
	broker.goChannels = make(map[string]*gochannel.GoChannel)
	return &broker
}

// GoChannel acts as a Publisher and Subscriber at the same time.
// Publishing to a GoChannel that is not subsribed by anyone results in a noop.
func (b *GoChannelMsgBroker) addPublisher(t publisherType, topic string, r *http.Request) error {
	return nil
}

// Nothing to be done
func (b *GoChannelMsgBroker) removePublisher(topic string) error {
	return nil
}

// Publish a msg using a Publisher to a given topic.
func (b *GoChannelMsgBroker) publish(topic string, msg *message.Message) error {
	if goChannel, found := b.goChannels[topic]; found {
		var err error
		if err = goChannel.Publish(topic, msg); err != nil {
			err = errors.Wrapf(err, "Error when Publishing a message on topic: %v",
				topic)
		}
		return err
	}

	return fmt.Errorf("Invalid topic: %v", topic)
}

// Add a Subscriber of type t with for a given topic.
// The Subsriber can be later accessed using its topic.
// If a Subscriber with for a given topic already exists, objectAlreadyExistsError is returned.
func (b *GoChannelMsgBroker) addSubscriber(t subscriberType, topic string, r *http.Request) error {
	if _, found := b.goChannels[topic]; found {
		// Only one Subscriber per ID is permitted
		return objectAlreadyExistsError{fmt.Errorf("Subscriber with ID '%v' already exists", topic)}
	}

	// Create a new GoChannel
	b.goChannels[topic] = gochannel.NewGoChannel(b.defaultConfig,
		watermill.NewStdLogger(true, true))

	msgChannel, err := b.goChannels[topic].Subscribe(context.Background(), topic)
	if err != nil {
		return errors.Wrapf(err, "Error when Subscribing to the topic: %v", topic)
	}

	switch t {
	case notificationSubscriber:
		go handleNotificationUpdates(msgChannel, b.eaaCtx)
	case servicesSubscriber:
		go handleServiceUpdates(msgChannel, b.eaaCtx)
	case clientSubscriber:
		go handleClientUpdates(msgChannel, b.eaaCtx)
	default:
		return fmt.Errorf("Unknown Subscriber type: %v", t)
	}

	return nil
}

// Close and remove a Subscriber for a given topic.
func (b *GoChannelMsgBroker) removeSubscriber(topic string) error {
	if goChannel, found := b.goChannels[topic]; found {
		err := goChannel.Close()
		delete(b.goChannels, topic)
		if err != nil {
			err = errors.Wrapf(err, "Failed to remove a Subscriber for the topic: %v", topic)
		}
		return err
	}

	return fmt.Errorf("Invalid Subscriber ID: %v", topic)
}

// Close and remove all GoChannels
func (b *GoChannelMsgBroker) removeAll() error {
	for topic, goChannel := range b.goChannels {
		err := goChannel.Close()
		if err != nil {
			return errors.Wrapf(err, "Failed to remove all GoChannels (topic '%v')", topic)
		}
	}

	// Clear the map
	b.goChannels = make(map[string]*gochannel.GoChannel)

	return nil
}
