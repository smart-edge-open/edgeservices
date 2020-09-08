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
func (b *GoChannelMsgBroker) addPublisher(t publisherType, id string, r *http.Request) error {
	return nil
}

// Nothing to be done
func (b *GoChannelMsgBroker) removePublisher(id string) error {
	return nil
}

// Publish a msg using a Publisher with given ID.
func (b *GoChannelMsgBroker) publish(publisherID string, topic string, msg *message.Message) error {
	// There's a 1<->1 mapping between Subscriber ID and topic that it's being subscribed to
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

// Add a Subscriber of type t with a given id.
// The Subsriber can be later accessed using its id.
// If a Subscriber with a given id already exists, objectAlreadyExistsError is returned.
func (b *GoChannelMsgBroker) addSubscriber(t subscriberType, id string, r *http.Request) error {
	if _, found := b.goChannels[id]; found {
		// Only one Subscriber per ID is permitted
		return objectAlreadyExistsError{fmt.Errorf("Subscriber with ID '%v' already exists", id)}
	}

	// Create a new GoChannel
	b.goChannels[id] = gochannel.NewGoChannel(b.defaultConfig,
		watermill.NewStdLogger(true, true))

	msgChannel, err := b.goChannels[id].Subscribe(context.Background(), id)
	if err != nil {
		return errors.Wrapf(err, "Error when Subscribing to topic: %v", id)
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

// Close and remove a Subscriber with a given id.
func (b *GoChannelMsgBroker) removeSubscriber(id string) error {
	if goChannel, found := b.goChannels[id]; found {
		err := goChannel.Close()
		delete(b.goChannels, id)
		if err != nil {
			err = errors.Wrapf(err, "Error when closing a GoChannel with ID: %v", id)
		}
		return err
	}

	return fmt.Errorf("Invalid Subscriber ID: %v", id)
}
