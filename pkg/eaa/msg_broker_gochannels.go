// // SPDX-License-Identifier: Apache-2.0
// // Copyright (c) 2020 Intel Corporation

package eaa

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/ThreeDotsLabs/watermill/pubsub/gochannel"
	"github.com/pkg/errors"
)

type goChannel struct {
	ch          *gochannel.GoChannel
	isPublisher bool
}

type goChannels struct {
	sync.RWMutex
	m map[string]goChannel
}

// GoChannelMsgBroker is a GoChannel-backed msgBroker
type GoChannelMsgBroker struct {
	eaaCtx        *Context
	defaultConfig gochannel.Config
	pubSubs       goChannels
}

// NewGoChannelMsgBroker creates and returns a GoChannel-backed msgBroker
func NewGoChannelMsgBroker(eaaCtx *Context) *GoChannelMsgBroker {
	broker := GoChannelMsgBroker{eaaCtx: eaaCtx}
	broker.defaultConfig = gochannel.Config{
		OutputChannelBuffer:            10000,
		Persistent:                     false,
		BlockPublishUntilSubscriberAck: false,
	}
	broker.pubSubs = goChannels{m: make(map[string]goChannel)}
	return &broker
}

// GoChannel acts as a Publisher and Subscriber at the same time.
// Publishing to a GoChannel that is not subsribed by anyone results in a noop.
func (b *GoChannelMsgBroker) addPublisher(t publisherType, topic string, r *http.Request) error {
	b.pubSubs.Lock()
	defer b.pubSubs.Unlock()

	if goChann, found := b.pubSubs.m[topic]; found {
		if goChann.isPublisher {
			return objectAlreadyExistsError{
				fmt.Errorf("Publisher for a topic '%v' already exists", topic)}
		}
		goChann.isPublisher = true
		b.pubSubs.m[topic] = goChann
	} else {
		b.pubSubs.m[topic] = goChannel{ch: nil, isPublisher: true}
	}

	return nil
}

// Publish a msg using a Publisher to a given topic.
func (b *GoChannelMsgBroker) publish(topic string, msg *message.Message) error {
	b.pubSubs.RLock()
	defer b.pubSubs.RUnlock()

	if goChann, found := b.pubSubs.m[topic]; found {
		if !goChann.isPublisher {
			return fmt.Errorf("No Publisher for topic: %v, map: %#v", topic, b.pubSubs.m)
		}
		if goChann.ch == nil {
			log.Debugf("Publish skipped: no Subscriber for topic: %v", topic)
			return nil
		}
		if err := goChann.ch.Publish(topic, msg); err != nil {
			return errors.Wrapf(err, "Error when Publishing a message on topic: %v",
				topic)
		}
		return nil
	}

	return fmt.Errorf("No PubSub for topic: %v, map: %#v", topic, b.pubSubs.m)
}

// Add a Subscriber of type t with for a given topic.
// The Subsriber can be later accessed using its topic.
// If a Subscriber with for a given topic already exists, objectAlreadyExistsError is returned.
func (b *GoChannelMsgBroker) addSubscriber(t subscriberType, topic string, r *http.Request) error {
	b.pubSubs.Lock()
	defer b.pubSubs.Unlock()

	if goChann, found := b.pubSubs.m[topic]; found {
		// Only one Subscriber per topic is permitted
		if goChann.ch != nil {
			return objectAlreadyExistsError{
				fmt.Errorf("Subscriber with topic '%v' already exists", topic)}
		}
	} else {
		b.pubSubs.m[topic] = goChannel{}
	}

	// Create a new GoChannel
	ch := gochannel.NewGoChannel(b.defaultConfig, watermill.NewStdLogger(false, false))

	goChann := b.pubSubs.m[topic]
	goChann.ch = ch
	b.pubSubs.m[topic] = goChann

	msgChannel, err := b.pubSubs.m[topic].ch.Subscribe(context.Background(), topic)
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

// Close and remove all GoChannels
func (b *GoChannelMsgBroker) removeAll() error {
	b.pubSubs.Lock()
	defer b.pubSubs.Unlock()

	for topic, goChann := range b.pubSubs.m {
		if goChann.ch != nil {
			err := goChann.ch.Close()
			if err != nil {
				return errors.Wrapf(err, "Failed to remove all GoChannels (topic '%v')", topic)
			}
		}
	}

	// Clear the map
	b.pubSubs.m = make(map[string]goChannel)

	return nil
}
