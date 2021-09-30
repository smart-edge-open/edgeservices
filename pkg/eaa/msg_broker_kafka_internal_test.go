// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package eaa

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/Shopify/sarama"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	mockEAA "github.com/smart-edge-open/edgeservices/pkg/mock"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill-kafka/v2/pkg/kafka"
	message "github.com/ThreeDotsLabs/watermill/message"

	g "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/undefinedlabs/go-mpatch"
)

// TestMarshaler implementation
type TestMarshaler struct{}

func (TestMarshaler) Marshal(_ string, _ *message.Message) (*sarama.ProducerMessage, error) {
	return nil, nil
}
func (TestMarshaler) Unmarshal(_ *sarama.ConsumerMessage) (*message.Message, error) { return nil, nil }

// interface definition for broken watermill kafka.Publisher being exposed as a struct instead of interface
// used just to generate mocks
//nolint
type KafkaPublisher interface {
	Publish(topic string, msgs ...*message.Message) error
	Close() error
}

// interface definition for broken watemill kafka.Subscriber being exposed as a struct instead of interface
// used just to generate mocks
//nolint
type KafkaSubscriber interface {
	Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error)
	Close() error
}

var _ = g.Describe("keyGenerator", func() {
	g.Context("with bad topic and any message", func() {
		topic := "bad topic"
		message := message.Message{}

		g.It("should fail", func() {
			key, err := keyGenerator(topic, &message)

			Expect(err).To(HaveOccurred())
			Expect(key).To(BeEmpty())
		})
	})

	g.Context("with notifications topic and any message", func() {
		topic := notificationsTopicPrefix
		message := message.Message{}

		g.It("should return new uid without an error", func() {

			key, err := keyGenerator(topic, &message)

			Expect(err).NotTo(HaveOccurred())
			Expect(key).NotTo(BeEmpty())

			var id uuid.UUID
			id, err = uuid.Parse(key)

			Expect(err).NotTo(HaveOccurred())
			Expect(id.String()).NotTo(BeEmpty())
		})
	})

	g.Context("with services topic", func() {
		topic := servicesTopic

		g.Context("and empty message", func() {
			g.It("should fail with an error", func() {
				message := message.Message{}

				key, err := keyGenerator(topic, &message)

				Expect(err).To(HaveOccurred())
				Expect(key).To(BeEmpty())
			})
		})

		g.Context("and malformed payload", func() {
			g.It("should fail with empty key and an error", func() {
				message := message.Message{
					Payload: []byte{1, 2, 3, 4, 5, 6, 7, 0, 0, 4},
				}

				key, err := keyGenerator(topic, &message)

				Expect(err).To(HaveOccurred())
				Expect(key).To(BeEmpty())
			})
		})

		g.Context("and nil URN", func() {
			g.It("should fail with empty key and an error", func() {
				m := ServiceMessage{
					Svc: &Service{
						URN: nil,
					},
				}

				message := message.Message{}
				message.Payload, _ = json.Marshal(m)
				key, err := keyGenerator(topic, &message)

				Expect(err).To(HaveOccurred())
				Expect(key).To(BeEmpty())
			})
		})

		g.Context("and a good message", func() {
			g.It("should not fail with an error", func() {
				m := ServiceMessage{
					Svc: &Service{
						URN: &URN{
							ID:        "someid",
							Namespace: "somenamespace",
						},
					},
				}

				message := message.Message{}
				message.Payload, _ = json.Marshal(m)

				key, err := keyGenerator(topic, &message)

				Expect(err).NotTo(HaveOccurred())
				Expect(key).NotTo(BeEmpty())
			})
		})

		g.Context("with client topic", func() {
			topic := clientTopicPrefix

			// TODO: discuss this
			// g.Context("with nil message", func() {
			// 	g.It("should fail with error and empty key", func() {

			// 		key, err := keyGenerator(topic, nil)

			// 		Expect(err).To(HaveOccurred())
			// 		Expect(key).To(BeEmpty())
			// 	})
			// })

			g.Context("with empty message", func() {
				g.It("should fail with error and empty key", func() {

					key, err := keyGenerator(topic, &message.Message{})

					Expect(err).To(HaveOccurred())
					Expect(key).To(BeEmpty())
				})
			})

			g.Context("with malformed payload", func() {
				g.It("should fail with error and empty key", func() {

					key, err := keyGenerator(topic, &message.Message{Payload: []byte{1, 0, 44, 12, 3}})

					Expect(err).To(HaveOccurred())
					Expect(key).To(BeEmpty())
				})
			})

			g.Context("with unsubscribe all and scope all", func() {
				g.It("should return empty key and no error", func() {

					m := SubscriptionMessage{
						Action: subscriptionActionUnsubscribe,
						Scope:  subscriptionScopeAll,
					}

					message := message.Message{}
					message.Payload, _ = json.Marshal(m)

					key, err := keyGenerator(topic, &message)

					Expect(err).NotTo(HaveOccurred())
					Expect(key).To(BeEmpty())
				})
			})

			g.Context("without URN", func() {
				g.It("should return empty key and error", func() {

					m := SubscriptionMessage{
						Subscription: &Subscription{
							URN: nil,
						},
					}

					message := message.Message{}
					message.Payload, _ = json.Marshal(m)

					key, err := keyGenerator(topic, &message)

					Expect(err).To(HaveOccurred())
					Expect(key).To(BeEmpty())
				})
			})

			g.Context("with URN defied", func() {
				g.It("should return key as URN.string and no error", func() {

					m := SubscriptionMessage{
						Subscription: &Subscription{
							URN: &URN{
								ID:        "an id",
								Namespace: "an namespace",
							},
						},
					}

					message := message.Message{}
					message.Payload, _ = json.Marshal(m)

					key, err := keyGenerator(topic, &message)

					Expect(err).NotTo(HaveOccurred())
					Expect(key).NotTo(BeEmpty())
				})
			})
		})
	})
})

var patches []*Patch

func patchInstanceMethod(o interface{}, n string, f interface{}) *Patch {
	t := reflect.TypeOf(o)
	p, e := PatchInstanceMethodByName(t, n, f)

	Expect(e).NotTo(HaveOccurred())

	patches = append(patches, p)

	return p
}

func patchMethod(t, r interface{}) *Patch {
	p, e := PatchMethodByReflectValue(reflect.ValueOf(t), r)

	Expect(e).NotTo(HaveOccurred())

	patches = append(patches, p)

	return p
}

func unpatchAll() {
	for _, p := range patches {
		p.Unpatch()
	}

	patches = []*Patch{}
}

var _ = g.Describe("Kafka Message Broker", func() {

	var (
		mockCtrl            *gomock.Controller
		mockKafka           *mockEAA.MockKafkaInterface
		mockKafkaPublisher  *mockEAA.MockKafkaPublisher
		mockKafkaSubscriber *mockEAA.MockKafkaSubscriber
		eaaCtx              Context
		kafkaBroker         *KafkaMsgBroker
		dspcFirstCall       *gomock.Call
		npmFirstCall        *gomock.Call
	)

	topic := "sample topic"
	subscriber := &kafka.Subscriber{}
	publisher := &kafka.Publisher{}

	g.BeforeEach(func() {
		mockCtrl = gomock.NewController(g.GinkgoT())
		mockKafka = mockEAA.NewMockKafkaInterface(mockCtrl)
		mockKafkaPublisher = mockEAA.NewMockKafkaPublisher(mockCtrl)
		mockKafkaSubscriber = mockEAA.NewMockKafkaSubscriber(mockCtrl)

		KafkaBroker = mockKafka

		dspcFirstCall = mockKafka.EXPECT().DefaultSaramaSyncPublisherConfig().
			Return(kafka.DefaultSaramaSyncPublisherConfig())
		npmFirstCall = mockKafka.EXPECT().NewWithPartitioningMarshaler(gomock.Any()).
			Return(kafka.DefaultMarshaler{})

		mockKafka.EXPECT().NewPublisher(gomock.Any(), gomock.Any()).Return(publisher, nil)

		patchInstanceMethod(publisher, "Publish",
			func(a *kafka.Publisher, topic string, msgs ...*message.Message) error {
				return mockKafkaPublisher.Publish(topic, msgs...)
			})

		patchInstanceMethod(publisher, "Close", func(s *kafka.Publisher) error {
			return mockKafkaPublisher.Close()
		})

		patchInstanceMethod(subscriber, "Subscribe",
			func(s *kafka.Subscriber, ctx context.Context, topic string) (<-chan *message.Message, error) {
				return mockKafkaSubscriber.Subscribe(ctx, topic)
			})

		patchInstanceMethod(subscriber, "Close", func(s *kafka.Subscriber) error {
			return mockKafkaSubscriber.Close()
		})

		var e error
		kafkaBroker, e = NewKafkaMsgBroker(&eaaCtx, "eaa_test_consumer", nil)

		Expect(e).NotTo(HaveOccurred())
	})

	g.AfterEach(func() {
		// clear patches first to do that before checking mocks
		unpatchAll()

		mockCtrl.Finish()

	})

	g.Describe("testbed check", func() {
		g.It("should pass", func() {
			Expect(true).To(BeTrue())
		})
	})

	g.Describe("addPublisher", func() {
		g.It("should work fine and do not return any error", func() {
			publishersCount := len(kafkaBroker.pubs.m)

			err := kafkaBroker.addPublisher(notificationPublisher, topic, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(kafkaBroker.pubs.m)).To(BeEquivalentTo(publishersCount + 1))

		})

		g.It("should fail with error when the called twice for the same topic aka one publisher per topic", func() {
			err := kafkaBroker.addPublisher(notificationPublisher, topic, nil)
			Expect(err).NotTo(HaveOccurred())

			err = kafkaBroker.addPublisher(notificationPublisher, topic, nil)
			Expect(err).To(HaveOccurred())
		})

		g.It("should fail with error when kafka fails to create publisher", func() {
			mockKafka.EXPECT().DefaultSaramaSyncPublisherConfig().
				Return(kafka.DefaultSaramaSyncPublisherConfig()).After(dspcFirstCall)

			mockKafka.EXPECT().NewPublisher(gomock.Any(), gomock.Any()).
				Return(nil, errors.New("unit test error")).After(dspcFirstCall)

			mockKafka.EXPECT().NewWithPartitioningMarshaler(gomock.Any()).
				Return(kafka.DefaultMarshaler{}).After(npmFirstCall)

			kafkaBroker.defaultPublisher = nil

			err := kafkaBroker.addPublisher(notificationPublisher, topic, nil)
			Expect(err).To(HaveOccurred())
		})

		//TODO: does this recreation code has any sense?
		g.It("should recreate publisher when it is nil", func() {
			mockKafka.EXPECT().DefaultSaramaSyncPublisherConfig().
				Return(kafka.DefaultSaramaSyncPublisherConfig()).After(dspcFirstCall)

			mockKafka.EXPECT().NewPublisher(gomock.Any(), gomock.Any()).Return(publisher, nil)

			mockKafka.EXPECT().NewWithPartitioningMarshaler(gomock.Any()).
				Return(kafka.DefaultMarshaler{}).After(npmFirstCall)

			kafkaBroker.defaultPublisher = nil

			err := kafkaBroker.addPublisher(notificationPublisher, topic, nil)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	g.Describe("publish", func() {
		g.BeforeEach(func() {
			kafkaBroker.addPublisher(servicesPublisher, topic, nil)
		})

		g.It("should publish a message when everything is fine", func() {

			m := message.Message{}

			mockKafkaPublisher.EXPECT().Publish(topic, &m).Return(nil)
			e := kafkaBroker.publish(topic, &m)

			Expect(e).NotTo(HaveOccurred())
		})

		g.It("should fail with an error when publishing on an unknown topic", func() {

			m := message.Message{}

			e := kafkaBroker.publish("unknown topic", &m)

			Expect(e).To(HaveOccurred())
		})

		g.It("should fail with an error when kafka publisherreports error", func() {

			m := message.Message{}

			mockKafkaPublisher.EXPECT().Publish(topic, &m).Return(errors.New("test error"))
			e := kafkaBroker.publish(topic, &m)

			Expect(e).To(HaveOccurred())
		})
	})

	g.Describe("createSubscriber", func() {
		config := kafka.DefaultSaramaSubscriberConfig()

		g.It("should return new subscriber without an error when everything is fine", func() {

			subscriberConfig := kafka.SubscriberConfig{}

			mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Do(
				func(config kafka.SubscriberConfig, _ watermill.LoggerAdapter) { subscriberConfig = config }).
				Return(subscriber, nil)

			s, e := kafkaBroker.createSubscriber(config)

			Expect(s).NotTo(BeNil())
			Expect(s).To(Equal(subscriber))
			Expect(e).NotTo(HaveOccurred())
			Expect(subscriberConfig.OverwriteSaramaConfig).To(Equal(config))
		})

		g.It("should report an error when kafka.NewSubscriber fails", func() {

			mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(nil, errors.New("test error"))

			s, e := kafkaBroker.createSubscriber(config)

			Expect(s).To(BeNil())
			Expect(e).To(HaveOccurred())
		})
	})

	g.Describe("createNotificationSubscriber", func() {
		g.It("should create notification subscriber and call handleNotificationUpdates when everything is fine",
			func() {
				sync := make(chan bool)
				patchMethod(handleNotificationUpdates, func(_ <-chan *message.Message, _ *Context) {
					sync <- true
					close(sync)
				})

				mc := make(chan *message.Message)

				mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(subscriber, nil)
				mockKafkaSubscriber.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Return(mc, nil)
				mockKafka.EXPECT().DefaultSaramaSubscriberConfig().Return(kafka.DefaultSaramaSubscriberConfig())

				s, e := kafkaBroker.createNotificationSubscriber(topic)
				close(mc)

				Expect(s).NotTo(BeNil())
				Expect(s).To(Equal(subscriber))
				Expect(e).NotTo(HaveOccurred())

				var called bool

				select {
				case called = <-sync:
				case <-time.After(5 * time.Second):
				}

				Expect(called).To(BeTrue())
			})

		g.It("should report an error when creating subscriber fails for some reason", func() {
			mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(nil, errors.New("test error"))
			mockKafka.EXPECT().DefaultSaramaSubscriberConfig().Return(kafka.DefaultSaramaSubscriberConfig())

			s, e := kafkaBroker.createNotificationSubscriber(topic)

			Expect(s).To(BeNil())
			Expect(e).To(HaveOccurred())
		})

		g.It("should report an error when subscribe fails for some reason", func() {
			mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(subscriber, nil)
			mockKafka.EXPECT().DefaultSaramaSubscriberConfig().Return(kafka.DefaultSaramaSubscriberConfig())
			mockKafkaSubscriber.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Return(nil, errors.New("test error"))

			s, e := kafkaBroker.createNotificationSubscriber(topic)

			Expect(s).To(BeNil())
			Expect(e).To(HaveOccurred())
		})
	})

	g.Describe("createServicesSubscriber", func() {
		g.BeforeEach(func() {
			mockKafka.EXPECT().DefaultSaramaSubscriberConfig().Return(kafka.DefaultSaramaSubscriberConfig())
		})

		g.It("should create service subscriber and call handleServiceUpdates when everything is fine", func() {

			sync := make(chan bool)
			patchMethod(handleServiceUpdates, func(_ <-chan *message.Message, _ *Context) {
				sync <- true
				close(sync)
			})

			mc := make(chan *message.Message)

			mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(subscriber, nil)
			mockKafkaSubscriber.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Return(mc, nil)

			s, e := kafkaBroker.createServicesSubscriber()
			close(mc)

			Expect(s).NotTo(BeNil())
			Expect(s).To(Equal(subscriber))
			Expect(e).NotTo(HaveOccurred())

			var called bool

			select {
			case called = <-sync:
			case <-time.After(5 * time.Second):
			}

			Expect(called).To(BeTrue())
		})

		g.It("should report an error when creating subscriber fails for some reason", func() {
			mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(nil, errors.New("test error"))

			s, e := kafkaBroker.createServicesSubscriber()

			Expect(s).To(BeNil())
			Expect(e).To(HaveOccurred())
		})

		g.It("should report an error when subscribe fails for some reason", func() {
			mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(subscriber, nil)
			mockKafkaSubscriber.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Return(nil, errors.New("test error"))

			s, e := kafkaBroker.createServicesSubscriber()

			Expect(s).To(BeNil())
			Expect(e).To(HaveOccurred())
		})
	})

	g.Describe("createClientSubscriber", func() {
		g.BeforeEach(func() {
			mockKafka.EXPECT().DefaultSaramaSubscriberConfig().Return(kafka.DefaultSaramaSubscriberConfig())
		})

		g.It("should create client subscriber and call handleServiceUpdates when everything is fine", func() {

			sync := make(chan bool)

			patchMethod(handleClientUpdates, func(_ <-chan *message.Message, _ *Context) {
				sync <- true
				close(sync)
			})

			mc := make(chan *message.Message)

			mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(subscriber, nil)
			mockKafkaSubscriber.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Return(mc, nil)

			s, e := kafkaBroker.createClientSubscriber(topic)
			close(mc)

			Expect(s).NotTo(BeNil())
			Expect(s).To(Equal(subscriber))
			Expect(e).NotTo(HaveOccurred())

			var called bool

			select {
			case called = <-sync:
			case <-time.After(5 * time.Second):
			}

			Expect(called).To(BeTrue())
		})

		g.It("should report an error when creating subscriber fails for some reason", func() {
			mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(nil, errors.New("test error"))

			s, e := kafkaBroker.createClientSubscriber(topic)

			Expect(s).To(BeNil())
			Expect(e).To(HaveOccurred())
		})

		g.It("should report an error when subscribe fails for some reason", func() {
			mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(subscriber, nil)
			mockKafkaSubscriber.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Return(nil, errors.New("test error"))

			s, e := kafkaBroker.createClientSubscriber(topic)

			Expect(s).To(BeNil())
			Expect(e).To(HaveOccurred())
		})
	})

	g.Describe("addSubscriber", func() {
		var dsscFirstCall *gomock.Call
		g.BeforeEach(func() {
			dsscFirstCall = mockKafka.EXPECT().DefaultSaramaSubscriberConfig().
				Return(kafka.DefaultSaramaSubscriberConfig())
		})

		g.It("should create and remember notification subscriber and call handleNotificationUpdates",
			func() {

				sync := make(chan bool)
				patchMethod(handleNotificationUpdates, func(_ <-chan *message.Message, _ *Context) {
					sync <- true
					close(sync)
				})

				subscribersCount := len(kafkaBroker.subs.m)

				mc := make(chan *message.Message)

				mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(subscriber, nil)
				mockKafkaSubscriber.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Return(mc, nil)

				e := kafkaBroker.addSubscriber(notificationSubscriber, topic, nil)

				close(mc)

				Expect(e).NotTo(HaveOccurred())
				Expect(len(kafkaBroker.subs.m)).To(BeEquivalentTo(subscribersCount + 1))

				var called bool

				select {
				case called = <-sync:
				case <-time.After(5 * time.Second):
				}

				Expect(called).To(BeTrue())
			})

		g.It("should create and remember service subscriber and call handleServiceUpdates when everything is fine",
			func() {

				sync := make(chan bool)
				patchMethod(handleServiceUpdates, func(_ <-chan *message.Message, _ *Context) {
					sync <- true
					close(sync)
				})

				subscribersCount := len(kafkaBroker.subs.m)

				mc := make(chan *message.Message)

				mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(subscriber, nil)
				mockKafkaSubscriber.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Return(mc, nil)

				e := kafkaBroker.addSubscriber(servicesSubscriber, topic, nil)

				close(mc)

				Expect(e).NotTo(HaveOccurred())
				Expect(len(kafkaBroker.subs.m)).To(BeEquivalentTo(subscribersCount + 1))

				var called bool

				select {
				case called = <-sync:
				case <-time.After(5 * time.Second):
				}

				Expect(called).To(BeTrue())
			})

		g.It("should create and remember client subscriber and call handleClientUpdates when everything is fine",
			func() {

				sync := make(chan bool)
				patchMethod(handleClientUpdates, func(_ <-chan *message.Message, _ *Context) {
					sync <- true
					close(sync)
				})

				subscribersCount := len(kafkaBroker.subs.m)

				mc := make(chan *message.Message)

				mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(subscriber, nil)
				mockKafkaSubscriber.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Return(mc, nil)

				e := kafkaBroker.addSubscriber(clientSubscriber, topic, nil)

				close(mc)

				Expect(e).NotTo(HaveOccurred())
				Expect(len(kafkaBroker.subs.m)).To(BeEquivalentTo(subscribersCount + 1))

				var called bool

				select {
				case called = <-sync:
				case <-time.After(5 * time.Second):
				}

				Expect(called).To(BeTrue())
			})

		g.It("should fail when subscribing for the same topic twice ", func() {

			sync := make(chan bool)
			patchMethod(handleClientUpdates, func(_ <-chan *message.Message, _ *Context) {
				sync <- true
				close(sync)
			})

			subscribersCount := len(kafkaBroker.subs.m)

			mc := make(chan *message.Message)

			mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(subscriber, nil)
			mockKafkaSubscriber.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Return(mc, nil)

			e := kafkaBroker.addSubscriber(clientSubscriber, topic, nil)

			close(mc)

			Expect(e).NotTo(HaveOccurred())
			Expect(len(kafkaBroker.subs.m)).To(BeEquivalentTo(subscribersCount + 1))

			var called bool

			select {
			case called = <-sync:
			case <-time.After(5 * time.Second):
			}

			Expect(called).To(BeTrue())

			e = kafkaBroker.addSubscriber(clientSubscriber, topic, nil)
			Expect(e).To(HaveOccurred())
		})

		g.It("should report an error when creating subscriber fails for some reason", func() {
			mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(nil, errors.New("test error"))

			subscribersCount := len(kafkaBroker.subs.m)

			e := kafkaBroker.addSubscriber(clientSubscriber, topic, nil)

			Expect(e).To(HaveOccurred())
			Expect(len(kafkaBroker.subs.m)).To(BeEquivalentTo(subscribersCount))
		})

		g.It("should report an error when subscribe fails for some reason", func() {
			mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(subscriber, nil)
			mockKafkaSubscriber.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Return(nil, errors.New("test error"))

			subscribersCount := len(kafkaBroker.subs.m)

			e := kafkaBroker.addSubscriber(clientSubscriber, topic, nil)

			Expect(e).To(HaveOccurred())
			Expect(len(kafkaBroker.subs.m)).To(BeEquivalentTo(subscribersCount))
		})

		g.It("should report an error when subsciber type is not supported", func() {
			dsscFirstCall.AnyTimes()

			e := kafkaBroker.addSubscriber(clientSubscriber+1000, topic, nil)

			Expect(e).To(HaveOccurred())
		})
	})

	g.Describe("removeAll", func() {
		var dsscFirstCall *gomock.Call

		g.BeforeEach(func() {
			dsscFirstCall = mockKafka.EXPECT().DefaultSaramaSubscriberConfig().
				Return(kafka.DefaultSaramaSubscriberConfig())
		})

		g.It("remove all scubscriptions when everything is fine", func() {
			sync := make(chan bool)
			patchMethod(handleClientUpdates, func(_ <-chan *message.Message, _ *Context) {
				sync <- true
				close(sync)
			})

			subscribersCount := len(kafkaBroker.subs.m)

			mc := make(chan *message.Message)

			mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(subscriber, nil)
			mockKafkaSubscriber.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Return(mc, nil)

			e := kafkaBroker.addSubscriber(clientSubscriber, topic, nil)

			close(mc)

			Expect(e).NotTo(HaveOccurred())
			Expect(len(kafkaBroker.subs.m)).To(BeEquivalentTo(subscribersCount + 1))

			var called bool

			select {
			case called = <-sync:
			case <-time.After(5 * time.Second):
			}

			Expect(called).To(BeTrue())

			e = kafkaBroker.addPublisher(notificationPublisher, topic, nil)
			Expect(e).NotTo(HaveOccurred())

			mockKafkaSubscriber.EXPECT().Close().Return(nil)
			mockKafkaPublisher.EXPECT().Close().Return(nil)

			e = kafkaBroker.removeAll()

			Expect(len(kafkaBroker.subs.m)).To(BeEquivalentTo(0))
			Expect(len(kafkaBroker.pubs.m)).To(BeEquivalentTo(0))
			Expect(e).NotTo(HaveOccurred())
		})

		g.It("return error and remove all scubscriptions when at leat one subscriber reports error when closing",
			func() {
				sync := make(chan bool)
				patchMethod(handleClientUpdates, func(_ <-chan *message.Message, _ *Context) {
					sync <- true
					close(sync)
				})

				subscribersCount := len(kafkaBroker.subs.m)

				mc := make(chan *message.Message)

				mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(subscriber, nil)
				mockKafkaSubscriber.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Return(mc, nil)

				e := kafkaBroker.addSubscriber(clientSubscriber, topic, nil)

				close(mc)

				Expect(e).NotTo(HaveOccurred())
				Expect(len(kafkaBroker.subs.m)).To(BeEquivalentTo(subscribersCount + 1))

				var called bool

				select {
				case called = <-sync:
				case <-time.After(5 * time.Second):
				}

				Expect(called).To(BeTrue())

				e = kafkaBroker.addPublisher(notificationPublisher, topic, nil)
				Expect(e).NotTo(HaveOccurred())

				mockKafkaSubscriber.EXPECT().Close().Return(errors.New("unit test error"))
				mockKafkaPublisher.EXPECT().Close().Return(nil)

				e = kafkaBroker.removeAll()

				Expect(len(kafkaBroker.subs.m)).To(BeEquivalentTo(0))
				Expect(len(kafkaBroker.pubs.m)).To(BeEquivalentTo(0))
				Expect(e).To(HaveOccurred())
			})

		g.It("return error and remove all scubscriptions when at leat one publisher reports error when closing",
			func() {
				sync := make(chan bool)
				patchMethod(handleClientUpdates, func(_ <-chan *message.Message, _ *Context) {
					sync <- true
					close(sync)
				})

				subscribersCount := len(kafkaBroker.subs.m)

				mc := make(chan *message.Message)

				mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(subscriber, nil)
				mockKafkaSubscriber.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Return(mc, nil)

				e := kafkaBroker.addSubscriber(clientSubscriber, topic, nil)

				close(mc)

				Expect(e).NotTo(HaveOccurred())
				Expect(len(kafkaBroker.subs.m)).To(BeEquivalentTo(subscribersCount + 1))

				var called bool

				select {
				case called = <-sync:
				case <-time.After(5 * time.Second):
				}

				Expect(called).To(BeTrue())

				e = kafkaBroker.addPublisher(notificationPublisher, topic, nil)
				Expect(e).NotTo(HaveOccurred())

				mockKafkaSubscriber.EXPECT().Close().Return(nil)
				mockKafkaPublisher.EXPECT().Close().Return(errors.New("unit test error"))

				e = kafkaBroker.removeAll()

				Expect(len(kafkaBroker.subs.m)).To(BeEquivalentTo(0))
				Expect(len(kafkaBroker.pubs.m)).To(BeEquivalentTo(0))
				Expect(e).To(HaveOccurred())
			})

		g.It("return error when at leat one subscriber is nil, dead code", func() {
			dsscFirstCall.Times(0)
			mockKafkaPublisher.EXPECT().Close().Return(nil)

			kafkaBroker.subs.m[topic] = nil

			e := kafkaBroker.removeAll()

			Expect(len(kafkaBroker.subs.m)).To(BeEquivalentTo(0))
			Expect(len(kafkaBroker.pubs.m)).To(BeEquivalentTo(0))
			Expect(e).To(HaveOccurred())
		})
	})

	g.Describe("Kafka proxy", func() {

		k := kafkaImplementation{}

		g.When("kafkaImplementation is used as a proxy to kafka", func() {
			g.When("there is a call to DefaultSaramaSubscriberConfig", func() {
				g.It("should call original kafka implementation", func() {
					c := &sarama.Config{}

					patchMethod(kafka.DefaultSaramaSubscriberConfig, func() *sarama.Config { return c })

					check := k.DefaultSaramaSubscriberConfig()

					Expect(c == check).To(BeTrue())
				})
			})

			g.When("there is a call to DefaultSaramaSyncPublisherConfig", func() {
				g.It("should call original kafka implementation", func() {
					c := &sarama.Config{}

					patchMethod(kafka.DefaultSaramaSyncPublisherConfig, func() *sarama.Config {
						return c
					})

					check := k.DefaultSaramaSyncPublisherConfig()

					Expect(c == check).To(BeTrue())
				})
			})

			g.When("there is a call to NewPublisher", func() {
				g.It("should call original kafka implementation", func() {
					p := &kafka.Publisher{}

					patchMethod(kafka.NewPublisher,
						func(_ kafka.PublisherConfig, _ watermill.LoggerAdapter) (*kafka.Publisher, error) {
							return p, nil
						})

					check, e := k.NewPublisher(kafka.PublisherConfig{}, nil)

					Expect(e).NotTo(HaveOccurred())
					Expect(p == check).To(BeTrue())
				})
			})

			g.When("there is a call to NewWithPartitioningMarshaler", func() {
				g.It("should call original kafka implementation", func() {
					tm := TestMarshaler{}

					patchMethod(kafka.NewWithPartitioningMarshaler,
						func(_ kafka.GeneratePartitionKey) kafka.MarshalerUnmarshaler {
							return tm
						})

					check := k.NewWithPartitioningMarshaler(
						func(_ string, _ *message.Message) (string, error) { return "", nil })

					km, ok := check.(TestMarshaler)

					Expect(ok).To(BeTrue())
					Expect(km).NotTo(BeNil())
				})
			})

			g.When("there is a call to NewSubscriber", func() {
				g.It("should call original kafka implementation", func() {
					s := &kafka.Subscriber{}

					patchMethod(kafka.NewSubscriber,
						func(_ kafka.SubscriberConfig, _ watermill.LoggerAdapter) (*kafka.Subscriber, error) {
							return s, nil
						})

					check, e := k.NewSubscriber(kafka.SubscriberConfig{}, nil)

					Expect(e).NotTo(HaveOccurred())
					Expect(s == check).To(BeTrue())
				})
			})
		})
	})
})
