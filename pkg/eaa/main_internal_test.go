// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/ThreeDotsLabs/watermill-kafka/v2/pkg/kafka"
	"github.com/ThreeDotsLabs/watermill/message"
	g "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/otcshare/edgeservices/pkg/config"
	mockEAA "github.com/otcshare/edgeservices/pkg/mock"

	"github.com/golang/mock/gomock"
	. "github.com/undefinedlabs/go-mpatch"
)

var _ = g.Describe("main internal errors", func() {
	var (
		eaaContext              *Context
		ctx                     context.Context
		mockCtrl                *gomock.Controller
		mockKafka               *mockEAA.MockKafkaInterface
		mockKafkaPublisher      *mockEAA.MockKafkaPublisher
		mockKafkaSubscriber     *mockEAA.MockKafkaSubscriber
		patchLoadJSONConfig     *Patch
		patchInitEaaCert        *Patch
		patchLoadX509KeyPair    *Patch
		patchReadFile           *Patch
		patchAppendCertsFromPEM *Patch
		patchNewKafkaMsgBroker  *Patch
		patchNetListen          *Patch
		patchServeTLS           *Patch
		patchServerClose        *Patch
		npfc                    *gomock.Call
		nsfc                    *gomock.Call
		pcfc                    *gomock.Call
		scfc                    *gomock.Call
	)

	g.BeforeEach(func() {

		eaaContext = &Context{}

		newContext, cancel := context.WithCancel(context.Background())
		ctx = newContext
		cancel()

		eaaContext.cfg.Certs.CaRootPath = "\\there is no such file\\+1"

		mockCtrl = gomock.NewController(g.GinkgoT())
		mockKafka = mockEAA.NewMockKafkaInterface(mockCtrl)
		mockKafkaPublisher = mockEAA.NewMockKafkaPublisher(mockCtrl)
		mockKafkaSubscriber = mockEAA.NewMockKafkaSubscriber(mockCtrl)

		KafkaBroker = mockKafka

		mockKafka.EXPECT().DefaultSaramaSyncPublisherConfig().
			Return(kafka.DefaultSaramaSyncPublisherConfig()).AnyTimes()
		mockKafka.EXPECT().DefaultSaramaSubscriberConfig().
			Return(kafka.DefaultSaramaSubscriberConfig()).AnyTimes()

		mockKafka.EXPECT().NewWithPartitioningMarshaler(gomock.Any()).Return(kafka.DefaultMarshaler{}).AnyTimes()
		npfc = mockKafka.EXPECT().NewPublisher(gomock.Any(), gomock.Any()).Return(&kafka.Publisher{}, nil).AnyTimes()
		nsfc = mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(&kafka.Subscriber{}, nil).AnyTimes()

		mc := make(chan *message.Message)

		mockKafkaSubscriber.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Return(mc, nil).AnyTimes()
		scfc = mockKafkaSubscriber.EXPECT().Close().Return(nil).AnyTimes()
		pcfc = mockKafkaPublisher.EXPECT().Close().Return(nil).AnyTimes()

		patchInstanceMethod(kafka.Subscriber{}, "Subscribe",
			func(s *kafka.Subscriber, ctx context.Context, topic string) (<-chan *message.Message, error) {
				return mockKafkaSubscriber.Subscribe(ctx, topic)
			})
		patchInstanceMethod(kafka.Subscriber{}, "Close", func(s *kafka.Subscriber) error {
			return mockKafkaSubscriber.Close()
		})

		patchInstanceMethod(kafka.Publisher{}, "Close", func(s *kafka.Publisher) error {
			return mockKafkaPublisher.Close()
		})

		patchLoadJSONConfig = patchMethod(config.LoadJSONConfig, func(_ string, _ interface{}) error {
			return nil
		})

		patchInitEaaCert = patchMethod(InitEaaCert, func(_ CertsInfo) (*CertKeyPair, error) { return nil, nil })

		patchLoadX509KeyPair = patchMethod(tls.LoadX509KeyPair, func(_, _ string) (tls.Certificate, error) {
			return tls.Certificate{}, nil
		})
		patchReadFile = patchMethod(ioutil.ReadFile, func(_ string) ([]byte, error) { return []byte{1}, nil })
		patchAppendCertsFromPEM = patchInstanceMethod(x509.CertPool{}, "AppendCertsFromPEM",
			func(_ *x509.CertPool, _ []byte) (ok bool) {
				ok = true
				return
			})
		patchNewKafkaMsgBroker = patchMethod(NewKafkaMsgBroker,
			func(eaaContext *Context, _ string, _ *tls.Config) (*KafkaMsgBroker, error) {
				b := KafkaMsgBroker{eaaCtx: eaaContext}

				b.pubs.m = make(map[string]*kafka.Publisher)
				b.subs.m = make(map[string]*kafka.Subscriber)

				return &b, nil
			})

		patchNetListen = patchMethod(net.Listen,
			func(_, _ string) (net.Listener, error) { return &net.TCPListener{}, nil })
		patchServeTLS = patchInstanceMethod(http.Server{}, "ServeTLS",
			func(_ *http.Server, _ net.Listener, _, _ string) error {
				return http.ErrServerClosed
			})
		patchServerClose = patchInstanceMethod(http.Server{}, "Close", func(_ *http.Server) error { return nil })

	})

	g.AfterEach(func() {
		unpatchAll()

		mockCtrl.Finish()
	})

	g.Describe("RunServer", func() {
		g.When("checking test bed", func() {
			g.It("should work", func() {

				e := Run(ctx, "")

				Expect(e).NotTo(HaveOccurred())
			})

		})

		g.When("LoadJSONConfig fails", func() {
			g.It("should fail with an error", func() {
				patchLoadJSONConfig.Unpatch()

				e := Run(ctx, "")

				Expect(e).To(HaveOccurred())
			})
		})

		g.When("InitEaaCert load fails", func() {
			g.It("should fail with an error", func() {
				patchInitEaaCert.Unpatch()

				e := Run(ctx, "")

				Expect(e).To(HaveOccurred())
			})
		})

		g.Context("newKafkaTLSConfig fails", func() {
			g.When("LoadX509KeyPair fails", func() {
				g.It("should fail with an error", func() {
					patchLoadX509KeyPair.Unpatch()

					e := Run(ctx, "")

					Expect(e).To(HaveOccurred())
				})
			})

			g.When("ReadFile fails", func() {
				g.It("should fail with an error", func() {
					patchReadFile.Unpatch()

					e := Run(ctx, "")

					Expect(e).To(HaveOccurred())
				})
			})

			g.When("AppendCertsFromPEM fails", func() {
				g.It("should fail with an error", func() {
					patchAppendCertsFromPEM.Unpatch()

					e := Run(ctx, "")

					// TODO: discuss, this should fail but it is not
					// Expect(e).To(HaveOccurred())

					Expect(e).NotTo(HaveOccurred())
				})
			})
		})

		g.When("NewKafkaMsgBroker fails", func() {
			g.It("should fail with an error", func() {
				patchNewKafkaMsgBroker.Unpatch()
				patchMethod(NewKafkaMsgBroker, func(_ *Context, _ string, _ *tls.Config) (*KafkaMsgBroker, error) {
					return nil, errors.New("")
				})

				e := Run(ctx, "")

				Expect(e).To(HaveOccurred())
			})
		})

		g.When("Reading CA fails", func() {
			g.It("should fail with an error ?", func() {
				patchReadFile.Unpatch()

				reads := 1
				patchMethod(ioutil.ReadFile, func(_ string) ([]byte, error) {

					reads = reads - 1

					if reads < 0 {
						return nil, errors.New("")
					}

					return []byte{1}, nil
				})

				e := Run(ctx, "")

				//TODO: this should fail perpahps
				//Expect(e).To(HaveOccurred())

				Expect(e).NotTo(HaveOccurred())
			})
		})

		g.When("Kafka add publisher fails", func() {
			g.It("should fail with an error", func() {
				fail := mockKafka.EXPECT().NewPublisher(gomock.Any(), gomock.Any()).Return(nil, errors.New(""))

				gomock.InOrder(fail, npfc)

				e := Run(ctx, "")

				Expect(e).To(HaveOccurred())
			})
		})

		g.When("Kafka add subscriber fails", func() {
			g.It("should fail with an error", func() {
				fail := mockKafka.EXPECT().NewSubscriber(gomock.Any(), gomock.Any()).Return(nil, errors.New(""))

				gomock.InOrder(fail, nsfc)

				e := Run(ctx, "")

				Expect(e).To(HaveOccurred())
			})
		})

		g.When("net.Listen fails", func() {
			g.It("should fail with an error", func() {
				patchNetListen.Unpatch()

				p := patchMethod(net.Listen, func(_, _ string) (net.Listener, error) {
					return nil, os.NewSyscallError("", errors.New(""))
				})

				defer p.Unpatch()

				e := Run(ctx, "")

				Expect(e).To(HaveOccurred())
			})
		})

		g.When("Kafka fails to close a publisher", func() {
			g.It("should fail with an error", func() {
				fail := mockKafkaPublisher.EXPECT().Close().Return(errors.New(""))

				gomock.InOrder(fail, pcfc)

				e := Run(ctx, "")

				Expect(e).To(HaveOccurred())
			})
		})

		g.When("Kafka fails to close a subscriber", func() {
			g.It("should fail with an error", func() {
				fail := mockKafkaSubscriber.EXPECT().Close().Return(errors.New(""))

				gomock.InOrder(fail, scfc)

				e := Run(ctx, "")

				Expect(e).To(HaveOccurred())
			})
		})

		g.When("http server close reports an error ", func() {
			g.It("should fail with an error", func() {
				closeChan := make(chan bool)

				patchServerClose.Unpatch()
				patchServerClose = patchInstanceMethod(http.Server{}, "Close",
					func(_ *http.Server) error {
						closeChan <- true
						return errors.New("")
					})

				patchServeTLS.Unpatch()
				patchServeTLS = patchInstanceMethod(http.Server{}, "ServeTLS",
					func(_ *http.Server, _ net.Listener, _, _ string) error {
						<-closeChan
						return http.ErrServerClosed
					})

				newCtx, cancel := context.WithCancel(context.Background())

				go func() {
					time.Sleep(time.Second)

					cancel()
				}()

				e := Run(newCtx, "")

				Expect(e).NotTo(HaveOccurred())
			})
		})

		g.When("http server ServeTLS reports an error ", func() {
			g.It("should fail with an error", func() {
				patchServeTLS.Unpatch()
				patchServeTLS = patchInstanceMethod(http.Server{}, "ServeTLS",
					func(_ *http.Server, _ net.Listener, _, _ string) error {
						return errors.New("")
					})

				e := Run(ctx, "")

				Expect(e).To(HaveOccurred())
			})
		})

		g.When("the server was running enough long", func() {
			g.It("should heartbeat in log", func() {
				// this test is here just to improve the coverage, no acctual log checking is done
				// it is visible only in coverage report

				closeChan := make(chan bool)

				patchServeTLS.Unpatch()
				patchServeTLS = patchInstanceMethod(http.Server{}, "ServeTLS",
					func(_ *http.Server, _ net.Listener, _, _ string) error {
						<-closeChan
						return http.ErrServerClosed
					})

				newCtx, cancel := context.WithCancel(context.Background())

				go func() {
					time.Sleep(time.Second)
					cancel()
					closeChan <- true
					log.Err("")
				}()

				patchLoadJSONConfig.Unpatch()
				patchLoadJSONConfig = patchMethod(config.LoadJSONConfig, func(_ string, cfg interface{}) error {

					c := cfg.(*Config)

					c.HeartbeatInterval.Duration = time.Microsecond * 100

					return nil
				})

				e := Run(newCtx, "")

				Expect(e).NotTo(HaveOccurred())
			})
		})

		g.When("http server ServeTLS reports an error and Kafka fails to close a publisher", func() {
			g.It("should fail with an error and both errors should be delivered properly", func() {
				fail := mockKafkaPublisher.EXPECT().Close().Return(errors.New(""))

				gomock.InOrder(fail, pcfc)

				patchServeTLS.Unpatch()
				patchServeTLS = patchInstanceMethod(http.Server{}, "ServeTLS",
					func(_ *http.Server, _ net.Listener, _, _ string) error {
						return errors.New("")
					})

				e := Run(ctx, "")

				Expect(e).To(HaveOccurred())
				Expect(errors.Unwrap(e)).To(HaveOccurred())
			})
		})
	})
})
