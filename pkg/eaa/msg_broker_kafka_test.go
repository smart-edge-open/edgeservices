// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa_test

import (
	"errors"

	"github.com/ThreeDotsLabs/watermill-kafka/v2/pkg/kafka"
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	eaa "github.com/otcshare/edgeservices/pkg/eaa"
	mockEAA "github.com/otcshare/edgeservices/pkg/mock"
)

var _ = Describe("Kafka Message Broker", func() {
	var (
		mockCtrl  *gomock.Controller
		mockKafka *mockEAA.MockKafkaInterface
		eaaCtx    eaa.Context
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		mockKafka = mockEAA.NewMockKafkaInterface(mockCtrl)

		eaa.KafkaBroker = mockKafka

		err := eaa.InitEaaContext(tempdir+"/configs/eaa.json", &eaaCtx)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		mockCtrl.Finish()
	})

	Describe("creation", func() {
		Context("with good configuration", func() {
			It("should be created seamlessly", func() {

				mockKafka.EXPECT().DefaultSaramaSyncPublisherConfig().Return(kafka.DefaultSaramaSyncPublisherConfig())
				mockKafka.EXPECT().NewWithPartitioningMarshaler(gomock.Any()).Return(kafka.DefaultMarshaler{})
				mockKafka.EXPECT().NewPublisher(gomock.Any(), gomock.Any()).Return(&kafka.Publisher{}, nil)

				broker, err := eaa.NewKafkaMsgBroker(&eaaCtx, "eaa_test_consumer", nil)

				Expect(err).NotTo(HaveOccurred())
				Expect(broker).ShouldNot(BeNil())
			})
		})

		Context("with bad configuration", func() {
			It("should return nil", func() {

				mockKafka.EXPECT().DefaultSaramaSyncPublisherConfig().Return(kafka.DefaultSaramaSyncPublisherConfig())
				mockKafka.EXPECT().NewWithPartitioningMarshaler(gomock.Any()).Return(nil)
				mockKafka.EXPECT().NewPublisher(gomock.Any(), gomock.Any()).AnyTimes().
					Return(nil, errors.New("Some test error occurred"))

				broker, err := eaa.NewKafkaMsgBroker(&eaaCtx, "eaa_test_consumer", nil)

				Expect(err).To(HaveOccurred())
				Expect(broker).Should(BeNil())
			})
		})
	})
})
