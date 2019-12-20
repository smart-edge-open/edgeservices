// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package util_test

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/open-ness/edgenode/pkg/util"
)

func TestUtil(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Util")
}

var _ = Describe("Duration", func() {
	Describe("MarshalJSON", func() {
		It("Should marshall the duration to JSON format",
			func() {
				t := util.Duration{time.Second * 5}
				ts, err := t.MarshalJSON()
				Expect(err).ToNot(HaveOccurred())
				Expect(string(ts)).To(BeEquivalentTo(`"5s"`))
			})
	})
	Describe("UnmarshalJSON", func() {
		It("Should unmarshall the duration from JSON format",
			func() {
				var t util.Duration
				err := t.UnmarshalJSON([]byte(`5s`))
				Expect(err).ToNot(HaveOccurred())
				Expect(t.Duration).To(BeEquivalentTo(time.Second * 5))
			})
	})

})

var _ = Describe("Heartbeat", func() {
	It("Should call the provided function and exit with provided context",
		func() {
			timeout := time.Millisecond * 5
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			i := 0
			util.Heartbeat(ctx, util.Duration{}, func() {
				i++
			})
			Expect(i).To(BeZero())

			util.Heartbeat(ctx, util.Duration{time.Millisecond}, func() {
				i++
			})

			time.Sleep(time.Millisecond * 10)
			Expect(i).ToNot(BeZero())
			time.Sleep(time.Millisecond)

			// make sure that the heartbeat stopped
			t := i
			time.Sleep(time.Millisecond * 2)
			Expect(i).To(BeEquivalentTo(t))
		})
})
