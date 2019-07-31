// Copyright 2019 Intel Corporation and Smart-Edge.com, Inc. All rights reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util_test

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/otcshare/edgenode/pkg/util"
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
