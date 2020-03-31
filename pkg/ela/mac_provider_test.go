// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package ela_test

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/open-ness/edgenode/pkg/ela"
)

var _ = Describe("MacProvider", func() {
	BeforeEach(func() {
	})

	AfterEach(func() {
	})

	Describe("Get MAC address", func() {
		When("Non-existent AppID is given", func() {
			It("Should return error", func() {
				setCtx, setCancel := context.WithTimeout(context.Background(),
					3*time.Second)
				defer setCancel()

				// HERE WE SHOULD HAVE A DUMMY DOCKER CONTAINER STARTED

				mfi := MACFetcherImpl{}
				_, err := mfi.GetMacAddress(setCtx, "dummy_app_id")
				fmt.Println(err)
				Expect(err).Should(HaveOccurred())
			})
		})
	})
})
