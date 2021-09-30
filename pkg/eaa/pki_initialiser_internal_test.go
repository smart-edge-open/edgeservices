// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa

import (
	"crypto"
	"crypto/x509"
	"reflect"
	"time"

	g "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/undefinedlabs/go-mpatch"

	"github.com/smart-edge-open/edgeservices/pkg/auth"
)

var _ = g.Describe("pki initialiser internal errors", func() {
	g.Describe("InitEaaCert", func() {
		var patch *Patch
		g.BeforeEach(func() {
			var e error
			patch, e = PatchMethodByReflectValue(reflect.ValueOf(auth.LoadKey),
				func(_ string) (crypto.PrivateKey, error) {
					return nil, nil
				})

			Expect(e).NotTo(HaveOccurred())
		})

		g.AfterEach(func() {
			patch.Unpatch()
		})

		g.When("loading server certificate fails", func() {
			g.It("should fail", func() {
				// p, e := PatchMethodByReflectValue(reflect.ValueOf(auth.))
				ci := CertsInfo{ServerCertPath: "bad path +-##$"}

				ckp, e := InitEaaCert(ci)

				Expect(e).To(HaveOccurred())
				Expect(ckp).To(BeNil())
			})
		})

		g.When("validating server certificate fails", func() {
			g.It("should fail", func() {
				p, e := PatchMethodByReflectValue(reflect.ValueOf(auth.LoadCert),
					func(_ string) (*x509.Certificate, error) {
						return &x509.Certificate{}, nil
					})

				Expect(e).NotTo(HaveOccurred())

				defer p.Unpatch()

				ckp, e := InitEaaCert(CertsInfo{})

				Expect(e).To(HaveOccurred())
				Expect(ckp).To(BeNil())
			})
		})
	})

	g.Describe("validateCert", func() {
		g.When("certificate from did not happen yet", func() {
			g.It("should return an error", func() {
				c := &x509.Certificate{NotBefore: time.Now().Add(1 * time.Minute)}

				e := validateCert(c)

				Expect(e).To(HaveOccurred())
			})
		})

		g.When("certificate to is already passed", func() {
			g.It("should return an error", func() {
				c := &x509.Certificate{NotAfter: time.Now().Add(-1 * time.Minute)}

				e := validateCert(c)

				Expect(e).To(HaveOccurred())
			})
		})
	})
})
