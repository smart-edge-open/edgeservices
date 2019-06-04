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

package eaa_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	mrand "math/rand"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/smartedgemec/appliance-ce/pkg/eaa"
)

// EaaCommonName Common Name that EAA uses for TLS connection
const EaaCommonName string = "eaa.community.appliance.mec"

// helper functions
func RequestCredentials(prvKey *ecdsa.PrivateKey) eaa.AuthCredentials {

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.org.com",
			Organization: []string{"TestOrg"},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		EmailAddresses:     []string{"test@test.org"},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template,
		prvKey)
	Expect(err).ShouldNot(HaveOccurred())

	m := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST",
		Bytes: csrBytes})

	var identity eaa.AuthIdentity
	identity.Csr = string(m)

	reqBody, err := json.Marshal(identity)
	Expect(err).ShouldNot(HaveOccurred())

	resp, err := http.Post("http://"+cfg.OpenEndpoint+"/auth", "",
		bytes.NewBuffer(reqBody))
	Expect(err).ShouldNot(HaveOccurred())

	var creds eaa.AuthCredentials
	err = json.NewDecoder(resp.Body).Decode(&creds)
	Expect(err).ShouldNot(HaveOccurred())

	return creds
}

func GetValidTLSClient(prvKey *ecdsa.PrivateKey) *http.Client {

	creds := RequestCredentials(prvKey)

	x509Encoded, err := x509.MarshalECPrivateKey(prvKey)
	Expect(err).ShouldNot(HaveOccurred())

	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY",
		Bytes: x509Encoded})

	cert, err := tls.X509KeyPair([]byte(creds.Certificate), pemEncoded)
	Expect(err).ShouldNot(HaveOccurred())

	certPool := x509.NewCertPool()
	for _, c := range creds.CaPool {
		ok := certPool.AppendCertsFromPEM([]byte(c))
		Expect(ok).To(BeTrue())
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: certPool,
				Certificates: []tls.Certificate{cert},
				ServerName:   EaaCommonName,
			},
		}}

	return client
}

func GenerateTLSCert(cTempl, cParent *x509.Certificate, pub,
	prv interface{}) tls.Certificate {

	sClientCertDER, err := x509.CreateCertificate(rand.Reader,
		cTempl, cParent, pub.(*ecdsa.PrivateKey).Public(), prv)
	Expect(err).ShouldNot(HaveOccurred())

	sClientCert, err := x509.ParseCertificate(sClientCertDER)
	Expect(err).ShouldNot(HaveOccurred())

	sClientCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: sClientCert.Raw,
	})
	derKey, err := x509.MarshalECPrivateKey(pub.(*ecdsa.PrivateKey))
	Expect(err).ShouldNot(HaveOccurred())

	clientKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derKey,
	})

	clientTLSCert, err := tls.X509KeyPair(sClientCertPEM,
		clientKeyPEM)
	Expect(err).ShouldNot(HaveOccurred())

	return clientTLSCert
}

func GetCertTempl() x509.Certificate {
	src := mrand.NewSource(time.Now().UnixNano())
	sn := big.NewInt(int64(mrand.New(src).Uint64()))

	certTempl := x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Second),
		NotAfter:              time.Now().Add(1 * time.Minute),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
	}

	return certTempl
}

var _ = Describe("ApiEaa", func() {
	Describe("GET", func() {
		Context("when client owns signed certificate", func() {
			Specify("will return no error and valid response", func() {

				clientPriv, err := ecdsa.GenerateKey(
					elliptic.P256(),
					rand.Reader,
				)
				Expect(err).ShouldNot(HaveOccurred())

				client := GetValidTLSClient(clientPriv)

				tlsResp, err := client.Get("https://" + cfg.TLSEndpoint)
				Expect(err).ShouldNot(HaveOccurred())
				defer tlsResp.Body.Close()

				body, err := ioutil.ReadAll(tlsResp.Body)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(string(body)).To(Equal("404 page not found\n"))
			})
		})

		Context("when client owns unsigned certificate", func() {
			Specify("will return error", func() {

				// create cert pool with rootCA
				certPool := x509.NewCertPool()
				c, err := ioutil.ReadFile(tempConfCaRootPath)
				Expect(err).ShouldNot(HaveOccurred())
				ok := certPool.AppendCertsFromPEM(c)
				Expect(ok).To(BeTrue())

				// generate key for client
				clientPriv, err := ecdsa.GenerateKey(elliptic.P256(),
					rand.Reader)
				Expect(err).ShouldNot(HaveOccurred())

				certTempl := GetCertTempl()
				clientTLSCert := GenerateTLSCert(&certTempl, &certTempl,
					clientPriv, clientPriv)

				// create client with certificate created above
				client := &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{RootCAs: certPool,
							Certificates: []tls.Certificate{clientTLSCert},
							ServerName:   EaaCommonName,
						},
					}}

				_, err = client.Get("https://" + cfg.TLSEndpoint)
				Expect(err).Should(HaveOccurred())
			})
		})
	})
})
