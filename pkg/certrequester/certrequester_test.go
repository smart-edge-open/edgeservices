// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2021 Intel Corporation

package certrequester_test

import (
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"io/ioutil"
	"log/syslog"
	"net"
	"os"
	"testing"
	"time"

	logger "github.com/otcshare/edgenode/common/log"
	"github.com/otcshare/edgenode/pkg/certrequester"
	"github.com/otcshare/edgenode/pkg/util"
	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestCertrequester(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Certrequester Suite")
}

var _ = Describe("Certrequester", func() {
	const (
		workDir      = "workdir"
		testKeyPath  = "./testdata/certs/key.pem"
		testCertPath = "./testdata/certs/cert.pem"
		keyPath      = workDir + "/certs/key.pem"
		certPath     = workDir + "/certs/cert.pem"
	)

	var (
		cfg           certrequester.Config
		cfgPath       string
		clientsetFake clientset.Interface
	)

	logger.DefaultLogger.SetLevel(syslog.LOG_DEBUG)

	BeforeEach(func() {
		Expect(os.MkdirAll(workDir+"/certs", 0755)).To(Succeed())

		cfg = certrequester.Config{
			CSR: certrequester.CSRConfig{
				Name: "test-csr",
				Subject: pkix.Name{
					CommonName: "test-cn",
				},
				DNSSANs: []string{"test-dns"},
				IPSANs:  []net.IP{},
				KeyUsages: []certificatesv1.KeyUsage{
					"server auth", "key encipherment", "digital signature",
				},
			},
			Signer:      "test-signer",
			WaitTimeout: util.Duration{Duration: 5 * time.Second},
		}

		cfgPath = workDir + "/config.json"
		dumpConfig(cfgPath, &cfg)

		clientsetFake = fake.NewSimpleClientset()
	})

	AfterEach(func() {
		os.RemoveAll(workDir)
	})

	Describe("certificate", func() {
		When("config is valid", func() {
			cert := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: []byte("TEST CERTIFICATE"),
			})

			When("no key and no certificate is provided", func() {
				It("should be generated and valid", func() {
					errCh := make(chan error)

					// Get certificate in another goroutine
					go func() {
						errCh <- certrequester.GetCertificate(
							context.Background(),
							clientsetFake,
							cfgPath,
							certPath,
							keyPath)
					}()

					// Sign the CSR
					Eventually(func() error {
						return signCSR(clientsetFake, cfg.CSR.Name, cert)
					}).Should(Succeed())

					// Wait for GetCertificate() to finish
					Expect(<-errCh).NotTo(HaveOccurred())
					Expect(ioutil.ReadFile(certPath)).To(Equal(cert))
				})
			})

			When("key is provided", func() {
				It("should be generated and valid", func() {
					errCh := make(chan error)
					copyFile(testKeyPath, keyPath)

					// Get certificate in another goroutine
					go func() {
						errCh <- certrequester.GetCertificate(
							context.Background(),
							clientsetFake,
							cfgPath,
							certPath,
							keyPath)
					}()

					// Sign the CSR
					Eventually(func() error {
						return signCSR(clientsetFake, cfg.CSR.Name, cert)
					}).Should(Succeed())

					// Wait for GetCertificate() to finish
					Expect(<-errCh).NotTo(HaveOccurred())
					Expect(ioutil.ReadFile(certPath)).To(Equal(cert))
				})
			})

			When("key and certificate are provided", func() {
				It("should be re-used and not generated", func() {
					copyFile(testKeyPath, keyPath)
					copyFile(testCertPath, certPath)

					c, err := ioutil.ReadFile(certPath)
					Expect(err).NotTo(HaveOccurred())

					Expect(certrequester.GetCertificate(
						context.Background(),
						clientsetFake,
						cfgPath,
						certPath,
						keyPath)).To(Succeed())

					Expect(ioutil.ReadFile(certPath)).To(Equal(c), "Certificate should remain unchanged")
				})
			})

			When("there's an old CSR with the same name", func() {
				It("should be generated and valid", func() {
					errCh := make(chan error)

					cfg.WaitTimeout = util.Duration{Duration: 1 * time.Millisecond}
					timeoutCfgPath := workDir + "/timeout.json"
					dumpConfig(timeoutCfgPath, cfg)

					Expect(certrequester.GetCertificate(
						context.Background(),
						clientsetFake,
						timeoutCfgPath,
						certPath,
						keyPath)).NotTo(Succeed(),
						"The first call to GetCertificate() should time out leaving the CSR request pending")

					// Get certificate using the same CSR name in another goroutine
					go func() {
						errCh <- certrequester.GetCertificate(
							context.Background(),
							clientsetFake,
							cfgPath,
							certPath,
							keyPath)
					}()

					// Sign the CSR
					Eventually(func() ([]byte, error) {
						signErr := signCSR(clientsetFake, cfg.CSR.Name, cert)
						if signErr != nil {
							return []byte{}, signErr
						}
						return ioutil.ReadFile(certPath)
					}).Should(Equal(cert))

					Expect(<-errCh).NotTo(HaveOccurred())
				})
			})
		})
	})
})

func dumpConfig(path string, v interface{}) {
	data, err := json.MarshalIndent(v, "", " ")
	Expect(err).ShouldNot(HaveOccurred())

	err = ioutil.WriteFile(path, data, 0644)
	Expect(err).ShouldNot(HaveOccurred())
}

func signCSR(clientsetFake clientset.Interface, name string, cert []byte) error {
	// Fetch the CSR
	csr, err := clientsetFake.CertificatesV1().CertificateSigningRequests().Get(
		context.TODO(), name, metav1.GetOptions{},
	)
	if err != nil {
		return err
	}

	// Add approval
	c := certificatesv1.CertificateSigningRequestCondition{
		Type:   certificatesv1.CertificateApproved,
		Status: "True",
	}

	// Sign the CSR
	csr.Status.Conditions = append(csr.Status.Conditions, c)
	csr.Status.Certificate = cert

	// Update the CSR
	_, err = clientsetFake.CertificatesV1().CertificateSigningRequests().UpdateStatus(
		context.TODO(), csr, metav1.UpdateOptions{},
	)
	return err
}

func copyFile(src string, dst string) {
	srcFile, err := os.Open(src)
	Expect(err).ToNot(HaveOccurred(), "Copy file - error when opening "+src)
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	Expect(err).ToNot(HaveOccurred(), "Copy file - error when creating "+dst)
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	Expect(err).ToNot(HaveOccurred(), "Copy file - error when copying "+src+" to "+dst)
}
