// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package auth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/otcshare/edgenode/pkg/auth"
	pb "github.com/otcshare/edgenode/pkg/auth/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcCreds "google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

var (
	// CAKey generated with:
	// openssl ecparam -genkey -name secp384r1 -out "ca.key"
	/*CAKey = []byte(`-----BEGIN EC PARAMETERS-----
	BgUrgQQAIg==
	-----END EC PARAMETERS-----
	-----BEGIN EC PRIVATE KEY-----
	MIGkAgEBBDC55ShIT3VDb4MC5wRXYJk9zp95MGLYIn8l+wgCCoSXRhkh2ef41acK
	3tel+K8Cs9ygBwYFK4EEACKhZANiAAQevjf1eHyZ5MPoIecuWiJ8wrRvXiYgkbS9
	2fKiv8yVpJtZ0yYfjZyWDbxnCgB7LIEYpY349FVSujqc+jbXhWZQFtWXyWMHS18J
	Ngi1rAnO9H8UnC5IbdkW49zJNCYB67o=
	-----END EC PRIVATE KEY-----`)
	*/
	// CACert generated with:
	// openssl req -key "ca.key" -new -x509 -days 3650 -subj \
	// "/CN=CATEST" -out "ca.crt"
	CACert = []byte(`-----BEGIN CERTIFICATE-----
MIIBsjCCATegAwIBAgIUE3P7e0UGTtKQO0/u1MPTq0iimVAwCgYIKoZIzj0EAwIw
ETEPMA0GA1UEAwwGQ0FURVNUMB4XDTIwMDgxOTAxMTA0OFoXDTMwMDgxNzAxMTA0
OFowETEPMA0GA1UEAwwGQ0FURVNUMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEHr43
9Xh8meTD6CHnLloifMK0b14mIJG0vdnyor/MlaSbWdMmH42clg28ZwoAeyyBGKWN
+PRVUro6nPo214VmUBbVl8ljB0tfCTYItawJzvR/FJwuSG3ZFuPcyTQmAeu6o1Aw
TjAdBgNVHQ4EFgQUwtjXDEkckeUbdpkSDR9s1b/0XM0wHwYDVR0jBBgwFoAUwtjX
DEkckeUbdpkSDR9s1b/0XM0wDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNpADBm
AjEAp3am/0lalH+gu7ib2b4fBwZKVUe6dmhmbB9VWztSnn85yn+yE6dRVf4p90Tu
Xg/UAjEAiz6/J/ldpHZCuMUWQvgw+LWhUQVNesXVnTPQokaneX71bwDNRUvIROE9
8ydKobJk
-----END CERTIFICATE-----`)
	// ServerKey generated with:
	// openssl ecparam -genkey -name secp384r1 -out "server.key"
	ServerKey = []byte(`-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDPM+azRRWyg85gCWSMJYlL9fA2/7t3xHpUFNxSkyfvTFLvo+4BlcIV
0bm8jrYKoJigBwYFK4EEACKhZANiAATt/+wLd+Cv740H9jsICihyrBpuuNdtYIEE
vrQKSAt4+dhIxnBhpRxyM6jgxIwO1c8z45Do+fPqHHNnaV/YjFfUq3LtBZxYu7AL
JvLeT3dabQnqd5PR9px5xZl48mgVvTM=
-----END EC PRIVATE KEY-----`)
	// ServerCert generated with:
	// echo "subjectAltName = DNS.1:enroll.controller.openness" \
	// >> extfile.cnf
	// openssl x509 -req -extfile extfile.cnf -in "server.csr" \
	// -CA "ca.crt" -CAkey "ca.key" -days 3650 -out "server.cert" \
	// -CAcreateserial
	ServerCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBnzCCASSgAwIBAgIUD4yRcV0odECXs+bZJ2IKBQjpvnUwCgYIKoZIzj0EAwIw
ETEPMA0GA1UEAwwGQ0FURVNUMB4XDTIwMDgxOTAxMTA0OFoXDTMwMDgxNzAxMTA0
OFowJTEjMCEGA1UEAwwaZW5yb2xsLmNvbnRyb2xsZXIub3Blbm5lc3MwdjAQBgcq
hkjOPQIBBgUrgQQAIgNiAATt/+wLd+Cv740H9jsICihyrBpuuNdtYIEEvrQKSAt4
+dhIxnBhpRxyM6jgxIwO1c8z45Do+fPqHHNnaV/YjFfUq3LtBZxYu7ALJvLeT3da
bQnqd5PR9px5xZl48mgVvTOjKTAnMCUGA1UdEQQeMByCGmVucm9sbC5jb250cm9s
bGVyLm9wZW5uZXNzMAoGCCqGSM49BAMCA2kAMGYCMQDyU8370vw8XxgaiERpbWO7
S4L/qjKCOq0wdPvXChnxh2E4C3b0Q5K2O5i78bZ9f3MCMQD89NAnSQFEd8Z19vrC
l8ovF7Xb551xGJcwjlkFemczvZgdGfS9QM+G0u8SdwlBZqY=
-----END CERTIFICATE-----`)
)

func TestEnroll(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Enroll Suite")
}

type fakeAuthServer struct {
	s *grpc.Server
}

var (
	certDir  string
	certPath string
	fs       fakeAuthServer
)

const certFileEnv = "SSL_CERT_FILE"

func (fs *fakeAuthServer) RequestCredentials(ctx context.Context,
	id *pb.Identity) (*pb.Credentials, error) {

	return credSuccess(id)
}

func (fs *fakeAuthServer) startFakeAuthServer(endpoint string) error {
	lis, err := net.Listen("tcp", endpoint)
	if err != nil {
		return status.Errorf(codes.NotFound,
			"Failed to start API listener: %v", err)
	}
	cert, err := tls.X509KeyPair(ServerCert, ServerKey)
	if err != nil {
		return status.Errorf(codes.NotFound,
			"Failed to load cret: %v", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		return status.Errorf(codes.NotFound,
			"Failed to get system cretpool: %v", err)
	}

	creds := grpcCreds.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
	})

	fs.s = grpc.NewServer(grpc.Creds(creds))
	pb.RegisterAuthServiceServer(fs.s, fs)

	go func() {
		if err := fs.s.Serve(lis); err != nil {
			log.Printf("grpcServer.Serve error: %v", err)
		}
	}()

	return nil
}

type enrollClientStub struct {
	getHandler func(id *pb.Identity, timeout time.Duration,
		endpoint string) (*pb.Credentials, error)
}

func (c enrollClientStub) Get(id *pb.Identity, timeout time.Duration,
	endpoint string) (*pb.Credentials, error) {
	return c.getHandler(id, timeout, endpoint)
}

var getCredSuccess = func(id *pb.Identity,
	timeout time.Duration, endpoint string) (*pb.Credentials, error) {
	return credSuccess(id)
}

func credSuccess(id *pb.Identity) (*pb.Credentials, error) {
	var c pb.Credentials

	csrPEM, _ := pem.Decode([]byte(id.GetCsr()))
	Expect(csrPEM).ToNot(BeNil())
	csr, err := x509.ParseCertificateRequest(csrPEM.Bytes)
	Expect(err).ToNot(HaveOccurred())

	caKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	Expect(err).ToNot(HaveOccurred())
	caCert, err := genCert(caKey)
	Expect(err).ToNot(HaveOccurred())
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     caCert.NotAfter,
	}

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		caCert,
		csr.PublicKey,
		caKey,
	)
	Expect(err).ToNot(HaveOccurred())
	encodedCert := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		},
	)
	Expect(encodedCert).ToNot(BeNil())
	encodedCA := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCert.Raw,
		},
	)
	Expect(encodedCA).ToNot(BeNil())

	c.Certificate = string(encodedCert)
	c.CaChain = []string{string(encodedCA), string(encodedCA)}
	c.CaPool = []string{string(encodedCA), string(encodedCA)}
	return &c, nil
}

var getCredFail = func(id *pb.Identity,
	timeout time.Duration, endpoint string) (*pb.Credentials, error) {
	return nil, errors.New("Get credentials failed")
}

var getCredFailCert = func(id *pb.Identity,
	timeout time.Duration, endpoint string) (*pb.Credentials, error) {
	c, err := getCredSuccess(id, timeout, "")
	Expect(err).ToNot(HaveOccurred())
	c.Certificate = ""
	return c, nil
}

var getCredFailCAChain = func(id *pb.Identity,
	timeout time.Duration, endpoint string) (*pb.Credentials, error) {
	c, err := getCredSuccess(id, timeout, "")
	Expect(err).ToNot(HaveOccurred())
	c.CaChain = []string{}
	return c, nil
}

var getCredFailCAPool = func(id *pb.Identity,
	timeout time.Duration, endpoint string) (*pb.Credentials, error) {
	c, err := getCredSuccess(id, timeout, "")
	Expect(err).ToNot(HaveOccurred())
	c.CaPool = []string{}
	return c, nil
}

var _ = BeforeSuite(func() {
	var err error

	cmd := exec.Command("sed", "-i", "$a127.0.0.1 enroll.controller.openness", "/etc/hosts")
	err = cmd.Run()
	Expect(err).ToNot(HaveOccurred())
	fs = fakeAuthServer{}
	certDir, err = ioutil.TempDir(os.TempDir(), "certs")
	Expect(err).ToNot(HaveOccurred())

	certPath = filepath.Join(certDir, "testca.crt")
	err = ioutil.WriteFile(certPath, CACert, os.FileMode(0644))
	Expect(err).ToNot(HaveOccurred())
	err = os.Setenv(certFileEnv, certDir+"/testca.crt")
	Expect(err).ToNot(HaveOccurred())

	endpoint := ":61919"
	err = fs.startFakeAuthServer(endpoint)
	Expect(err).ToNot(HaveOccurred())
})

var _ = Describe("Enrollment", func() {
	Describe("Requests and verifies credentials", func() {
		When("Received credentials are invalid", func() {
			It("Fails with an error", func() {
				err := auth.Enroll("", "", time.Second,
					auth.EnrollClient{})
				Expect(err).To(HaveOccurred())

				err = auth.Enroll(certDir, "", time.Second,
					enrollClientStub{getCredFail})
				Expect(err).To(HaveOccurred())

				err = auth.Enroll(certDir, "", time.Second,
					enrollClientStub{getCredFailCert})
				Expect(err).To(HaveOccurred())

				err = auth.Enroll(certDir, "", time.Second,
					enrollClientStub{getCredFailCAChain})
				Expect(err).To(HaveOccurred())

				err = auth.Enroll(certDir, "", time.Second,
					enrollClientStub{getCredFailCAPool})
				Expect(err).To(HaveOccurred())

				err = os.Chmod(certDir, os.FileMode(0456))
				Expect(err).ToNot(HaveOccurred())
				err = auth.Enroll(certDir, "", time.Second,
					auth.EnrollClient{})
				Expect(err).To(HaveOccurred())
			})
		})
		When("Received credentials are correct", func() {
			It("Saves credentials and returns no error", func() {
				err := auth.Enroll(certDir, "dns:///enroll.controller.openness:61919", time.Second,
					auth.EnrollClient{})
				Expect(err).ToNot(HaveOccurred())

				Expect(certDir).To(BeADirectory())
				Expect(filepath.Join(certDir, "key.pem")).To(BeAnExistingFile())
				Expect(filepath.Join(certDir, "cert.pem")).To(
					BeAnExistingFile())
				Expect(filepath.Join(certDir, "cacerts.pem")).To(
					BeAnExistingFile())
				Expect(filepath.Join(certDir, "root.pem")).To(
					BeAnExistingFile())

				caPool, err := ioutil.ReadFile(filepath.Join(
					certDir, "root.pem"))
				Expect(err).ToNot(HaveOccurred())
				caChain, err := ioutil.ReadFile(filepath.Join(certDir,
					"cacerts.pem"))
				Expect(err).ToNot(HaveOccurred())
				Expect(caPool).To(Equal(caChain))

				err = auth.Enroll(certDir, "", time.Second,
					enrollClientStub{getCredFail})
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})
})

var _ = AfterSuite(func() {
	err := os.RemoveAll(certDir)
	Expect(err).ToNot(HaveOccurred())
	fs.s.GracefulStop()
	cmd := exec.Command("sed", "-i", "$d", "/etc/hosts")
	err = cmd.Run()
	Expect(err).ToNot(HaveOccurred())
})
