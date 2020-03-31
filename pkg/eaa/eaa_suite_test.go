// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"io/ioutil"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/errors"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"

	"github.com/gorilla/websocket"
	"github.com/open-ness/edgenode/internal/authtest"
	"github.com/open-ness/edgenode/pkg/eaa"
	evapb "github.com/open-ness/edgenode/pkg/eva/internal_pb"

	"github.com/open-ness/common/log"
)

// EaaCommonName Common Name that EAA uses for TLS connection
const EaaCommonName string = "eaa.openness"

// To pass configuration file path use ginkgo pass-through argument
// ginkgo -r -v -- -cfg=myconfig.json
var cfgPath string

func init() {
	flag.StringVar(&cfgPath, "cfg", "", "EAA TestSuite configuration file path")
}

func TestEaa(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Eaa Suite")
}

type EAATestSuiteConfig struct {
	Dir                 string `json:"Dir"`
	TLSEndpoint         string `json:"TlsEndpoint"`
	OpenEndpoint        string `json:"OpenEndpoint"`
	ValidationEndpoint  string `json:"ValidationEndpoint"`
	ApplianceTimeoutSec int    `json:"Timeout"`
}

// test suite config with default values
var cfg = EAATestSuiteConfig{"../../", "localhost:44300", "localhost:48080",
	"localhost:42555", 2}

func readConfig(path string) {
	if path != "" {
		By("Configuring EAA test suite with: " + path)
		cfgData, err := ioutil.ReadFile(path)
		if err != nil {
			Fail("Failed to read suite configuration file!")
		}
		err = json.Unmarshal(cfgData, &cfg)
		if err != nil {
			Fail("Failed to unmarshal suite configuration file!")
		}
	}
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

// Function is not used anymore, but can be used as helper:
// func generateCerts() {

// 	By("Generating certs")
// 	err := os.MkdirAll(tempdir+"/certs/eaa", 0755)
// 	Expect(err).ToNot(HaveOccurred(), "Error when creating temp directory")

// 	cmd := exec.Command("openssl", "req", "-x509", "-nodes", "-newkey",
// 		"rsa:2048", "-keyout", "server.key", "-out", "server.crt", "-days",
// 		"3650", "-subj", "/C=TT/ST=Test/L=Test/O=Test/OU=Test/CN=localhost")

// 	cmd.Dir = tempdir + "/certs/eaa"
// 	err = cmd.Run()
// 	Expect(err).ToNot(HaveOccurred(), "Error when generating .key .crt")

// 	cmd = exec.Command("openssl", "x509", "-in", "server.crt", "-out",
// 		"rootCA.pem", "-outform", "PEM")

// 	cmd.Dir = tempdir + "/certs/eaa"
// 	err = cmd.Run()
// 	Expect(err).ToNot(HaveOccurred(), "Error when converting .crt to .pem")

// 	cmd = exec.Command("openssl", "req", "-new", "-key", "server.key",
// 		"-out", "server.csr", "-subj",
// 		"/C=TT/ST=Test/L=Test/O=Test/OU=Test/CN=localhost")

// 	cmd.Dir = tempdir + "/certs/eaa"
// 	err = cmd.Run()
// 	Expect(err).ToNot(HaveOccurred(), "Error when generating .csr")
// }

type FakeIPAppLookupServiceServerImpl struct{}

var responseFromEva = "testapp"

func (*FakeIPAppLookupServiceServerImpl) GetApplicationByIP(
	ctx context.Context,
	ipAppLookupInfo *evapb.IPApplicationLookupInfo) (
	*evapb.IPApplicationLookupResult, error) {

	log.Info("FakeIPAppLookupServiceServerImpl GetApplicationByIP for: " +
		ipAppLookupInfo.GetIpAddress())

	var result evapb.IPApplicationLookupResult
	result.AppID = responseFromEva
	return &result, nil
}

func fakeAppidProvider() error {

	lApp, err := net.Listen("tcp", cfg.ValidationEndpoint)
	if err != nil {
		log.Errf("net.Listen error: %+v", err)
		return err
	}

	serverApp := grpc.NewServer()
	ipAppLookupService := FakeIPAppLookupServiceServerImpl{}
	evapb.RegisterIPApplicationLookupServiceServer(serverApp,
		&ipAppLookupService)

	go func() {
		log.Infof("Fake internal serving on %s", cfg.ValidationEndpoint)
		err = serverApp.Serve(lApp)
		if err != nil {
			log.Errf("Failed grpcServe(): %v", err)
			return
		}
	}()

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
	Expect(err).ToNot(HaveOccurred(), "Copy file - error when copying "+src+
		" to "+dst)
}

func generateConfigs() {
	By("Generating configuration files")
	_ = os.MkdirAll(tempdir+"/configs", 0755)

	files, err := ioutil.ReadDir(cfg.Dir + "/configs/")
	Expect(err).ToNot(HaveOccurred(), "Error when reading configs directory")
	for _, f := range files {
		if f.Name() != "eaa.json" {
			copyFile(cfg.Dir+"/configs/"+f.Name(), tempdir+
				"/configs/"+f.Name())
		}
	}

	// custom config for EAA
	eaaCfg := []byte(`{
		"TlsEndpoint": "` + cfg.TLSEndpoint + `",
		"OpenEndpoint": "` + cfg.OpenEndpoint + `",
		"ValidationEndpoint": "` + cfg.ValidationEndpoint + `",
		"Certs": {
			"CaRootKeyPath": "` + tempConfCaRootKeyPath + `",
			"CaRootPath": "` + tempConfCaRootPath + `",
			"ServerCertPath": "` + tempConfServerCertPath + `",
			"ServerKeyPath": "` + tempConfServerKeyPath + `",
			"CommonName": "` + EaaCommonName + `"
		}
	}`)

	err = ioutil.WriteFile(tempdir+"/configs/eaa.json", eaaCfg, 0644)
	Expect(err).ToNot(HaveOccurred(), "Error when creating eaa.json")
}

var (
	srvCtx             context.Context
	srvCancel          context.CancelFunc
	applianceIsRunning bool
)

func runEaa(stopIndication chan bool) error {

	By("Starting appliance")

	srvCtx, srvCancel = context.WithCancel(context.Background())
	_ = srvCancel
	eaaRunFail := make(chan bool)
	go func() {
		err := eaa.Run(srvCtx, tempdir+"/configs/eaa.json")
		if err != nil {
			log.Errf("Run() exited with error: %#v", err)
			applianceIsRunning = false
			eaaRunFail <- true
		}
		stopIndication <- true
	}()

	// Wait until appliance is ready before running any tests specs
	c1 := make(chan bool, 1)
	go func() {
		for {
			conn, err := net.Dial("tcp", cfg.OpenEndpoint)
			if err == nil {
				conn.Close()
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		c1 <- true
	}()

	select {
	case <-c1:
		By("Appliance ready")
	case <-time.After(time.Duration(cfg.ApplianceTimeoutSec) * time.Second):
		return errors.New("starting appliance - timeout")
	case <-eaaRunFail:
		return errors.New("starting appliance - run fail")

	}
	return nil
}

func stopEaa(stopIndication chan bool) int {
	By("Stopping appliance")
	srvCancel()
	<-stopIndication
	if applianceIsRunning == true {
		return 0
	}

	return 1
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

func generateSignedClientCert(certTempl *x509.Certificate) (tls.Certificate,
	*x509.CertPool) {
	src := mrand.NewSource(time.Now().UnixNano())
	sn := big.NewInt(int64(mrand.New(src).Uint64()))
	certTempl.SerialNumber = sn

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

	// use root key generated by EAA
	serverPriv, err := tls.LoadX509KeyPair(
		tempConfCaRootPath,
		tempConfCaRootKeyPath)
	Expect(err).ShouldNot(HaveOccurred())

	prvCert, err := x509.ParseCertificate(
		serverPriv.Certificate[0])
	Expect(err).ShouldNot(HaveOccurred())

	clientTLSCert := GenerateTLSCert(certTempl, prvCert,
		clientPriv, serverPriv.PrivateKey)

	return clientTLSCert, certPool
}

func createHTTPClient(clientTLSCert tls.Certificate,
	certPool *x509.CertPool) *http.Client {
	// create client with certificate signed above
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      certPool,
				Certificates: []tls.Certificate{clientTLSCert},
				ServerName:   EaaCommonName,
			},
		}}

	return client
}

func createWebSocDialer(clientTLSCert tls.Certificate,
	certPool *x509.CertPool) *websocket.Dialer {
	// create socket with certificate signed above
	socket := &websocket.Dialer{
		TLSClientConfig: &tls.Config{
			RootCAs:      certPool,
			Certificates: []tls.Certificate{clientTLSCert},
			ServerName:   EaaCommonName,
		},
	}

	return socket
}

var (
	tempdir                string
	tempConfCaRootKeyPath  string
	tempConfCaRootPath     string
	tempConfServerCertPath string
	tempConfServerKeyPath  string
)

var _ = BeforeSuite(func() {
	readConfig(cfgPath)

	var err error
	tempdir, err = ioutil.TempDir("", "eaaTestBuild")
	if err != nil {
		Fail("Unable to create temporary build directory")
	}

	Expect(authtest.EnrollStub(filepath.Join(tempdir, "certs"))).ToNot(
		HaveOccurred())

	tempConfCaRootKeyPath = tempdir + "/" + "certs/eaa/rootCA.key"
	tempConfCaRootPath = tempdir + "/" + "certs/eaa/rootCA.pem"
	tempConfServerCertPath = tempdir + "/" + "certs/eaa/server.pem"
	tempConfServerKeyPath = tempdir + "/" + "certs/eaa/server.key"

	generateConfigs()

	err = fakeAppidProvider()
	Expect(err).ToNot(HaveOccurred(), "Unable to start fake AppID provider")

	By("Building appliance")
	cmd := exec.Command("make", "BUILD_DIR="+tempdir, "SKIP_DOCKER_IMAGES=1", "appliance-nts")
	cmd.Dir = cfg.Dir
	err = cmd.Run()
	Expect(err).ToNot(HaveOccurred(), "Error when building appliance!")
})

var _ = AfterSuite(func() {

	defer os.RemoveAll(tempdir) // cleanup temporary build directory

})
