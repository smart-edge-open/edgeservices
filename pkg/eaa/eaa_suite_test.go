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
	"crypto/tls"
	"encoding/json"
	"flag"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/onsi/gomega/gexec"
)

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

var appliance *gexec.Session

type EAATestSuiteConfig struct {
	Dir                 string `json:"dir"`
	Endpoint            string `json:"endpoint"`
	ApplianceTimeoutSec int    `json:"timeout"`
}

// test suite config with default values
var cfg = EAATestSuiteConfig{"../../", "localhost:44300", 2}

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

func generateCerts() {

	// TODO: Example cert creation required to appliance init - to be replaced
	// by functional cert generation logic
	By("Generating certs")
	err := os.MkdirAll(tempdir+"/certs/eaa", 0755)
	Expect(err).ToNot(HaveOccurred(), "Error when creating temp directory")

	cmd := exec.Command("openssl", "req", "-x509", "-nodes", "-newkey",
		"rsa:2048", "-keyout", "server.key", "-out", "server.crt", "-days",
		"3650", "-subj", "/C=TT/ST=Test/L=Test/O=Test/OU=Test/CN=test.com")

	cmd.Dir = tempdir + "/certs/eaa"
	err = cmd.Run()
	Expect(err).ToNot(HaveOccurred(), "Error when generating .key .crt")

	cmd = exec.Command("openssl", "x509", "-in", "server.crt", "-out",
		"rootCA.pem", "-outform", "PEM")

	cmd.Dir = tempdir + "/certs/eaa"
	err = cmd.Run()
	Expect(err).ToNot(HaveOccurred(), "Error when converting .crt to .pem")

	cmd = exec.Command("openssl", "req", "-new", "-key", "server.key",
		"-out", "server.csr", "-subj",
		"/C=TT/ST=Test/L=Test/O=Test/OU=Test/CN=test.com")

	cmd.Dir = tempdir + "/certs/eaa"
	err = cmd.Run()
	Expect(err).ToNot(HaveOccurred(), "Error when generating .csr")
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
		"endpoint": "` + cfg.Endpoint + `",
		"certs": {
			"caRootPath": "certs/eaa/rootCA.pem",
			"serverCertPath": "certs/eaa/server.crt",
			"serverKeyPath": "certs/eaa/server.key"
		}
	}`)
	err = ioutil.WriteFile(tempdir+"/configs/eaa.json", eaaCfg, 0644)
	Expect(err).ToNot(HaveOccurred(), "Error when creating eaa.json")
}

var tempdir string

var _ = BeforeSuite(func() {

	readConfig(cfgPath)

	var err error
	tempdir, err = ioutil.TempDir("", "eaaTestBuild")
	if err != nil {
		Fail("Unable to create temporary build directory")
	}

	// TODO: generate certificates before starting appliance
	generateCerts()

	generateConfigs()

	By("Building appliance")
	cmd := exec.Command("make", "BUILD_DIR="+tempdir, "appliance")
	cmd.Dir = cfg.Dir
	err = cmd.Run()
	Expect(err).ToNot(HaveOccurred(), "Error when building appliance!")

	By("Starting appliance")
	cmd = exec.Command(tempdir + "/appliance")
	cmd.Dir = tempdir
	appliance, err = gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).ToNot(HaveOccurred(), "Unable to start appliance")

	// Wait until appliance is ready before running any tests specs
	cert, err := tls.LoadX509KeyPair(tempdir+"/certs/eaa/rootCA.pem",
		tempdir+"/certs/eaa/server.key")
	if err != nil {
		Fail("Error when loading client certificates")
	}

	//nolint
	conf := tls.Config{Certificates: []tls.Certificate{cert},
		InsecureSkipVerify: true}

	c1 := make(chan bool, 1)
	go func() {
		for {
			conn, err := tls.Dial("tcp", cfg.Endpoint, &conf)
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
		Fail("Starting appliance - timeout!")
	}
})

var _ = AfterSuite(func() {

	defer os.RemoveAll(tempdir) // cleanup temporary build directory

	if appliance != nil {
		By("Stopping appliance")
		appliance.Terminate()
		appliance.Wait((time.Duration(cfg.ApplianceTimeoutSec) * time.Second))
		Expect(appliance.ExitCode()).To(Equal(0))
	}
})
