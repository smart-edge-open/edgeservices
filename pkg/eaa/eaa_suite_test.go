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
	"encoding/json"
	"flag"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/onsi/gomega/gexec"
	"github.com/smartedgemec/appliance-ce/internal/authtest"
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
	TLSEndpoint         string `json:"tlsEndpoint"`
	OpenEndpoint        string `json:"openEndpoint"`
	ApplianceTimeoutSec int    `json:"timeout"`
}

// test suite config with default values
var cfg = EAATestSuiteConfig{"../../", "localhost:44300", "localhost:8000", 2}

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
		"tlsEndpoint": "` + cfg.TLSEndpoint + `",
		"openEndpoint": "` + cfg.OpenEndpoint + `",
		"certs": {
			"CaRootKeyPath": "` + tempConfCaRootKeyPath + `",
			"caRootPath": "` + tempConfCaRootPath + `",
			"serverCertPath": "` + tempConfServerCertPath + `",
			"serverKeyPath": "` + tempConfServerKeyPath + `"
		}
	}`)

	err = ioutil.WriteFile(tempdir+"/configs/eaa.json", eaaCfg, 0644)
	Expect(err).ToNot(HaveOccurred(), "Error when creating eaa.json")
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
	tempConfServerCertPath = tempdir + "/" + "certs/eaa/server.crt"
	tempConfServerKeyPath = tempdir + "/" + "certs/eaa/server.key"

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
