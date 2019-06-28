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

package eva_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/smartedgemec/appliance-ce/internal/authtest"
	"github.com/smartedgemec/appliance-ce/pkg/config"
	"github.com/smartedgemec/appliance-ce/pkg/eva"
	pb "github.com/smartedgemec/appliance-ce/pkg/eva/pb"

	logger "github.com/smartedgemec/log"
	"log/syslog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	mainCfgFile = "testdata/eva.json"
	kubeCfgFile = "testdata/eva_kube.json"
)

// NOTE
// This test file uses the Go testing framework, while rest of the
// test code in OpenNESS uses Ginko / Gomeka.
// This file needs to be updated to match the other test files.
// (Or other test files updated to match this one)
func TestEva(t *testing.T) {
	var cfg eva.Config
	var wg sync.WaitGroup
	dockerTestOn := false
	libvirtTestOn := false

	logger.SetLevel(syslog.LOG_DEBUG) // want full debug logging for tests
	if err := config.LoadJSONConfig(mainCfgFile, &cfg); err != nil {
		t.Errorf("LoadJSONConfig() failed: %v", err)
	}

	// Cert setup
	if err := os.MkdirAll(cfg.CertsDir, 0700); err != nil {
		t.Errorf("Creating temp directory for certs failed: %v", err)
	}
	defer os.RemoveAll(cfg.CertsDir)
	transportCreds := prepareCerts(t, cfg.CertsDir)

	// Automated tests do not have the application image binaries
	// so we can only run basic tests there.
	// To manually test when you have those images, use the following:
	// go test -args dvk
	if len(os.Args) == 2 {
		if strings.Contains(os.Args[1], "d") {
			dockerTestOn = true
		}
		if strings.Contains(os.Args[1], "v") {
			libvirtTestOn = true
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	wg.Add(1)
	go func() {
		err := eva.Run(ctx, mainCfgFile)
		wg.Done()
		if err != nil {
			t.Errorf("eva.Run() failed: %v", err)
		}
	}()

	ctxTimeout, cancelTimeout := context.WithTimeout(context.Background(),
		10*time.Second)
	defer cancelTimeout()
	conn, err := grpc.DialContext(ctxTimeout, cfg.Endpoint,
		grpc.WithTransportCredentials(transportCreds), grpc.WithBlock())

	if err != nil {
		t.Errorf("failed to dial EVA: %v", err)
		cancel()
		return
	}
	defer conn.Close()

	/* TODO: add negative tests - undeploying a non-existent app */
	if dockerTestOn {
		failDockerDeploy(t, conn, "corrupt", "https://localhost/corrupt.img")

		callDockerDeploy(t, conn, "app-test-1",
			"https://localhost/hello-world.tar.gz")
		callUndeployAPI(t, conn, "app-test-1")

		callDockerDeploy(t, conn, "app-test-1",
			"https://localhost/hello-world.tar.gz")
		callGetStatus(t, conn, "app-test-1")
		callDockerDeploy(t, conn, "app-test-2", "/var/www/html/busybox.tar.gz")
		callUndeployAPI(t, conn, "app-test-1")
		callGetStatus(t, conn, "app-test-1")
		callUndeployAPI(t, conn, "app-test-2")

		testLifecycleDocker(t, conn, "hello-world-app",
			"/var/www/html/hello-world.tar.gz")
	}

	if libvirtTestOn {
		callLibvirtDeploy(t, conn, "app-test-vm-1",
			"https://localhost/freedos-1.0.7z")
		callGetStatus(t, conn, "app-test-vm-1")
		callLibvirtDeploy(t, conn, "app-test-vm-2",
			"https://localhost/freedos-1.0.7z")
		callUndeployAPI(t, conn, "app-test-vm-1")
		callGetStatus(t, conn, "app-test-vm-1")
		callUndeployAPI(t, conn, "app-test-vm-2")

		// nolint 'freedos-1.0.7z' is a file name, should not be autocorrected
		testLifecycleVM(t, conn, "hello-world-app",
			"/var/www/html/freedos-1.0.7z") // file test
	}

	cancel()  // stop the EVA running in other thread
	wg.Wait() // wait for the other thread to terminate!
}

func TestEvaKubernetesMode(t *testing.T) {
	var cfg eva.Config
	var wg sync.WaitGroup

	if len(os.Args) != 2 {
		return // Basic test already done above, no need to repeat
	}
	if !strings.Contains(os.Args[1], "k") {
		return // Basic test already done above, no need to repeat
	}

	fmt.Println("======================== KUBE ========================")
	if err := config.LoadJSONConfig(kubeCfgFile, &cfg); err != nil {
		t.Errorf("LoadJSONConfig() failed: %v", err)
	}
	// Cert setup
	if err := os.MkdirAll(cfg.CertsDir, 0700); err != nil {
		t.Errorf("Creating temp directory for certs failed: %v", err)
	}
	defer os.RemoveAll(cfg.CertsDir)
	transportCreds := prepareCerts(t, cfg.CertsDir)
	ctx, cancel := context.WithCancel(context.Background())

	wg.Add(1)
	go func() {
		err := eva.Run(ctx, kubeCfgFile)
		wg.Done()
		if err != nil {
			t.Errorf("eva.Run() failed: %v", err)
		}
	}()

	ctxTimeout, cancelTimeout := context.WithTimeout(context.Background(),
		10*time.Second)
	defer cancelTimeout()

	conn, err := grpc.DialContext(ctxTimeout, cfg.Endpoint,
		grpc.WithTransportCredentials(transportCreds), grpc.WithBlock())

	if err != nil {
		t.Errorf("failed to dial EVA: %v", err)
		cancel()
		return
	}
	defer conn.Close()

	callDockerDeploy(t, conn, "app-test-1",
		"https://localhost/hello-world.tar.gz")
	callGetStatus(t, conn, "app-test-1")

	callDockerDeploy(t, conn, "app-test-2", "/var/www/html/busybox.tar.gz")
	callGetStatus(t, conn, "app-test-2")

	callUndeployAPI(t, conn, "app-test-1")
	callGetStatus(t, conn, "app-test-1")
	callUndeployAPI(t, conn, "app-test-2")
	callGetStatus(t, conn, "app-test-2")

	cancel()  // stop the EVA running in other thread
	wg.Wait() // wait for the other thread to terminate!
}

// Prepare certificates for test
func prepareCerts(t *testing.T,
	certsDir string) credentials.TransportCredentials {

	err := authtest.EnrollStub(certsDir)
	if err != nil {
		t.Errorf("EnrollStub failed: %v", err)
	}
	transportCreds, err := authtest.ClientCredentialsStub()
	if err != nil {
		t.Errorf("ClientCredentialsStub failed: %v", err)
	}
	return transportCreds
}

func callDockerDeploy(t *testing.T, conn *grpc.ClientConn, id string,
	file string) {

	fmt.Printf("---------------------%v--DEPLOY-------------------\n", id)
	client := pb.NewApplicationDeploymentServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	uri := pb.Application_HttpUri{
		HttpUri: &pb.Application_HTTPSource{HttpUri: file},
	}
	app := pb.Application{Id: id, Cores: 2, Memory: 40, Source: &uri}

	_, err := client.DeployContainer(ctx, &app, grpc.WaitForReady(true))
	if err != nil {
		t.Errorf("DeployContainer failed: %+v", err)
	}

	cancel()
}

func failDockerDeploy(t *testing.T, conn *grpc.ClientConn, id string,
	file string) {

	fmt.Printf("---------------------%v--DEPLOY-BAD---------------\n", id)
	client := pb.NewApplicationDeploymentServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	uri := pb.Application_HttpUri{
		HttpUri: &pb.Application_HTTPSource{HttpUri: file},
	}
	app := pb.Application{Id: id, Cores: 2, Memory: 40960, Source: &uri}

	_, err := client.DeployContainer(ctx, &app, grpc.WaitForReady(true))
	if err == nil {
		t.Errorf("DeployContainer succeeded")
	} else {
		fmt.Printf("DeployContainer failed on bad image: %v\n", err)
	}

	cancel()
}

func callLibvirtDeploy(t *testing.T, conn *grpc.ClientConn, id string,
	file string) {

	fmt.Printf("------------LIBVIRT--%v--DEPLOY-------------------\n", id)
	client := pb.NewApplicationDeploymentServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	uri := pb.Application_HttpUri{
		HttpUri: &pb.Application_HTTPSource{HttpUri: file},
	}
	app := pb.Application{Id: id, Cores: 1, Memory: 40, Source: &uri}

	_, err := client.DeployVM(ctx, &app, grpc.WaitForReady(true))
	if err != nil {
		t.Errorf("DeployVM failed: %+v", err)
	}
	cancel()
}

func callUndeployAPI(t *testing.T, conn *grpc.ClientConn, id string) {
	fmt.Printf("---------------------%v--UNDEPLOY-----------------\n", id)

	client := pb.NewApplicationDeploymentServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	app := pb.ApplicationID{Id: id}

	_, err := client.Undeploy(ctx, &app, grpc.WaitForReady(true))
	if err != nil {
		t.Errorf("Undeploy failed: %+v", err)
	}
	cancel()
}

func callGetStatus(t *testing.T, conn *grpc.ClientConn, id string) {

	client := pb.NewApplicationLifecycleServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	app := pb.ApplicationID{Id: id}

	status, err := client.GetStatus(ctx, &app, grpc.WaitForReady(true))
	if err != nil {
		fmt.Printf("GetStatus(%s) failed: '%+v'\n", id, err)
		t.Errorf("GetStatus(%s) failed: %+v", id, err)
		return
	}

	fmt.Printf("GetStatus(%s) returned: '%v'\n", id, status)
}

// Deploy application in container from given image; start, restart and stop
// container; undeploy application.
func testLifecycleDocker(t *testing.T, conn *grpc.ClientConn, id string,
	image string) {

	var err error

	callDockerDeploy(t, conn, id, image)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	alsClient := pb.NewApplicationLifecycleServiceClient(conn)

	lc := pb.LifecycleCommand{Id: id}

	_, err = alsClient.Start(ctx, &lc, grpc.WaitForReady(true))
	if err != nil {
		t.Errorf("StartContainer failed: %+v", err)
	}

	_, err = alsClient.Restart(ctx, &lc, grpc.WaitForReady(true))
	if err != nil {
		t.Errorf("RestartContainer failed: %v", err)
	}

	_, err = alsClient.Stop(ctx, &lc, grpc.WaitForReady(true))
	if err != nil {
		t.Errorf("StopContainer failed: %v", err)
	}

	callUndeployAPI(t, conn, id)
}

// Deploy application in VM from given image; start, restart and stop
// VM; undeploy application.
func testLifecycleVM(t *testing.T, conn *grpc.ClientConn, id string,
	image string) {

	var err error

	callLibvirtDeploy(t, conn, id, image)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	alsClient := pb.NewApplicationLifecycleServiceClient(conn)

	lc := pb.LifecycleCommand{Id: id}

	_, err = alsClient.Start(ctx, &lc, grpc.WaitForReady(true))
	if err != nil {
		t.Errorf("StartVM failed: %+v", err)
	}

	_, err = alsClient.Restart(ctx, &lc, grpc.WaitForReady(true))
	if err != nil {
		t.Errorf("RestartVM failed: %v", err)
	}

	_, err = alsClient.Stop(ctx, &lc, grpc.WaitForReady(true))
	if err != nil {
		t.Errorf("StopVM failed: %v", err)
	}

	callUndeployAPI(t, conn, id)
}
