// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package cni

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/kata-containers/runtime/virtcontainers/pkg/nsenter"
	evapb "github.com/open-ness/edgenode/pkg/eva/pb"
)

var (
	defaultCniBinDir = "/opt/cni/bin"
	hostNSPath       = "/var/host_ns/net"
)

// Action defines CNI Action type
type Action string

const (
	// Add corresponds to CNI_COMMAND=ADD
	Add Action = "ADD"
	// Del corresponds to CNI_COMMAND=DEL
	Del Action = "DEL"
	// Check corresponds to CNI_COMMAND=CHECK
	Check Action = "CHECK"
	// Version corresponds to CNI_COMMAND=VERSION
	Version Action = "VERSION"
)

// Invoker is a type for storing CNI execution parameters and executing the CNI
type Invoker struct {
	infraCtr InfrastructureContainerInfo
	cniConf  *evapb.CNIConfiguration
	action   Action
	name     string
}

// NewCNIInvoker creates new Invoker object
func NewCNIInvoker(infrastructureContainer InfrastructureContainerInfo,
	cniConf *evapb.CNIConfiguration, action Action) *Invoker {
	return &Invoker{
		infraCtr: infrastructureContainer,
		cniConf:  cniConf,
		action:   action,
	}
}

// GetTypeFromCNIConfig parses CNI configuration (JSON format) looking for field 'type' and returns its value
func GetTypeFromCNIConfig(cniConfig string) (string, error) {
	var cni struct {
		Type string `json:"type"`
	}

	if err := json.Unmarshal([]byte(cniConfig), &cni); err != nil {
		return "", err
	}

	if cni.Type == "" {
		return "", errors.New("CNI type not found or empty")
	}

	return cni.Type, nil
}

func (c *Invoker) constructEnvs() []string {
	return []string{
		fmt.Sprintf("CNI_CONTAINERID=%s", c.infraCtr.ID),
		fmt.Sprintf("CNI_NETNS=/proc/%d/ns/net", c.infraCtr.PID),
		fmt.Sprintf("CNI_COMMAND=%s", c.action),
		fmt.Sprintf("CNI_ARGS=%s", c.cniConf.Args),
		fmt.Sprintf("CNI_PATH=%s", c.cniConf.Path),
		fmt.Sprintf("CNI_IFNAME=%s", c.cniConf.InterfaceName),
	}
}

func (c *Invoker) runCmdAndGetOutput(cmd *exec.Cmd) (string, string, error) {
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = strings.NewReader(c.cniConf.CniConfig)

	log.Debugf("Invoker: running cmd")
	err := cmd.Run()

	return stdout.String(), stderr.String(), err
}

func (c *Invoker) createCmd() (*exec.Cmd, error) {
	if c.cniConf == nil {
		log.Errf("Invoker: cniConf is nil")
		return nil, errors.New("cniConf is nil")
	}

	cniType, err := GetTypeFromCNIConfig(c.cniConf.CniConfig)
	if err != nil {
		log.Errf("Invoker: failed to get type: %s", err.Error())
		return nil, err
	}
	c.name = cniType

	path := filepath.Join(defaultCniBinDir, cniType)
	cmd := exec.Command(path)
	cmd.Env = append(os.Environ(), c.constructEnvs()...)

	return cmd, nil
}

// Invoke runs the CNI executable
func (c *Invoker) Invoke() (string, error) {
	cmd, err := c.createCmd()
	if err != nil {
		log.Errf("Invoker: failed to construct cmd. Reason='%s'", err.Error())
		return "", err
	}

	var sout, serr string
	ns := []nsenter.Namespace{{Path: hostNSPath, Type: nsenter.NSTypeNet}}
	err = nsenter.NsEnter(ns, func() error {
		var err error
		sout, serr, err = c.runCmdAndGetOutput(cmd)
		return err
	})

	if err != nil {
		log.Errf("Invoker: failed to run cmd. Reason='%s', stdout='%s', stderr='%s'", err.Error(), sout, serr)
		return "", err
	}

	log.Debugf("Invoker: cni successfully executed. stdout='%s', stderr='%s'", sout, serr)

	return sout, err
}
