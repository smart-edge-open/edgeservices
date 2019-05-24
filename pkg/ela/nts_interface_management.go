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

package ela

import (
	"bytes"
	"context"
	"os/exec"
	"time"

	"github.com/pkg/errors"
	"github.com/smartedgemec/appliance-ce/pkg/ela/ini"
	"github.com/smartedgemec/appliance-ce/pkg/ela/pb"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

type InterfacesData struct {
	TrafficPolicies   []*pb.TrafficPolicy
	NetworkInterfaces *pb.NetworkInterfaces
}

var (
	InterfaceConfigurationData = InterfacesData{}

	ntsConfigTemplate = ini.NtsConfig{
		VMCommon: ini.VMCommon{
			Max:      32,
			Number:   2,
			VHostDev: "/var/lib/nts/usvhost-1",
		},
		NtsServer: ini.NtsServer{
			ControlSocket: "/var/lib/nts/control-socket",
		},
		KNI: ini.KNI{
			Max: 32,
		},
		Ports: nil,
	}
)

func (data *InterfacesData) validate() error {
	if data == nil {
		return errors.New("Configuration data is nil")
	}

	if data.NetworkInterfaces == nil {
		return errors.New("network interfaces are nil")
	}

	return nil
}

func (data *InterfacesData) toMap() (map[string]interfaceData, error) {
	d := make(map[string]interfaceData)

OUTER:
	for _, policy := range data.TrafficPolicies {
		for _, netIf := range data.NetworkInterfaces.NetworkInterfaces {
			if policy.Id == netIf.Id {
				d[policy.Id] = interfaceData{policy, netIf}
				continue OUTER
			}
		}

		return nil, errors.Errorf("NetworkInterface with PCI %s not found",
			policy.Id)
	}

	return d, nil
}

type interfaceData struct {
	TrafficPolicy    *pb.TrafficPolicy
	NetworkInterface *pb.NetworkInterface
}

func startNTS(ctx context.Context) error {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return err
	}

	return cli.ContainerStart(ctx, "nts", types.ContainerStartOptions{})
}

func stopNTS(ctx context.Context) error {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return err
	}

	timeout := 10 * time.Second
	return cli.ContainerStop(ctx, "nts", &timeout)
}

func isAnyAppRunning() (bool, error) {
	// TODO: implement
	return false, nil
}

func makeNtsConfig(data map[string]interfaceData) (*ini.NtsConfig, error) {
	cfg := ntsConfigTemplate

	for pci, d := range data {
		port := ini.Port{}
		if err := port.UpdateFromTrafficPolicy(d.TrafficPolicy); err != nil {
			return nil, errors.Wrapf(err,
				"failed to create port from traffic policy (pci: %s)", pci)
		}

		if err := port.UpdateFromNetworkInterface(
			d.NetworkInterface); err != nil {
			return nil, errors.Wrapf(err,
				"failed to create port from network interface (pci: %s)", pci)
		}

		cfg.AddNewPort(port)
	}

	cfg.Update()

	return &cfg, nil
}

func rebindDevices(nts *ini.NtsConfig) error {
	var bindParams []string
	bindParams = append(bindParams, "-b", "igb_uio")
	for _, port := range nts.Ports {
		bindParams = append(bindParams, port.PciAddress)
	}

	if len(bindParams) == 2 {
		return nil
	}

	cmd := exec.Command("/root/dpdk-devbind.py", bindParams...)
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "devices bind failure: %v", out.String())
	}
	return nil
}

func configureNTS(ctx context.Context) error {
	if err := InterfaceConfigurationData.validate(); err != nil {
		return errors.Wrap(err, "invalid configuration data")
	}

	mappedConfig, mapErr := InterfaceConfigurationData.toMap()
	if mapErr != nil {
		return errors.Wrap(mapErr, "failed to map traffic policies "+
			"to network interfaces")
	}

	if anyAppRunning, err := isAnyAppRunning(); err != nil {
		return errors.Wrap(err, "failed to check if any app is running")
	} else if anyAppRunning {
		return errors.New("there's at least 1 app currently running")
	}

	ntsCfg, cfgErr := makeNtsConfig(mappedConfig)
	if cfgErr != nil {
		return errors.Wrap(cfgErr, "failed to make new NTS config")
	}

	if err := ntsCfg.SaveToFile(Config.NtsConfigPath); err != nil {
		return errors.Wrap(err, "failed to write new NTS config")
	}

	if err := stopNTS(ctx); err != nil {
		return errors.Wrap(err, "failed to stop NTS")
	}

	if err := rebindDevices(ntsCfg); err != nil {
		return errors.Wrap(err, "failed to rebind devices")
	}

	if err := startNTS(ctx); err != nil {
		return errors.Wrap(err, "failed to start NTS")
	}

	InterfaceConfigurationData = InterfacesData{}

	return nil
}
