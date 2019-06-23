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
	"os"
	"os/exec"
	"time"

	"github.com/pkg/errors"
	"github.com/smartedgemec/appliance-ce/pkg/ela/ini"
	pb "github.com/smartedgemec/appliance-ce/pkg/ela/pb"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

type InterfacesData struct {
	TrafficPolicies   []*pb.TrafficPolicy
	NetworkInterfaces *pb.NetworkInterfaces
}

const (
	ntsContainerName = "nts"
	ntsVhostFile     = "/var/lib/appliance/nts/usvhost-1"
	dnsContainerName = "mec-app-edgednssvr"
)

var (
	InterfaceConfigurationData = InterfacesData{}

	ntsConfigTemplate = ini.NtsConfig{
		VMCommon: ini.VMCommon{
			Max:      32,
			Number:   2,
			VHostDev: ntsVhostFile,
		},
		NtsServer: ini.NtsServer{
			ControlSocket: "/var/lib/appliance/nts/control-socket",
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
	for _, netIf := range data.NetworkInterfaces.NetworkInterfaces {
		for _, policy := range data.TrafficPolicies {
			if policy.Id == netIf.Id {
				d[netIf.Id] = interfaceData{policy, netIf}
				continue OUTER
			}
		}

		d[netIf.Id] = interfaceData{
			NetworkInterface: netIf,
			TrafficPolicy:    &pb.TrafficPolicy{Id: netIf.Id},
		}
	}

	return d, nil
}

type interfaceData struct {
	TrafficPolicy    *pb.TrafficPolicy
	NetworkInterface *pb.NetworkInterface
}

func startContainer(ctx context.Context, containerName string) error {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return err
	}

	return cli.ContainerStart(ctx, containerName, types.ContainerStartOptions{})
}

func stopContainer(ctx context.Context, containerName string) error {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return err
	}

	timeout := 10 * time.Second
	return cli.ContainerStop(ctx, containerName, &timeout)
}

func isNTSrunning(ctx context.Context) error {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return err
	}

	containerData, err := cli.ContainerInspect(ctx, ntsContainerName)
	if err != nil {
		return err
	}

	if containerData.State.Running {
		return nil
	}

	return errors.New("NTS container is not running, status: " +
		containerData.State.Status)
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

	// #nosec G204 - bindParams controlled and checked above
	cmd := exec.Command("/root/dpdk-devbind.py", bindParams...)
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "devices bind failure: %v", out.String())
	}
	return nil
}

func stopDNSAndRemoveRules(ctx context.Context) error {
	if err := stopContainer(ctx, dnsContainerName); err != nil {
		return errors.Wrap(err, "failed to stop Edge DNS")
	}

	if err := isNTSrunning(ctx); err == nil {
		trafficPolicy := pb.TrafficPolicy{Id: dnsContainerName}

		_, err := DialEDASet(ctx, &trafficPolicy, Config.EDAEndpoint)
		if err != nil {
			return errors.Wrap(err,
				"failed to remove TrafficRules for Edge DNS")
		}
	}

	return nil

}

func restartDNSAndSetRules(ctx context.Context) error {
	if err := startContainer(ctx, dnsContainerName); err != nil {
		return errors.Wrap(err, "failed to start Edge DNS")
	}

	var err error
	dnsKNImac := ""

	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		if err = ctx.Err(); err != nil {
			return errors.Wrap(err,
				"context error while waiting for Edge DNS KNI")
		}

		dnsKNImac, err = getMACForContainerKNI(ctx, dnsContainerName)
		if err == nil {
			break
		}
	}

	trafficPolicy := pb.TrafficPolicy{
		Id: dnsContainerName,
		TrafficRules: []*pb.TrafficRule{
			{
				Description: "Edge DNS svr - IP traffic",
				Priority:    5,
				Destination: &pb.TrafficSelector{
					Ip: &pb.IPFilter{
						Address: Config.DNSIP,
						Mask:    32,
					}},
				Target: &pb.TrafficTarget{
					Mac: &pb.MACModifier{MacAddress: dnsKNImac},
				},
			},
			{
				Description: "Edge DNS svr - LTE traffic",
				Priority:    5,
				Source: &pb.TrafficSelector{
					Gtp: &pb.GTPFilter{
						Address: "0.0.0.0",
						Mask:    0,
					},
				},
				Destination: &pb.TrafficSelector{
					Ip: &pb.IPFilter{
						Address: Config.DNSIP,
						Mask:    32,
					}},
				Target: &pb.TrafficTarget{
					Mac: &pb.MACModifier{MacAddress: dnsKNImac},
				},
			},
		}}

	_, err = DialEDASet(ctx, &trafficPolicy, Config.EDAEndpoint)
	if err != nil {
		return errors.Wrap(err, "failed to set TrafficRules for Edge DNS")
	}

	return nil
}

func waitForNTS(ctx context.Context) error {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err := isNTSrunning(ctx); err != nil {
			return err
		}

		if _, err := os.Stat(ntsVhostFile); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return errors.Wrap(err, "failed to stat NTS' usvhost file")
		}
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

	if err := stopDNSAndRemoveRules(ctx); err != nil {
		return errors.Wrap(err, "failed to stop Edge DNS")
	}

	if err := stopContainer(ctx, ntsContainerName); err != nil {
		return errors.Wrap(err, "failed to stop NTS")
	}

	if err := rebindDevices(ntsCfg); err != nil {
		return errors.Wrap(err, "failed to rebind devices")
	}

	if err := startContainer(ctx, ntsContainerName); err != nil {
		return errors.Wrap(err, "failed to start NTS")
	}

	InterfaceConfigurationData = InterfacesData{}

	if err := waitForNTS(ctx); err != nil {
		return err
	}

	return restartDNSAndSetRules(ctx)
}
