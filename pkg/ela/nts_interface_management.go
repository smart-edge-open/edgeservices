// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package ela

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"time"

	"github.com/open-ness/edgenode/pkg/ela/ini"
	pb "github.com/open-ness/edgenode/pkg/ela/pb"
	"github.com/pkg/errors"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// InterfacesData describes data for interfaces
type InterfacesData struct {
	TrafficPolicies   map[string]*pb.TrafficPolicy
	NetworkInterfaces *pb.NetworkInterfaces
}

const (
	ntsContainerName = "nts"
	ntsVhostFile     = "/var/lib/appliance/nts/qemu/usvhost-1"
	dnsContainerName = "mec-app-edgednssvr"
)

var (
	// InterfaceConfigurationData interface configuration data
	InterfaceConfigurationData = InterfacesData{
		TrafficPolicies: map[string]*pb.TrafficPolicy{},
	}

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

		// Skip KERNEL driver interfaces
		if netIf.Driver == pb.NetworkInterface_KERNEL {
			continue
		}

		if policy, ok := data.TrafficPolicies[netIf.Id]; ok {
			d[netIf.Id] = interfaceData{policy, netIf}
			continue OUTER
		}

		d[netIf.Id] = interfaceData{
			NetworkInterface: netIf,
			TrafficPolicy:    &pb.TrafficPolicy{Id: netIf.Id},
		}
	}

	return d, nil
}

func (data *InterfacesData) getDevicesToUnbind() ([]string, error) {
	nis, err := GetInterfaces()
	if err != nil {
		return nil, err
	}

	var pcis []string

	for _, ifaceUpdate := range data.NetworkInterfaces.NetworkInterfaces {
		for _, ifaceCurrent := range nis.NetworkInterfaces {

			if ifaceUpdate.Id == ifaceCurrent.Id {
				// Unbind only if change is from USERSPACE to KERNEL
				if ifaceUpdate.Driver == pb.NetworkInterface_KERNEL &&
					ifaceCurrent.Driver == pb.NetworkInterface_USERSPACE {

					pcis = append(pcis, ifaceUpdate.Id)
				}
			}
		}
	}

	return pcis, nil
}

func (data *InterfacesData) getDevicesToBind() []string {
	var pcis []string

	for _, ifaceUpdate := range data.NetworkInterfaces.NetworkInterfaces {
		if ifaceUpdate.Driver == pb.NetworkInterface_USERSPACE {
			pcis = append(pcis, ifaceUpdate.Id)
		}
	}

	return pcis
}

type interfaceData struct {
	TrafficPolicy    *pb.TrafficPolicy
	NetworkInterface *pb.NetworkInterface
}

func updateContainer(ctx context.Context, containerName string, updateConfig container.UpdateConfig) (container.ContainerUpdateOKBody, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return container.ContainerUpdateOKBody{}, err
	}

	return cli.ContainerUpdate(ctx, containerName, updateConfig)
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
		cli.Close()
		return err
	}

	containerData, err := cli.ContainerInspect(ctx, ntsContainerName)
	if err != nil {
		cli.Close()
		return err
	}

	if containerData.State.Running {
		cli.Close()
		return nil
	}

	cli.Close()
	return errors.New("NTS container is not running, status: " +
		containerData.State.Status)
}

func isAnyAppRunning() (bool, error) {
	// TODO: implement
	return false, nil
}

func makeAndSaveNtsConfig(data map[string]interfaceData,
	filePath string) error {

	cfg := ntsConfigTemplate

	for pci, d := range data {
		port := ini.Port{MTU: Config.InterfaceMTU}
		if err := port.UpdateFromTrafficPolicy(d.TrafficPolicy); err != nil {
			return errors.Wrapf(err,
				"failed to create port from traffic policy (pci: %s)", pci)
		}

		if err := port.UpdateFromNetworkInterface(
			d.NetworkInterface); err != nil {
			return errors.Wrapf(err,
				"failed to create port from network interface (pci: %s)", pci)
		}

		cfg.AddNewPort(port)
	}

	cfg.Update()

	return cfg.SaveToFile(Config.NtsConfigPath)
}

func rebindDevices(pcis []string,
	driver pb.NetworkInterface_InterfaceDriver) error {

	var bindParams []string

	if driver == pb.NetworkInterface_KERNEL {
		bindParams = append(bindParams, "-b", "none")
	} else {
		bindParams = append(bindParams, "-b", "igb_uio")
	}

	bindParams = append(bindParams, pcis...)

	if len(bindParams) == 2 {
		return nil
	}

	// #nosec G204 - bindParams controlled and checked above
	cmd := exec.Command("./dpdk-devbind.py", bindParams...)
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
	_, err := updateContainer(ctx, dnsContainerName,
		container.UpdateConfig{
			Resources: container.Resources{
				CPUShares:  1024,      // Default value
				Memory:     134217728, // 128 MiB
				MemorySwap: 134217728, // 128 MiB
				PidsLimit:  100,
			},
		})
	if err != nil {
		return errors.Wrap(err, "failed to update Edge DNS container")
	}

	if err := startContainer(ctx, dnsContainerName); err != nil {
		return errors.Wrap(err, "failed to start Edge DNS")
	}

	dnsKNImac := ""

	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		if err = ctx.Err(); err != nil {
			return errors.Wrap(err,
				"context error while waiting for Edge DNS KNI")
		}

		if err = isNTSrunning(ctx); err != nil {
			return errors.Wrap(err, "NTS failed to start")
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
			return errors.Wrap(err, "NTS failed to start")
		}

		if _, err := os.Stat(ntsVhostFile); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return errors.Wrap(err, "failed to stat NTS' usvhost file")
		}
	}

	return nil
}

func startNTSandDNS(ctx context.Context) error {
	_, err := updateContainer(ctx, ntsContainerName,
		container.UpdateConfig{
			Resources: container.Resources{
				CPUShares:  1024,      // Default value
				Memory:     134217728, // 128 MiB
				MemorySwap: 134217728, // 128 MiB
				PidsLimit:  100,
			},
		})
	if err != nil {
		return errors.Wrap(err, "failed to update NTS container")
	}

	if err := startContainer(ctx, ntsContainerName); err != nil {
		return errors.Wrap(err, "failed to start NTS")
	}

	InterfaceConfigurationData.NetworkInterfaces = nil

	if err := waitForNTS(ctx); err != nil {
		return errors.Wrap(err, "NTS did not start fully")
	}

	return restartDNSAndSetRules(ctx)
}

func configureNTS(ctx context.Context) error {
	if err := InterfaceConfigurationData.validate(); err != nil {
		return errors.Wrap(err, "invalid configuration data")
	}

	devsToUnbind, err := InterfaceConfigurationData.getDevicesToUnbind()
	if err != nil {
		return errors.Wrap(err, "failed to get list of devices to unbind")
	}

	devsToBind := InterfaceConfigurationData.getDevicesToBind()

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

	if err := makeAndSaveNtsConfig(mappedConfig,
		Config.NtsConfigPath); err != nil {

		return errors.Wrap(err, "failed to make new NTS config")
	}

	if err := stopDNSAndRemoveRules(ctx); err != nil {
		return errors.Wrap(err, "failed to stop Edge DNS")
	}

	if err := stopContainer(ctx, ntsContainerName); err != nil {
		return errors.Wrap(err, "failed to stop NTS")
	}

	if err := rebindDevices(devsToUnbind,
		pb.NetworkInterface_KERNEL); err != nil {
		return errors.Wrapf(err,
			"failed to unbind devices: %v", devsToUnbind)
	}

	if err := rebindDevices(devsToBind,
		pb.NetworkInterface_USERSPACE); err != nil {
		return errors.Wrapf(err, "failed to bind devices to DPDK driver: %v",
			devsToBind)
	}

	return startNTSandDNS(ctx)
}
