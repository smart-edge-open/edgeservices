// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package ela

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	libvirt "github.com/libvirt/libvirt-go"
	libvirtxml "github.com/libvirt/libvirt-go-xml"
	"github.com/pkg/errors"
)

// MACFetcherImpl is a MACAddressProvider which allows to get MAC of
// libvirt Domain's vHostUser interface or Docker container's KNI
type MACFetcherImpl struct{}

// GetMacAddress function tries to fetch a MAC for domain or container
// with given ID
func (*MACFetcherImpl) GetMacAddress(ctx context.Context,
	appID string) (string, error) {

	// TODO: Check app's metadata to decide which daemon should be asked for MAC

	log.Infof("GetMacAddress for: %s", appID)

	mac, err := getMACForVMvhostuser(appID)
	if err == nil {
		return mac, nil
	}
	log.Infof("GetMacAddress for: %s. VM error: %v", appID, err)

	mac, err = getMACForContainerKNI(ctx, appID)
	if err == nil {
		return mac, nil
	}
	log.Infof("GetMacAddress for: %s. Docker error: %v", appID, err)

	return "", errors.New("MAC address not found for: " + appID)
}

func getMACForVMvhostuser(appID string) (string, error) {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return "", err
	}
	defer func() {
		if c, err1 := conn.Close(); err1 != nil || c < 0 {
			log.Errf("Failed to close libvirt connection: code: %v, error: %v",
				c, err1)
		}
	}()

	virtDomain, err := conn.LookupDomainByName(appID)
	if err != nil {
		return "", err
	}
	defer func() { _ = virtDomain.Free() }()

	xmlDump, err := virtDomain.GetXMLDesc(0)
	if err != nil {
		return "", err
	}

	domcfg := &libvirtxml.Domain{}
	err = domcfg.Unmarshal(xmlDump)
	if err != nil {
		return "", err
	}

	for _, iface := range domcfg.Devices.Interfaces {
		if iface.Source.VHostUser != nil {
			return iface.MAC.Address, nil
		}
	}

	return "", errors.New("Interface not found")
}

func getNetNamespaceForContainer(ctx context.Context,
	appName string) (string, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return "", err
	}

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return "", err
	}

	for _, c := range containers {
		if len(c.Names) == 0 {
			continue
		}

		cj, inspectErr := cli.ContainerInspect(ctx, c.ID)
		if inspectErr != nil {
			log.Debugf("Failed to inspect the container: " + inspectErr.Error())
			continue
		}

		if c.Names[0][1:] == appName {
			return cj.NetworkSettings.SandboxKey, nil
		}

		if cj.Config == nil {
			continue
		}

		// Extracting SandboxKey for K8s pods
		if appID, ok := cj.Config.Labels["app-id"]; ok && appID == appName {
			return cj.NetworkSettings.SandboxKey, nil
		}
	}

	return "", errors.New("Container not found")
}

func getMACForContainerKNI(ctx context.Context, appID string) (string, error) {
	nsPath, err := getNetNamespaceForContainer(ctx, appID)
	if err != nil {
		return "", err
	}

	// TODO: Find a proper solution
	// Temporary workaround for appliance not being able to
	// access containers' network namespaces.
	// First enter host's mount namespace, then enter container's net namespace,
	// then obtain vEth mac address from ip link
	cmdline := fmt.Sprintf("nsenter --mount=/var/host_ns/mnt "+
		"nsenter --net=%s "+
		"ip link | grep vEth -A1 | awk '/ether/ {print $2}'", nsPath)

	// nolint cmdline is constant
	cmd := exec.Command("bash", "-c", cmdline)
	var out bytes.Buffer
	cmd.Stdout = &out

	err = cmd.Run()
	if err != nil {
		return "", errors.Wrap(err, "failed to obtain mac")
	}

	mac := strings.Trim(out.String(), "\n")

	if mac == "" {
		return "", errors.New("vEth interface not found")
	}

	return mac, nil
}
