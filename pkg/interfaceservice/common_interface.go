// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package interfaceservice

import (
	"os"
	"regexp"
	"strings"

	pb "github.com/open-ness/edgenode/pkg/interfaceservice/pb"
	"github.com/pkg/errors"
)

const (
	defaultDpdkDriver  = "igb_uio"
	netdevBridgeOption = "netdev"
)

var devbindInterfacesInfo []string

// updateDPDKDevbindOutput get an info from dpdk-devbind.py script. It
// stores lines starting with PCI address like: XXXX:XX:XX.X only.
func updateDPDKDevbindOutput() {
	devbindOutput, _ := Devbind("--status")
	devbindInterfacesInfo = regexp.MustCompile(`[0-9a-fA-F]{4}(:[0-9a-fA-F]{2}){2}.\d .*`).
		FindAllString(string(devbindOutput), -1)
	for i := range devbindInterfacesInfo {
		devbindInterfacesInfo[i] = strings.TrimSpace(devbindInterfacesInfo[i])
	}
}

// getPortDrivers returns current driver and list of unused drivers
func getPortDrivers(pci string) (string, []string) {
	if !DpdkEnabled {
		return "kernel", nil
	}

	portInfo := getLineFromDevbindInterfacesInfo(pci)

	if len(portInfo) > 0 {
		drv := getListValues(portInfo, "drv")
		unused := getListValues(portInfo, "unused")
		if drv != nil {
			currentDrv := drv[0]
			return currentDrv, unused
		}
		return "", unused
	}
	return "", nil
}

// getLineFromDevbindInterfacesInfo gets port's info from devbindInterfacesInfo
func getLineFromDevbindInterfacesInfo(pci string) string {
	for _, str := range devbindInterfacesInfo {
		if strings.HasPrefix(str, pci) {
			return str
		}
	}
	return ""
}

// getListValues uses regexp to create list of drivers
func getListValues(portInfo string, value string) []string {
	r, _ := regexp.Compile(value + "=[^ ]*")
	drvFull := r.FindStringSubmatch(portInfo)
	if len(drvFull) > 0 {
		drvSplit := strings.Split(drvFull[0], "=")
		return strings.Split(drvSplit[1], ",")
	}
	return nil
}

func findDrvToBind(port pb.Port, current string,
	unused []string) (string, error) {

	drvIdx := 0
	if port.Driver == pb.Port_USERSPACE {
		if current == defaultDpdkDriver {
			return "", errors.New("Could not bind device " + port.Pci + " to DPDK driver - device already binded")
		}

		found := false
		for idx, driver := range unused {
			if driver == defaultDpdkDriver {
				found = true
				drvIdx = idx
				break
			}
		}
		if !found {
			return "", errors.New("Port " + port.Pci + " cannot use DPDK enabled driver")
		}
	} else {
		if current != defaultDpdkDriver {
			return "", nil
		}

		found := false
		for idx, driver := range unused {
			if driver != defaultDpdkDriver {
				found = true
				drvIdx = idx
				break
			}
		}

		if !found {
			return "", errors.New("Port " + port.Pci + " cannot use kernel driver")
		}
	}
	return unused[drvIdx], nil
}

// bindDriver binds driver to port
func bindDriver(port pb.Port) error {
	current, unused := getPortDrivers(port.Pci)
	if current == "" && unused == nil {
		return errors.New(port.Pci + ": no such device")
	} else if current == "" {
		return errors.New("Device: " + port.Pci + " is not binded to any driver.")
	}

	drv, err := findDrvToBind(port, current, unused)
	if err != nil {
		return err
	}
	if drv != "" {
		_, err := Devbind("-b", drv, port.Pci)
		if err == nil {
			log.Info("Port ", port.Pci, " binded to drver ", drv)
		}
		return err
	}
	return nil
}

// getPortName returns port name
func getPortName(pci string) (string, error) {
	current, _ := getPortDrivers(pci)

	if current == defaultDpdkDriver {
		return getDpdkPortName(pci, "")
	} else if current != "" {
		devs, err := KernelNetworkDevicesProvider()
		if err != nil {
			return "", err
		}
		for _, dev := range devs {
			if dev.PCI == pci {
				return dev.Name, nil
			}
		}
	}

	return "", errors.New("Failed to get interface's name - interface may be not binded to any driver")
}

// getOvsBridgeType returns datapath_type for selected bridge, return value may be netdev or ""
func getOvsBridgeType(bridge string) (string, error) {
	output, err := Vsctl("get", "bridge", bridge, "datapath_type")
	if err != nil {
		return "", errors.Wrapf(err, "Couldn't get bridge %s", bridge)
	}
	outputTrim := strings.TrimRight(string(output), "\r\n")
	return outputTrim, err
}

// validatePort validates port's data
func validatePort(port pb.Port) error {
	pciRegexp := "[0-9]{0,4}:[0-9a-f]{2}:[0-9a-f]{2}\\.[0-9a-f]{1}$"
	isPciValid, _ := regexp.MatchString(pciRegexp, port.Pci)
	if !isPciValid {
		return errors.New("PCI address " + port.Pci + " is invalid")
	}

	if len(port.Bridge) == 0 {
		return errors.New("Bridge has been not provided")
	}

	if port.Driver != pb.Port_USERSPACE && port.Driver != pb.Port_KERNEL {
		return errors.New("Driver has to be 'kernel' or 'dpdk'")
	}

	return nil
}

// reattachDpdkPorts will reattach DPDK ports that were broken during machine restart
func reattachDpdkPorts() error {
	if _, err := Vsctl("show"); err != nil {
		log.Errf("Couldn't perform ovs-vsctl show. Exiting...")
		os.Exit(1)
	}

	log.Info("Trying to reattach ports if existed previously...")

	bridges, err := Vsctl("list-br")
	if err != nil {
		log.Info("Error listing bridges: ", err.Error())
		return err
	}

	brList := trimVsctlOutput(bridges)

	for _, bridge := range brList {
		if brType, _ := getOvsBridgeType(bridge); brType != netdevBridgeOption {
			continue
		}
		allIfs, _ := Vsctl("list-ifaces", bridge)
		ifsList := trimVsctlOutput(allIfs)
		for _, ifs := range ifsList {
			ifErr, errIfs := Vsctl("get", "interface", ifs, "error")
			if errIfs != nil {
				log.Info("Error getting interface ", ifs, ":", errIfs.Error())
				continue
			}
			if strings.Contains(string(ifErr), "Error attaching device") {
				pciList := regexp.MustCompile(`\d{4}(:\d{2}){2}\.\d`).FindAllString(string(ifErr), 1)
				if len(pciList) > 0 {
					updateDPDKDevbindOutput()
					currentDriver, _ := getPortDrivers(pciList[0])
					if currentDriver != "igb_uio" {
						log.Info("Port ", pciList[0], " will be reattached to bridge ", bridge)

						tmpPort := &pb.Port{
							Bridge: bridge,
							Pci:    pciList[0],
							Driver: pb.Port_USERSPACE,
						}

						if err = detachPortFromOvs(*tmpPort); err != nil {
							log.Info("Error detaching port: ", err.Error())
							continue
						}

						if err = attachPortToOvs(*tmpPort); err != nil {
							log.Info("Error attaching port: ", err.Error())
							continue
						}

						log.Info("Port ", pciList[0], " successfully reattached to bridge ", bridge)
					}
				}
			}
		}
	}

	return err
}

func trimVsctlOutput(output []byte) []string {
	outSplit := strings.Split(strings.TrimRight(string(output), "\r\n"), "\n")
	var result []string
	for _, value := range outSplit {
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}
