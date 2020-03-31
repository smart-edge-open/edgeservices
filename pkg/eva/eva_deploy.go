// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

package eva

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"time"

	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/golang/protobuf/ptypes/empty"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"

	libvirtxml "github.com/libvirt/libvirt-go-xml"

	"github.com/open-ness/edgenode/internal/wrappers"
	metadata "github.com/open-ness/edgenode/pkg/app-metadata"
	"github.com/open-ness/edgenode/pkg/cni"
	pb "github.com/open-ness/edgenode/pkg/eva/pb"
	"github.com/open-ness/edgenode/pkg/ovncni"
	"github.com/pkg/errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	libvirt "github.com/libvirt/libvirt-go"

	"github.com/digitalocean/go-openvswitch/ovs"
	"github.com/digitalocean/go-openvswitch/ovsdb"

	"github.com/docker/go-connections/nat"
)

// DeploySrv describes deplyment
type DeploySrv struct {
	cfg  *Config
	meta *metadata.AppMetadata
}

const (
	// InterfaceTypeDpdk defines ovs interface type used to set a port up
	interfaceTypeDpdk ovs.InterfaceType = "dpdkvhostuserclient"

	// ovsDbSocket defines a path, where ovs db socket persist
	ovsDbSocket = "/usr/local/var/run/openvswitch/db.sock"

	// ovsPath defines a path to ovs tmp folder, where all port sockers are
	// placed into
	ovsPath = "/tmp/openvswitch"
)

var httpMatcher = regexp.MustCompile("^http://.")
var httpsMatcher = regexp.MustCompile("^https://.")

// EACHandler - the type for the generic Enhanced App Confuration handler
type EACHandler func(string, interface{}, interface{})

// EACHandlersDocker - Table of EACHandlers for the Docker backend
var EACHandlersDocker = map[string]EACHandler{
	"hddl":      handleHddl,
	"env_vars":  handleEnvVars,
	"cmd":       handleCmd,
	"mount":     handleMountContainer,
	"cpu_pin":   handleCPUPinContainer,
	"sriov_nic": handleContainerNicSriov,
}

// EACHandlersVM - Table of EACHandlers for the Libvirt backend
var EACHandlersVM = map[string]EACHandler{
	"cpu_pin":   handleCPUPinVM,
	"sriov_nic": handleVmNicSriov,
}

func downloadImage(ctx context.Context, url string,
	target string) error {

	var input io.Reader

	if httpMatcher.MatchString(url) {
		return fmt.Errorf("HTTP image path unsupported as insecure, " +
			"please use HTTPS")
	} else if httpsMatcher.MatchString(url) {
		request, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return err
		}
		request = request.WithContext(ctx)

		client := wrappers.CreateHTTPClient()

		resp, err := client.Do(request)
		if err != nil {
			return err
		}

		defer func() {
			if err1 := resp.Body.Close(); err1 != nil {
				log.Errf("Failed to close body reader from %s: %v", url, err1)
			}
		}()

		if resp.StatusCode != 200 {
			return fmt.Errorf("unexpected HTTP code %v returned",
				resp.StatusCode)
		}

		input = resp.Body
	} else {
		file, err := os.Open(filepath.Clean(url))
		if err != nil {
			return err
		}
		defer func() {
			if err1 := file.Close(); err1 != nil {
				log.Errf("Failed to close file %s: %v", url, err1)
			}
		}()

		input = file
	}

	output, err := os.Create(target)
	if err != nil {
		return errors.Wrap(err, "Failed to create image file")
	}
	_, err = io.Copy(output, input)
	if err1 := output.Close(); err == nil {
		err = err1
	}
	log.Infof("Downloaded %v to %v", url, target)

	return err
}

func (s *DeploySrv) checkIfAppNotDeployed(id string) error {
	app2, err := s.meta.Load(id)
	if err == nil && app2.IsDeployed {
		return status.Errorf(codes.AlreadyExists, "app %s already deployed",
			id)
	}

	return nil
}

func (s *DeploySrv) checkDeployPreconditions(dapp *metadata.DeployedApp) error {
	c := s.cfg

	if dapp.App.Cores <= 0 {
		return fmt.Errorf("Cores value incorrect: %v", dapp.App.Cores)
	} else if dapp.App.Cores > c.MaxCores {
		return fmt.Errorf("Cores value over limit: %v > %v",
			dapp.App.Cores, c.MaxCores)
	}

	if dapp.App.Memory <= 0 {
		return fmt.Errorf("Memory value incorrect: %v", dapp.App.Memory)
	} else if dapp.App.Memory > c.MaxAppMem {
		return fmt.Errorf("Memory value over limit: %v > %v",
			dapp.App.Memory, c.MaxAppMem)
	}

	switch uri := dapp.App.Source.(type) {
	case *pb.Application_HttpUri:
		if httpMatcher.MatchString(uri.HttpUri.HttpUri) {
			return fmt.Errorf("HTTP image path unsupported as insecure, " +
				"please use HTTPS")
		}
		dapp.URL = uri.HttpUri.HttpUri
		dapp.App.Source = nil
	default:
		return status.Errorf(codes.Unimplemented, "unknown app source")
	}

	return nil
}

func (s *DeploySrv) deployCommon(ctx context.Context,
	dapp *metadata.DeployedApp) error {

	dapp.App.Status = pb.LifecycleStatus_DEPLOYING

	// Initial save - creates the app directory if needed
	if err := dapp.Save(false); err != nil {
		return errors.Wrap(err, "metadata save failed")
	}

	/* Now download the image. */
	return downloadImage(ctx, dapp.URL, dapp.ImageFilePath())
}

// This function uses named return variables
func parseImageName(body io.Reader) (out string, hadTag bool, err error) {
	parsed := struct {
		Stream string
	}{}

	bytes, err := ioutil.ReadAll(body)
	if err != nil {
		return "", false, errors.Wrap(err,
			"failed to read JSON from docker.ImageLoad()")
	}
	err = json.Unmarshal(bytes, &parsed)

	// Validate output
	if err != nil {
		return "", false, errors.Wrap(err,
			"failed to parse docker image name")
	}
	if parsed.Stream == "" {
		return "", false, fmt.Errorf(
			"failed to parse docker image name: stream empty")
	}
	if !strings.Contains(parsed.Stream, "Loaded image") {
		return "", false, fmt.Errorf(
			"failed to parse docker image name: stream malformed")
	}

	out = strings.Replace(parsed.Stream, "Loaded image ID: ", "", 1)
	if strings.Contains(out, "Loaded image: ") {
		hadTag = true // Image already tagged, we'll need to untag
		out = strings.Replace(out, "Loaded image: ", "", 1)
	}
	out = out[0 : len(out)-1] // cut '\n'

	return out, hadTag, nil
}

func loadImage(ctx context.Context,
	dapp *metadata.DeployedApp, docker wrappers.DockerClient) error {

	/* NOTE: ImageLoad could read directly from our HTTP stream that's
	 * downloading the image, thus removing the need for storing the image as
	 * a file. But store for now for easier debugging. */
	file, err := os.Open(dapp.ImageFilePath())
	if err != nil { /* shouldn't happen as we just wrote it */
		return errors.Wrap(err, "Failed to open image file")
	}

	respLoad, err := docker.ImageLoad(ctx, file, true)
	if err != nil {
		return errors.Wrap(err, "Failed to ImageLoad() the docker image")
	}
	defer func() {
		if err1 := respLoad.Body.Close(); err1 != nil {
			log.Errf("Failed to close docker reader %v", err1)
		}
	}()

	if !respLoad.JSON {
		return fmt.Errorf("No JSON output loading app %s", dapp.App.Id)
	}
	imageName, hadTag, err := parseImageName(respLoad.Body)
	if err != nil {
		return err
	}
	log.Infof("Image '%v' retagged to '%v'", imageName, dapp.App.Id)
	if err = docker.ImageTag(ctx, imageName, dapp.App.Id); err != nil {
		return err
	}
	if hadTag {
		_, err = docker.ImageRemove(ctx, imageName, types.ImageRemoveOptions{})
	}

	return err
}

// DeployContainer deploys a container
func (s *DeploySrv) DeployContainer(ctx context.Context,
	pbapp *pb.Application) (*empty.Empty, error) {

	dapp := s.meta.NewDeployedApp(metadata.Container, pbapp)

	if err := s.checkIfAppNotDeployed(dapp.App.Id); err != nil {
		return nil, err
	}

	if err := s.checkDeployPreconditions(dapp); err != nil {
		return nil, errors.Wrap(err, "preconditions unfulfilled")
	}

	if err := dapp.IsChangeAllowed(pb.LifecycleStatus_DEPLOYING); err != nil {
		return nil, err
	}

	go func() {
		deployCtx, cancel := context.WithTimeout(context.Background(),
			s.cfg.DownloadTimeout.Duration)
		defer cancel()
		s.syncDeployContainer(deployCtx, dapp)
	}()

	return &empty.Empty{}, nil
}

func handleHddl(value string, genericCfg interface{}, additionalCfg interface{}) {
	turnedOn := map[string]bool{"on": true, "yes": true, "enabled": true,
		"y": true, "true": true}
	if _, on := turnedOn[strings.ToLower(value)]; !on {
		return
	}
	log.Infof("HDDL requested (%v), adding mappings.", value)

	hostCfg := genericCfg.(*container.HostConfig)
	devIon := container.DeviceMapping{
		PathOnHost:        "/dev/ion",
		PathInContainer:   "/dev/ion",
		CgroupPermissions: "rmw",
	}
	hostCfg.Resources.Devices = append(hostCfg.Resources.Devices, devIon)
	hostCfg.Binds = append(hostCfg.Binds, "/var/tmp:/var/tmp")
	hostCfg.Binds = append(hostCfg.Binds, "/dev/shm:/dev/shm")
}

// Checks the received core Id list to see if any letters present
func checkForLetters(input string) bool {
	convStrToRune := []rune(input)

	for loopCount := 0; loopCount < len(convStrToRune); loopCount++ {
		if unicode.IsLetter(convStrToRune[loopCount]) {
			return true
		}
	}

	return false
}

func handleCPUPinContainer(value string, genericCfg interface{}, additionalCfg interface{}) {
	isCommaFound := strings.Contains(value, ",")
	isDashFound := strings.Contains(value, "-")

	log.Infof("CPU Pinning settings for Container provided (%v), applying", value)

	// Check that one of the correct string formats was provided
	if (isCommaFound && !isDashFound) || (!isCommaFound && isDashFound) || (!isCommaFound && !isDashFound) {
		// Check that only numbers were provided
		if checkForLetters(value) {
			log.Err("Incorrect core Id found in input, skipping")
			return
		}
		hostCfg := genericCfg.(*container.HostConfig)
		hostCfg.Resources.CpusetCpus = value
		return
	}

	log.Err("Please provide only one input format for CPU pinning, skipping")
}

func processPorts(ports []*pb.PortProto, cfg *container.Config) {
	if cfg.ExposedPorts == nil {
		cfg.ExposedPorts = make(nat.PortSet)
	}
	for _, p := range ports {
		var port nat.Port

		log.Debugf("processing requested port: %d proto: %s\n", p.Port, p.Protocol)
		if p.Port <= 0 {
			log.Infof("processPorts: port %d invalid, skipping", p.Port)
			continue
		}
		if p.Protocol == "" {
			log.Infof("processPorts: protocol empty, skipping")
			continue
		}
		port, err := nat.NewPort(p.Protocol, fmt.Sprintf("%d", p.Port))
		if err != nil {
			log.Warning("Failed to parse ports: %v", err)
			return
		}
		cfg.ExposedPorts[port] = struct{}{}
	}

}

func handleCPUPinVM(value string, genericCfg interface{}, additionalCfg interface{}) {
	hostCfg := genericCfg.(*libvirtxml.Domain)
	totalVMCores := hostCfg.VCPU.Value
	isCommaFound := strings.Contains(value, ",")
	isDashFound := strings.Contains(value, "-")

	log.Infof("CPU Pinning settings for VM provided (%v), applying", value)

	// Check that one of the correct string formats was provided
	if (isCommaFound && !isDashFound) || (!isCommaFound && isDashFound) || (!isCommaFound && !isDashFound) {
		// Check the only numbers were provided
		if checkForLetters(value) {
			log.Err("Incorrect core Id found in input, skipping")
			return
		}
		for coreIDIndex := 0; coreIDIndex < totalVMCores; coreIDIndex++ {
			vcpuPin := libvirtxml.DomainCPUTuneVCPUPin{
				VCPU:   uint(coreIDIndex),
				CPUSet: value,
			}
			hostCfg.CPUTune.VCPUPin = append(hostCfg.CPUTune.VCPUPin, vcpuPin)
		}
		return
	}

	log.Err("Please provide only one input format for CPU Pinning, skipping")
}

func handleEnvVars(value string, genericCfg interface{}, additionalCfg interface{}) {
	envSettings := strings.Split(value, ";")
	log.Infof("Environment settings provided (%v), setting", value)

	for _, setting := range envSettings {
		// Check that each variable provided is set to a value and
		// only one variable has been provided per semi-colon
		if strings.Count(setting, "=") != 1 {
			log.Errf("Variable is not set correctly (%v), skipping", setting)
			continue
		}

		// Check that the environment variable name has been set
		isVarNameSet := strings.Index(setting, "=")
		if isVarNameSet == 0 {
			log.Errf("Variable name is not provided (%v), skipping", setting)
			continue
		}

		// Check that the environment variable value has been set
		if isVarNameSet == len(setting)-1 {
			log.Errf("Variable value is not provided (%v), skipping", setting)
			continue
		}

		containCfg := additionalCfg.(*container.Config)
		containCfg.Env = append(containCfg.Env, setting)
	}
}

func handleCmd(cmd string, genericCfg interface{}, additionalCfg interface{}) {
	log.Infof("Using command override: %v", cmd)

	containerCfg := additionalCfg.(*container.Config)
	if cmd == "" {
		log.Errf("Command override string is empty, ignoring")
		return
	}

	for _, arg := range strings.Split(cmd, " ") {
		containerCfg.Cmd = append(containerCfg.Cmd, arg)
	}
}

func handleMountContainer(mountString string, genericCfg interface{}, additionalCfg interface{}) {
	hostCfg := genericCfg.(*container.HostConfig)
	if mountString == "" {
		log.Errf("Mount string is empty, ignoring")
		return
	}

	log.Infof("Mount settings for Container provided (%v), applying", mountString)

	split := strings.Split(mountString, ";")
	for _, m := range split {
		pieces := strings.Split(m, ",")
		if len(pieces) == 4 {
			var tb mount.Type
			if strings.ToLower(pieces[0]) == "bind" {
				tb = mount.TypeBind
			} else if strings.ToLower(pieces[0]) == "volume" {
				tb = mount.TypeVolume
			} else {
				log.Errf("Invalid mount type for: %s skipping...", pieces)
				continue
			}

			m := mount.Mount{
				Type:     tb,
				Source:   pieces[1], // Source is the location on the Host
				Target:   pieces[2], // Target is the location on the Container
				ReadOnly: pieces[3] == "true",
			}

			hostCfg.Mounts = append(hostCfg.Mounts, m)
		} else {
			log.Errf("Invalid syntax: ...;type,source,target,readonly;... for entry: %s! skipping...", pieces)
			continue
		}
	}
}

func handleContainerNicSriov(value string, genericCfg interface{}, additionalCfg interface{}) {
	if value == "" {
		log.Errf("SRIOV NIC string is empty, ignoring")
		return
	}
	log.Infof("SRIOV NIC Settings (%v) provided for container, setting", value)

	hostConfig := genericCfg.(*container.HostConfig)
	hostConfig.NetworkMode = container.NetworkMode(value)
}

func handleVmNicSriov(value string, genericCfg interface{}, additionalCfg interface{}) {
	if value == "" {
		log.Errf("SRIOV NIC string is empty, ignoring")
		return
	}
	log.Infof("SRIOV NIC Settings (%v) provided for VM, setting", value)

	pciAddress := strings.Split(value, ":")
	if len(pciAddress) != 3 {
		log.Errf("Incorrect pciAddress provided (%v), skipping", value)
		return
	}

	if len(pciAddress[0]) != 4 {
		log.Errf("Domain address is incorrect (%v), skipping", pciAddress[0])
		return
	}
	domainAddr, err := strconv.ParseUint(pciAddress[0], 16, 0)
	if err != nil {
		log.Errf("Error converting Domain address from string to uint (%v), skipping", err)
		return
	}
	domain := uint(domainAddr)

	if len(pciAddress[1]) != 2 {
		log.Errf("Bus address is incorrect (%v), skipping", pciAddress[1])
		return
	}
	busAddr, err := strconv.ParseUint(pciAddress[1], 16, 0)
	if err != nil {
		log.Errf("Error converting Bus address from string to uint (%v), skipping", err)
		return
	}
	bus := uint(busAddr)

	slotFuncAddr := strings.Split(pciAddress[2], ".")
	if len(slotFuncAddr) != 2 {
		log.Errf("Incorrect slot:function provided (%v), skipping", pciAddress[2])
		return
	}

	if len(slotFuncAddr[0]) != 2 {
		log.Errf("Slot address is incorrect (%v), skipping", slotFuncAddr[0])
		return
	}
	slotAddr, err := strconv.ParseUint(slotFuncAddr[0], 16, 0)
	if err != nil {
		log.Errf("Error converting Slot address from string to uint (%v), skipping", err)
		return
	}
	slot := uint(slotAddr)

	if len(slotFuncAddr[1]) != 1 {
		log.Errf("Function address is incorrect (%v), skipping", slotFuncAddr[1])
		return
	}
	functionAddr, err := strconv.ParseUint(slotFuncAddr[1], 16, 0)
	if err != nil {
		log.Errf("Error converting Slot address from string to uint (%v), skipping", err)
		return
	}
	function := uint(functionAddr)

	domConfig := genericCfg.(*libvirtxml.Domain)
	ifCfg := libvirtxml.DomainInterface{
		Managed: "yes",
		Source: &libvirtxml.DomainInterfaceSource{
			Hostdev: &libvirtxml.DomainInterfaceSourceHostdev{
				PCI: &libvirtxml.DomainHostdevSubsysPCISource{
					Address: &libvirtxml.DomainAddressPCI{
						Domain:   &domain,
						Bus:      &bus,
						Slot:     &slot,
						Function: &function,
					},
				},
			},
		},
	}
	domConfig.Devices.Interfaces = append(domConfig.Devices.Interfaces, ifCfg)
	return
}

// EPAFeature - we get an array of those in API calls from controller
// Key is used to lookup the proper EACHandler, value is handler specific
type EPAFeature struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

// This function will go through all the entries in our EPAFeatures
// table and find any keys for which we have registered handlers.
// If match is found, it will call the handler with the value
// as entered on the UI. (EPA Feature Value)
func processEAC(EACJson string, EACHandlers map[string]EACHandler,
	genericCfg interface{}, genericHostCfg interface{}) {
	var EPAFeatures []EPAFeature

	if err := json.Unmarshal([]byte(EACJson), &EPAFeatures); err != nil {
		log.Errf("Failed unmarshall'ing EPAFeatures json: %v", err)
		return
	}
	log.Debugf("Unmarshalled EPAFeatures: %+v", EPAFeatures)

	for _, entry := range EPAFeatures {
		log.Debugf("processing EAC key %v (val=%v)", entry.Key, entry.Value)

		// If the handler for key is found, call it with the value
		handler, ok := EACHandlers[entry.Key]
		if ok {
			log.Debugf("calling handler for %v", entry.Key)
			handler(entry.Value, genericCfg, genericHostCfg)
		}
	}
}

func (s *DeploySrv) syncDeployContainer(ctx context.Context,
	dapp *metadata.DeployedApp) {

	defer func() {
		if err := dapp.Save(true); err != nil {
			log.Errf("failed to save state of %v: %+v", dapp.App.Id, err)
		}
	}()

	if err := s.deployCommon(ctx, dapp); err != nil {
		dapp.App.Status = pb.LifecycleStatus_ERROR
		log.Errf("deployCommon failed: %s", err.Error())
		return
	}

	/* Now call the docker API. */
	docker, err := wrappers.CreateDockerClient()
	if err != nil {
		dapp.App.Status = pb.LifecycleStatus_ERROR
		log.Errf("failed to create a docker client: %s", err.Error())
		return
	}

	// Load the image first
	if err = loadImage(ctx, dapp, docker); err != nil {
		dapp.App.Status = pb.LifecycleStatus_ERROR
		log.Errf("failed to load docker image: %s", err.Error())
		return
	}

	// Status will be error unless explicitly reset
	dapp.App.Status = pb.LifecycleStatus_ERROR

	if s.cfg.KubernetesMode { // this mode requires us to only upload the image
		if err = dapp.SetDeployed(""); err != nil {
			log.Errf("SetDeployed() failed: %+v", err)
			return
		}
		dapp.App.Status = pb.LifecycleStatus_READY
		return
	}

	// Now create a container out of the image

	nanoCPUs := int64(dapp.App.Cores) * 1e9 // convert CPUs to NanoCPUs
	resources := container.Resources{
		Memory:   int64(dapp.App.Memory) * 1024 * 1024,
		NanoCPUs: nanoCPUs,
	}
	hostCfg := container.HostConfig{
		Resources: resources,
		CapAdd:    []string{"NET_ADMIN"}}

	if s.cfg.UseCNI {
		infraCtrID, cniErr := cni.CreateInfrastructureContainer(ctx, dapp)
		if cniErr != nil {
			log.Errf("Failed to create infrastructure container. AppID=%s, Reason=%s", dapp.App.Id, cniErr.Error())
			return
		}

		hostCfg.NetworkMode = container.NetworkMode(fmt.Sprintf("container:%s", infraCtrID))
	}

	containerCfg := container.Config{
		Image: dapp.App.Id,
	}

	// Update hostCfg and containCfg based on EAC configuration
	processPorts(dapp.App.Ports, &containerCfg)
	processEAC(dapp.App.EACJsonBlob, EACHandlersDocker, &hostCfg, &containerCfg)
	log.Debugf("containerCfg: %+v", containerCfg)
	log.Debugf("hostCfg: %+v", hostCfg)

	respCreate, err := docker.ContainerCreate(ctx,
		&containerCfg, &hostCfg, nil, dapp.App.Id)

	if err != nil {
		log.Errf("docker.ContainerCreate failed: %+v", err)
		return
	}

	log.Infof("Created a container with id %v", respCreate.ID)

	// Deployment succeeded, update our metadata
	if err = dapp.SetDeployed(respCreate.ID); err != nil {
		log.Errf("SetDeployed(%v) failed: %+v", dapp.App.Id, err)
		return
	}

	dapp.App.Status = pb.LifecycleStatus_READY
}

// DeployVM deploys VM
func (s *DeploySrv) DeployVM(ctx context.Context,
	pbapp *pb.Application) (*empty.Empty, error) {

	dapp := s.meta.NewDeployedApp(metadata.VM, pbapp)

	if err := s.checkIfAppNotDeployed(dapp.App.Id); err != nil {
		return nil, err
	}

	if err := s.checkDeployPreconditions(dapp); err != nil {
		return nil, errors.Wrap(err, "preconditions unfulfilled")
	}

	if err := dapp.IsChangeAllowed(pb.LifecycleStatus_DEPLOYING); err != nil {
		return nil, err
	}

	go func() {
		deployCtx, cancel := context.WithTimeout(context.Background(),
			s.cfg.DownloadTimeout.Duration)
		defer cancel()
		s.syncDeployVM(deployCtx, dapp)
	}()

	return &empty.Empty{}, nil
}

type updateDPDKVHostPath struct {
	PortName  string
	VHostPath string
}

func (u updateDPDKVHostPath) MarshalJSON() ([]byte, error) {
	// Following command must be reproduced in go:
	//   ovsdb-client -v transact '["Open_vSwitch", { "op": "update", "table":
	//   "Interface", "where": [["name", "==", "PORT"]], "row": {"options":
	//   ["map", [["vhost-server-path", "SOCK_PATH"]]]}}]'
	// Command performs an UPDATE query against ovs database. In table
	// "Interface" it changes "options" row to
	// "vhost-server-path:/path/vhost.sock" where "name" is specified name of
	// ovs interface.
	return []byte(fmt.Sprintf("{\"op\": \"update\", \"table\": \"Interface\","+
		" \"where\": [[\"name\", \"==\", \"%s\"]], "+
		"\"row\": {\"options\": "+
		"[\"map\", [[\"vhost-server-path\", \"%s\"]]]}}",
		u.PortName, u.VHostPath)), nil
}

// isOVSBridgeCreated checks whether the bridge given already exists
func isOVSBridgeCreated(o *ovs.Client, name string) (bool, error) {

	bridges, err := o.VSwitch.ListBridges()
	if err != nil {
		log.Errf("Couldn't list OVS bridges: %+v", err.Error())
		return false, err
	}

	for _, b := range bridges {
		if b == name {
			return true, nil // Found!
		}
	}

	return false, nil
}

// execOvsWithPath concatenates a path with rest of options to execute
// ovs-vsctl with appropriate ovs db path
func execOvsWithPath(cmd string, args ...string) ([]byte, error) {
	commands := append(
		[]string{"--db=unix:" + ovsDbSocket}, args...)
	// #nosec G204 - This is a workaround to use OVS cli with custom socket file
	return exec.Command(cmd, commands...).CombinedOutput()
}

// newOvs creates OVS Client with changed ovs-vsctl database path
func newOvs() *ovs.Client {
	return ovs.New(ovs.Exec(execOvsWithPath))
}

func addOVSPort(bridgeName string, id string) error {
	var (
		o               = newOvs()
		portName        = bridgeName + "-" + id
		vHostSocketPath = path.Join(ovsPath, portName+".sock")
		err             error
	)

	isBrCreated, err := isOVSBridgeCreated(o, bridgeName)
	if err != nil {
		return errors.Wrap(err, "Couldn't check status of bridge: "+bridgeName)
	}
	if !isBrCreated {
		return errors.Wrap(err, "There is no OVS bridge: "+bridgeName)
	}

	// The port may or may not already exist no need to check that
	err = o.VSwitch.AddPort(bridgeName, portName)
	if err != nil {
		return errors.Wrapf(err, "Couldn't attach OVS port %s ", portName)
	}

	// Set type to dpdkvhostuserclient
	if err = o.VSwitch.Set.Interface(portName,
		ovs.InterfaceOptions{Type: interfaceTypeDpdk}); err != nil {
		return errors.Wrapf(err, "Couldn't set interface dpdk type")
	}

	// Set option:'vhost-server-path' by making a transaction against ovsdb
	db, err := ovsdb.Dial("unix", ovsDbSocket)
	if err != nil {
		return errors.Wrap(err, "Failed to connect to ovsdb")
	}
	defer func() {
		if err = db.Close(); err != nil {
			log.Warning("Couldn't cloense db socket")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = db.Transact(ctx, "Open_vSwitch",
		[]ovsdb.TransactOp{updateDPDKVHostPath{
			PortName:  portName,
			VHostPath: vHostSocketPath}})
	if err != nil {
		return errors.Wrapf(err, "db.Transact() failure")
	}

	return nil
}

func removeOVSPort(bridgeName string, id string) error {
	var (
		o        = newOvs()
		portName = bridgeName + "-" + id
		err      error
	)

	// The port may or may not already exist no need to check that
	err = o.VSwitch.DeletePort(bridgeName, portName)
	if err != nil {
		return errors.Wrapf(err, "Couldn't remove OVS port %s ", portName)
	}

	return nil
}

func (s *DeploySrv) syncDeployVM(ctx context.Context,
	dapp *metadata.DeployedApp) {

	defer func() {
		if err := dapp.Save(true); err != nil {
			log.Errf("failed to save state of %v: %+v", dapp.App.Id, err)
		}
	}()

	if err := s.deployCommon(ctx, dapp); err != nil {
		dapp.App.Status = pb.LifecycleStatus_ERROR
		log.Errf("deployCommon failed: %s", err.Error())
		return
	}

	/* Now call the libvirt API. */
	conn, err := CreateLibvirtConnection("qemu:///system")
	if err != nil {
		dapp.App.Status = pb.LifecycleStatus_ERROR
		log.Errf("failed to create a libvirt client: %s", err.Error())
		return
	}

	defer func() {
		if c, err1 := conn.Close(); err1 != nil || c < 0 {
			log.Errf("Failed to close libvirt connection: code: %v, error: %v",
				c, err1)
		}
	}()

	// Round up to next 2 MiB boundary
	memRounded := math.Ceil(float64(dapp.App.Memory)/2) * 2
	domcfg := libvirtxml.Domain{
		Type: "kvm", Name: dapp.App.Id,
		OS: &libvirtxml.DomainOS{
			Type: &libvirtxml.DomainOSType{Arch: "x86_64", Type: "hvm"},
		},
		Features: &libvirtxml.DomainFeatureList{
			ACPI: &libvirtxml.DomainFeature{}},

		CPU: &libvirtxml.DomainCPU{
			Mode: "host-passthrough",
			Numa: &libvirtxml.DomainNuma{
				Cell: []libvirtxml.DomainCell{
					{
						ID:        new(uint), // it's initialized to 0
						CPUs:      fmt.Sprintf("0-%v", dapp.App.Cores-1),
						Memory:    fmt.Sprintf("%v", memRounded),
						Unit:      "MiB",
						MemAccess: "shared",
					},
				},
			},
		},
		VCPU: &libvirtxml.DomainVCPU{Value: int(dapp.App.Cores)},

		CPUTune: &libvirtxml.DomainCPUTune{
			VCPUPin: []libvirtxml.DomainCPUTuneVCPUPin{},
		},

		MemoryBacking: &libvirtxml.DomainMemoryBacking{
			MemoryHugePages: &libvirtxml.DomainMemoryHugepages{
				Hugepages: []libvirtxml.DomainMemoryHugepage{
					{Size: 2, Unit: "MiB"},
				},
			},
		},
		Devices: &libvirtxml.DomainDeviceList{
			Emulator: "/usr/local/bin/qemu-system-x86_64",
			Disks: []libvirtxml.DomainDisk{
				{
					Device: "disk",
					Driver: &libvirtxml.DomainDiskDriver{
						Name: "qemu",
						Type: "qcow2",
					},
					Source: &libvirtxml.DomainDiskSource{
						File: &libvirtxml.DomainDiskSourceFile{
							File: dapp.ImageFilePath()},
					},
					Target: &libvirtxml.DomainDiskTarget{Dev: "hda"},
				},
			},
			Interfaces: []libvirtxml.DomainInterface{},
		},
	}

	if s.cfg.OpenvSwitch {
		domcfg.Devices.Interfaces = append(domcfg.Devices.Interfaces,
			libvirtxml.DomainInterface{
				Source: &libvirtxml.DomainInterfaceSource{
					VHostUser: &libvirtxml.DomainChardevSource{
						UNIX: &libvirtxml.DomainChardevSourceUNIX{
							Path: path.Join(ovsPath, s.cfg.OpenvSwitchBridge+
								"-"+dapp.App.Id+".sock"),
							Mode: "server",
						},
					},
				},
				Model: &libvirtxml.DomainInterfaceModel{Type: "virtio"},
			},
		)
		if err = addOVSPort(s.cfg.OpenvSwitchBridge, dapp.App.Id); err != nil {
			log.Errf("failed to add port to OVS: %+v", err)
			return
		}
	}

	if s.cfg.UseCNI {
		if t, cniErr := cni.GetTypeFromCNIConfig(dapp.App.CniConf.CniConfig); cniErr != nil {
			dapp.App.Status = pb.LifecycleStatus_ERROR
			log.Errf("failed to get CNI type from CniConfig: %s", cniErr.Error())
			return
		} else if cni.Type(t) == cni.OVN {
			port, cniErr := cni.OVNCNICreatePort(dapp)
			if cniErr != nil {
				dapp.App.Status = pb.LifecycleStatus_ERROR
				log.Errf("failed to create OVN port: %s", cniErr.Error())
				return
			}

			bridge, cniErr := ovncni.GetCNIArg("ovsBrName", dapp.App.CniConf.Args)
			if cniErr != nil {
				bridge = ovncni.DefaultOvsBrName
			}

			domcfg.Devices.Interfaces = append(domcfg.Devices.Interfaces,
				libvirtxml.DomainInterface{
					MAC: &libvirtxml.DomainInterfaceMAC{
						Address: port.MAC.String(),
					},
					Source: &libvirtxml.DomainInterfaceSource{
						Bridge: &libvirtxml.DomainInterfaceSourceBridge{Bridge: bridge},
					},

					VirtualPort: &libvirtxml.DomainInterfaceVirtualPort{
						Params: &libvirtxml.DomainInterfaceVirtualPortParams{
							OpenVSwitch: &libvirtxml.DomainInterfaceVirtualPortParamsOpenVSwitch{
								InterfaceID: dapp.App.Id,
							},
						},
					},
					Model: &libvirtxml.DomainInterfaceModel{Type: "virtio"},
				},
			)
		}
	} else {
		// Dataplane: NTS
		domcfg.Devices.Interfaces = append(domcfg.Devices.Interfaces,
			libvirtxml.DomainInterface{
				Source: &libvirtxml.DomainInterfaceSource{
					Network: &libvirtxml.DomainInterfaceSourceNetwork{
						Network: "default",
					},
				},
				Model: &libvirtxml.DomainInterfaceModel{Type: "virtio"},
			},
			libvirtxml.DomainInterface{
				Source: &libvirtxml.DomainInterfaceSource{
					VHostUser: &libvirtxml.DomainChardevSource{
						UNIX: &libvirtxml.DomainChardevSourceUNIX{
							Path: s.cfg.VhostSocket, Mode: "client",
						},
					},
				},
				Model: &libvirtxml.DomainInterfaceModel{Type: "virtio"},
			},
		)
	}

	// Update domcfg based on EAC configuration
	processEAC(dapp.App.EACJsonBlob, EACHandlersVM, &domcfg, nil)
	xmldoc, err := domcfg.Marshal()
	if err != nil {
		dapp.App.Status = pb.LifecycleStatus_ERROR
		log.Errf("failed to marshal a domain: %s", err.Error())
		return
	}
	log.Debugf("XML doc for %v:\n%v", dapp.App.Id, xmldoc)

	dom, err := conn.DomainDefineXML(xmldoc)
	if err != nil {
		dapp.App.Status = pb.LifecycleStatus_ERROR
		log.Errf("failed to define a domain: %s", err.Error())
		return
	}
	defer func() { _ = dom.Free() }()

	name, err := dom.GetName()
	if err == nil {
		log.Infof("VM '%v' created", name)
	} else {
		log.Errf("failed to get VM name of '%v'", dapp.App.Id)
	}

	if err = dapp.SetDeployed(dapp.App.Id); err != nil {
		log.Errf("SetDeployed(%v) failed: %+v", dapp.App.Id, err)
		return
	}

	dapp.App.Status = pb.LifecycleStatus_READY
}

func (s *DeploySrv) syncRedeploy(ctx context.Context,
	dapp *metadata.DeployedApp) {

	if err := s.syncUndeploy(ctx, dapp); err != nil {
		log.Errf("failed to undeploy %v", dapp.App.Id)
		return
	}

	switch dapp.Type {
	case metadata.Container:
		s.syncDeployContainer(ctx, dapp)
	case metadata.VM:
		s.syncDeployVM(ctx, dapp)
	default:
		log.Errf("redeploy for unknown app type: %v", dapp.Type)
	}
}

// Redeploy asynchronously undeploys and deploys application again
func (s *DeploySrv) Redeploy(ctx context.Context,
	app *pb.Application) (*empty.Empty, error) {

	// Check currently existing metadata (undeploy preconditions)
	dapp, err := s.meta.Load(app.Id)
	if err != nil {
		return nil, errors.Wrapf(err, "Application %v not found", app.Id)
	}

	if err = dapp.IsChangeAllowed(pb.LifecycleStatus_UNKNOWN); err != nil {
		return nil, err
	}

	// Check new metadata (deploy preconditions)
	dapp = s.meta.NewDeployedApp(dapp.Type, app)
	if err = s.checkDeployPreconditions(dapp); err != nil {
		return nil, errors.Wrap(err, "preconditions unfulfilled")
	}

	go func() {
		redeployCtx, cancel := context.WithTimeout(context.Background(),
			s.cfg.DownloadTimeout.Duration)
		defer cancel()
		s.syncRedeploy(redeployCtx, dapp)
	}()

	return &empty.Empty{}, err
}

func (s *DeploySrv) dockerUndeploy(ctx context.Context,
	dapp *metadata.DeployedApp) error {

	docker, err := wrappers.CreateDockerClient()
	if err != nil {
		return errors.Wrap(err, "Failed to create a docker client")
	}

	if dapp.DeployedID != "" {
		if dapp.App.GetStatus() == pb.LifecycleStatus_RUNNING {
			log.Warningf("Removing running container '%v'", dapp.DeployedID)
		}
		err = docker.ContainerRemove(ctx, dapp.DeployedID,
			types.ContainerRemoveOptions{Force: true})

		if err != nil {
			return errors.Wrapf(err, "Undeploy(%s)", dapp.DeployedID)
		}
		log.Infof("Removed container '%v'", dapp.DeployedID)
	} else if !s.cfg.KubernetesMode {
		log.Errf("Could not find container ID for '%v'", dapp.App.Id)
	}
	_, err = docker.ImageRemove(ctx, dapp.App.Id, types.ImageRemoveOptions{})
	if err != nil {
		return errors.Wrapf(err, "ImageRemove(%v) failed", dapp.App.Id)
	}
	log.Infof("Docker image '%v' removed", dapp.App.Id)

	if s.cfg.UseCNI {
		err = cni.RemoveInfrastructureContainer(ctx, dapp)
		if err != nil {
			log.Errf("Failed to remove the Infra Container. AppID=%s, Reason=%s",
				dapp.App.Id, err.Error())
		}
	}

	return dapp.SetUndeployed()
}

func (s *DeploySrv) libvirtUndeploy(ctx context.Context,
	dapp *metadata.DeployedApp) error {

	conn, err := CreateLibvirtConnection("qemu:///system")

	if err != nil {
		return err
	}
	defer func() {
		if c, err1 := conn.Close(); err1 != nil || c < 0 {
			log.Errf("Failed to close libvirt connection: code: %v, error: %v",
				c, err1)
		}
	}()

	dom, err := conn.LookupDomainByName(dapp.App.Id)
	if err != nil {
		return err
	}
	defer func() { _ = dom.Free() }()

	state, _, err := dom.GetState()
	if err != nil {
		log.Errf("Could not get domain '%v' state: %v", dapp.App.Id, err)
	}

	if state == libvirt.DOMAIN_RUNNING {
		log.Infof("Domain (VM) '%v' is running - stopping before undeploy",
			dapp.App.Id)
		if err = dom.Destroy(); err != nil {
			return errors.Wrapf(err, "Failed to destroy '%v'", dapp.App.Id)
		}
	}

	if err = dom.Undefine(); err != nil {
		return errors.Wrapf(err, "Failed to undefine '%v'", dapp.App.Id)
	}
	log.Infof("Domain (VM) '%v' undefined", dapp.App.Id)

	if s.cfg.OpenvSwitch {
		if err = removeOVSPort(s.cfg.OpenvSwitchBridge,
			dapp.App.Id); err != nil {
			log.Errf("Undeploy(%v) failed: %+v", dapp.App.Id, err)
		}
	}

	if s.cfg.UseCNI {
		if t, err := cni.GetTypeFromCNIConfig(dapp.App.CniConf.CniConfig); err != nil {
			log.Errf("failed to get CNI type from CniConfig: %s", err.Error())
			return errors.Wrapf(err, "failed to get CNI type from CniConfig")
		} else if cni.Type(t) == cni.OVN {
			if err := cni.OVNCNIDeletePort(dapp); err != nil {
				log.Errf("failed to delete OVN port: %s", err.Error())
			}
		}
	}

	return dapp.SetUndeployed()
}

func (s *DeploySrv) syncUndeploy(ctx context.Context,
	dapp *metadata.DeployedApp) error {

	var err error
	switch dapp.Type {
	case metadata.Container:
		err = s.dockerUndeploy(ctx, dapp)
	case metadata.VM:
		err = s.libvirtUndeploy(ctx, dapp)
	default:
		log.Errf("Undeploy(%s): not supported application type: %v",
			dapp.App.Id, dapp.Type)
		return err
	}

	if err != nil {
		log.Errf("Undeploy(%v) failed: %+v", dapp.App.Id, err)
		dapp.App.Status = pb.LifecycleStatus_ERROR /* We're in a bad state.*/
		if saveErr := dapp.Save(true); saveErr != nil {
			log.Errf("failed to save state of %v: %+v", dapp.App.Id, saveErr)
		}
		return err
	}

	if err = os.RemoveAll(dapp.Path); err != nil {
		log.Errf("failed to delete metadata directory of %v because: %+v",
			dapp.App.Id, err)
	} else {
		log.Debugf("Deleted metadata directory of %v", dapp.App.Id)
	}

	return nil
}

// Undeploy executes asynchronous removal of application
func (s *DeploySrv) Undeploy(ctx context.Context,
	app *pb.ApplicationID) (*empty.Empty, error) {

	log.Infof("Undeploy(%s)", app.Id)

	dapp, err := s.meta.Load(app.Id)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"Application %v not found: %v", app.Id, err)
	}

	if err := dapp.IsChangeAllowed(pb.LifecycleStatus_UNKNOWN); err != nil {
		return nil, err
	}

	if !dapp.IsDeployed {
		log.Debugf("Undeploying not deployed app (%v)", app.Id)

		// Because OVN port is created during deployment, it needs to be removed even if app's deployment fails
		if s.cfg.UseCNI {
			if t, err := cni.GetTypeFromCNIConfig(dapp.App.CniConf.CniConfig); err != nil {
				log.Errf("failed to get CNI type from CniConfig: %s", err.Error())
				return nil, status.Errorf(codes.FailedPrecondition,
					"failed to get CNI type from CniConfig: %s", err.Error())
			} else if cni.Type(t) == cni.OVN {
				if err := cni.OVNCNIDeletePort(dapp); err != nil {
					log.Errf("failed to delete OVN port: %s", err.Error())
				}
			}
		}

		if err := os.RemoveAll(dapp.Path); err != nil {
			log.Debugf("Failed to delete metadata directory of %v because: %+v",
				app.Id, err)
		}

		return &empty.Empty{}, nil
	}

	go func() {
		undeployCtx, cancel := context.WithTimeout(context.Background(),
			s.cfg.DownloadTimeout.Duration)
		defer cancel()
		_ = s.syncUndeploy(undeployCtx, dapp)
	}()

	return &empty.Empty{}, nil
}
