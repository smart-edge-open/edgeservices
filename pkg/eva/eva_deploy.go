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
	"strings"

	"github.com/golang/protobuf/ptypes/empty"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"

	libvirtxml "github.com/libvirt/libvirt-go-xml"

	"github.com/otcshare/edgenode/internal/wrappers"
	metadata "github.com/otcshare/edgenode/pkg/app-metadata"
	pb "github.com/otcshare/edgenode/pkg/eva/pb"
	"github.com/pkg/errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	libvirt "github.com/libvirt/libvirt-go"

	"github.com/digitalocean/go-openvswitch/ovs"
	"github.com/digitalocean/go-openvswitch/ovsdb"
)

// DeploySrv describes deplyment
type DeploySrv struct {
	cfg    *Config
	meta   *metadata.AppMetadata
	hddlIn bool
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

// detectHDDL detects if HDDL is present and configured: checks if devices exist
func (s *DeploySrv) detectHDDL() {
	var hddlPaths = []string{"/dev/ion", "/dev/myriad0"}

	for _, d := range hddlPaths {
		if _, err := os.Stat(filepath.Clean(d)); os.IsNotExist(err) {
			s.hddlIn = false
			break
		} else {
			s.hddlIn = true
		}
	}
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
	devIon := container.DeviceMapping{
		PathOnHost:        "/dev/ion",
		PathInContainer:   "/dev/ion",
		CgroupPermissions: "rmw",
	}
	var hddlDevices []container.DeviceMapping
	var hddlBinds []string
	if s.hddlIn {
		hddlDevices = []container.DeviceMapping{devIon}
		hddlBinds = []string{"/var/tmp:/var/tmp"}
	}
	nanoCPUs := int64(dapp.App.Cores) * 1e9 // convert CPUs to NanoCPUs
	resources := container.Resources{
		Memory:   int64(dapp.App.Memory) * 1024 * 1024,
		NanoCPUs: nanoCPUs,
		Devices:  hddlDevices,
	}
	respCreate, err := docker.ContainerCreate(ctx,
		&container.Config{Image: dapp.App.Id},
		&container.HostConfig{
			Resources: resources,
			Binds:     hddlBinds,
			CapAdd:    []string{"NET_ADMIN"}},
		nil, dapp.App.Id)

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
			Interfaces: []libvirtxml.DomainInterface{
				{
					Source: &libvirtxml.DomainInterfaceSource{
						Network: &libvirtxml.DomainInterfaceSourceNetwork{
							Network: "default",
						},
					},
					Model: &libvirtxml.DomainInterfaceModel{Type: "virtio"},
				},
				{
					Source: &libvirtxml.DomainInterfaceSource{
						VHostUser: &libvirtxml.DomainChardevSource{
							UNIX: &libvirtxml.DomainChardevSourceUNIX{
								Path: s.cfg.VhostSocket, Mode: "client",
							},
						},
					},
					Model: &libvirtxml.DomainInterfaceModel{Type: "virtio"},
				},
			},
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
		log.Debugf("Undeploing not deployed app (%v)", app.Id)

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
