// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package metadata

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	logger "github.com/open-ness/common/log"
	pb "github.com/open-ness/edgenode/pkg/eva/pb"
	"github.com/pkg/errors"
)

var log = logger.DefaultLogger.WithField("meta", nil)

const (
	metadataFileName = "metadata.json"
	deployedFileName = "deployed"
	imageFileName    = "image"
)

// AppMetadata describes metadata for an app
type AppMetadata struct {
	RootPath string
}

// AppType is type for specifying type of application
type AppType string

const (
	// VM is a virtual machine type
	VM AppType = "LibvirtDomain" // VM
	// Container is a container machine type
	Container AppType = "DockerContainer" // container
)

// AppData represents metadata.json file
type AppData struct {
	Type AppType
	URL  string
	App  *pb.Application
}

// DeployedApp is type storing metadata and additional not serialized data
type DeployedApp struct {
	AppData
	IsDeployed bool
	DeployedID string
	Path       string
}

// IsChangeAllowed checks if transition from current state to desired is allowed
func (a *DeployedApp) IsChangeAllowed(
	targetStatus pb.LifecycleStatus_Status) error { //nolint:interfacer

	switch a.App.Status {
	case pb.LifecycleStatus_READY:
		switch targetStatus {
		case pb.LifecycleStatus_STARTING,
			pb.LifecycleStatus_UNKNOWN:
			return nil
		}

	case pb.LifecycleStatus_RUNNING:
		switch targetStatus {
		case pb.LifecycleStatus_STARTING,
			pb.LifecycleStatus_STOPPING,
			pb.LifecycleStatus_UNKNOWN:
			return nil
		}

	case pb.LifecycleStatus_ERROR:
		switch targetStatus {
		case pb.LifecycleStatus_STARTING,
			pb.LifecycleStatus_UNKNOWN:
			return nil
		}

	case pb.LifecycleStatus_STOPPED:
		switch targetStatus {
		case pb.LifecycleStatus_STOPPING,
			pb.LifecycleStatus_STARTING,
			pb.LifecycleStatus_UNKNOWN:
			return nil
		}

	// Transition from non-existent application
	case pb.LifecycleStatus_UNKNOWN:
		switch targetStatus {
		case pb.LifecycleStatus_DEPLOYING:
			return nil
		}
	}

	return errors.Errorf("transition from %s to %s is not allowed",
		a.App.Status.String(), targetStatus.String())
}

func (m *AppMetadata) appPath(appID string) string {
	return path.Join(m.RootPath, appID)
}

func (a *DeployedApp) metadataFilePath() string {
	return path.Join(a.Path, metadataFileName)
}

func (a *DeployedApp) deployedFilePath() string {
	return path.Join(a.Path, deployedFileName)
}

// ImageFilePath joins path with imageFileName
func (a *DeployedApp) ImageFilePath() string {
	return path.Join(a.Path, imageFileName)
}

// NewDeployedApp create a new deployed app
func (m *AppMetadata) NewDeployedApp(appType AppType,
	app *pb.Application) *DeployedApp {
	a := new(DeployedApp)
	a.Type = appType
	a.App = app
	a.App.Status = pb.LifecycleStatus_UNKNOWN
	a.IsDeployed = false
	a.Path = m.appPath(app.Id)

	return a
}

// Load loads application's metadata from disk
func (m *AppMetadata) Load(appID string) (*DeployedApp, error) {
	if appID == "" {
		return nil, errors.New("ApplicationID is empty")
	}

	appPath := m.appPath(appID)

	dapp := m.NewDeployedApp("UNKNOWN", &pb.Application{Id: appID}) // bootstrap
	bytes, err := ioutil.ReadFile(dapp.metadataFilePath())
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load metadata file")
	}

	err = json.Unmarshal(bytes, &dapp.AppData) // now read proper data
	if err != nil {
		return nil, errors.Wrap(err, "Failed to unmarshal metadata")
	}
	dapp.Path = appPath

	file, err := os.Open(dapp.deployedFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			dapp.IsDeployed = false
			return dapp, nil
		}
		return nil, fmt.Errorf("Failed to open %s", deployedFileName)
	}
	dapp.IsDeployed = true
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to stat %v", file.Name())
	}
	deployedFileBytes := make([]byte, fileInfo.Size())
	num, err := file.Read(deployedFileBytes)

	if err1 := file.Close(); err == nil {
		err = err1
	}
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to read %v", file.Name())
	}

	dapp.DeployedID = string(deployedFileBytes[0 : num-1]) // cut '\n'
	log.Infof("Found the deployment ID for %v: '%v'", appID, dapp.DeployedID)

	return dapp, nil
}

// Save function will write into a temporary file that's in the same directory
// as target first. Only when temp file is fully written, will it atomically
// rename it to the target file. This ensures we don't end up with a partially
// written file in case of power failure / system hang etc, since mostly we're
// updating only a single field anyway.
func (a *DeployedApp) Save(updateOnly bool) error {
	tmpfile := a.metadataFilePath() + ".tmp"
	/* Serialize the metadata. */
	bytes, err := json.Marshal(&a.AppData)
	if err != nil {
		return errors.Wrap(err, "Failed to serialize application metadata.")
	}
	log.Infof("Saving metadata: %v", string(bytes))
	bytes = append(bytes, '\n') // serialization doesn't add newline, looks bad

	if !updateOnly {
		if err = os.Mkdir(a.Path, os.ModePerm); err != nil {
			if os.IsExist(err) {
				log.Infof("Save(): %v already exists", a.Path)
			} else {
				return errors.Wrap(err, "Could not create App image directory.")
			}
		} else {
			log.Infof("created %v", a.Path)
		}
	}

	file, err := os.Create(tmpfile)
	if err != nil {
		return errors.Wrap(err, "failed to create metadata file")
	}

	_, err = file.Write(bytes)
	if err1 := file.Close(); err == nil {
		err = err1
	}
	if err != nil {
		return err
	}

	return os.Rename(tmpfile, a.metadataFilePath()) // Atomic rename
}

// SetDeployed sets deployed
func (a *DeployedApp) SetDeployed(deployedID string) error {
	a.DeployedID = deployedID
	file, err := os.Create(a.deployedFilePath())
	if err != nil {
		return errors.Wrap(err, "failed to create the deployed file")
	}
	/* We also store the deployed ID in here */
	bytes := []byte(deployedID)
	_, err = file.Write(append(bytes, '\n'))
	if err1 := file.Close(); err == nil {
		err = err1
	}

	log.Infof("created the deployed indicator: %s", file.Name())

	return err
}

// SetUndeployed sets undeployed
func (a *DeployedApp) SetUndeployed() error {
	path := a.deployedFilePath()

	log.Infof("Removing %v", path)

	return os.Remove(path)
}
