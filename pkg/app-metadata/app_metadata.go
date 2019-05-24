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

package metadata

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/pkg/errors"
	"github.com/smartedgemec/appliance-ce/pkg/ela/pb"
	logger "github.com/smartedgemec/log"
)

var log = logger.DefaultLogger.WithField("meta", nil)

const (
	metadataFileName = "metadata.json"
	deployedFileName = "deployed"
)

type AppMetadata struct {
	RootPath string
}

// ApplicationType is type for specifying type of application
type AppType string

const (
	VM        AppType = "LibvirtDomain"   // VM
	Container AppType = "DockerContainer" // container
)

// AppData represents metadata.json file
type AppData struct {
	Type AppType
	App  *pb.Application
}

// Application is type storing metadata and additional not serialized data
type DeployedApp struct {
	AppData
	IsDeployed bool
	DeployedID string
	Path       string
}

func (m *AppMetadata) appPath(appID string) string {
	return m.RootPath + "/" + appID
}

// Loads application's metadata from disk
func (m *AppMetadata) Load(appID string) (*DeployedApp, error) {
	if appID == "" {
		return nil, errors.New("ApplicationID is empty")
	}

	appPath := m.appPath(appID)

	if err := os.Chdir(appPath); err != nil {
		return nil, err
	}
	log.Infof("Load(): Entered directory %s", appPath)

	bytes, err := ioutil.ReadFile(metadataFileName)
	if err != nil {
		return nil, fmt.Errorf("Failed to load metadata file: %s", err.Error())
	}

	dapp := DeployedApp{}
	err = json.Unmarshal(bytes, &dapp.AppData)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal metadata: %s", err.Error())
	}
	dapp.Path = appPath

	file, err := os.Open(dapp.deployedFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			dapp.IsDeployed = false
			return &dapp, nil
		}
		return nil, fmt.Errorf("Failed to open %s", deployedFileName)
	}
	defer file.Close()
	dapp.IsDeployed = true
	num, err := file.Read(bytes) // bytes is definitely big enough
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to read %v", file.Name())
	}

	dapp.DeployedID = string(bytes[0 : num-1]) // cut '\n'
	log.Infof("Found the deployment ID for %v: '%v'", appID, dapp.DeployedID)

	return &dapp, nil
}

func (m *AppMetadata) NewDeployedApp(appType AppType,
	app *pb.Application) *DeployedApp {
	a := new(DeployedApp)
	a.Type = appType
	a.App = app
	a.IsDeployed = false
	a.Path = m.appPath(app.Id)

	return a
}

func (a *DeployedApp) Save() error {
	/* Serialize the metadata. */
	bytes, err := json.Marshal(&a.AppData)
	if err != nil {
		return errors.Wrap(err, "Failed to serialize application metadata.")
	}
	log.Infof("Saving metadata: %v", string(bytes))
	bytes = append(bytes, '\n') // serialization doesn't add newline, looks bad

	if err = os.Mkdir(a.Path, os.ModePerm); err != nil {
		if os.IsExist(err) {
			log.Infof("Save(): %v already exists", a.Path)
		} else {
			return errors.Wrap(err, "Could not create App image directory.")
		}
	}
	if err = os.Chdir(a.Path); err != nil {
		return errors.Wrap(err, "Can not enter the metadata dir")
	}
	log.Infof("created and/or entered %v", a.Path)

	file, err := os.Create(metadataFileName)
	if err != nil {
		return errors.Wrap(err, "failed to create metadata file")
	}

	_, err = file.Write(bytes)
	file.Close()

	return err
}

func (a *DeployedApp) deployedFilePath() string {
	return path.Join(a.Path, deployedFileName)
}

func (a *DeployedApp) SetDeployed(deployedID string) error {
	a.DeployedID = deployedID
	file, err := os.Create(a.deployedFilePath())
	if err != nil {
		return errors.Wrap(err, "failed to create the deployed file")
	}
	/* We also store the deployed ID in here */
	bytes := []byte(deployedID)
	_, err = file.Write(append(bytes, '\n'))
	file.Close()

	log.Infof("created the deployed indicator: %s", file.Name())

	return err
}

func (a *DeployedApp) SetUndeployed() error {
	path := a.deployedFilePath()

	log.Infof("Removing %v", path)

	return os.Remove(path)
}
