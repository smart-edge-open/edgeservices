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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// RootPath is a string of metadata's root directory
// TODO: Get from config file
var RootPath = "/var/lib/appliance/applications"

const (
	metadataFileName = ".metadata.json"
	deployFileName   = ".deployed"
)

// Application is type storing metadata and additional not serialized data
type Application struct {
	ApplicationMetadata
	IsDeployed bool
}

// ApplicationType is type for specifying type of application
type ApplicationType string

const (
	// LibvirtDomain means that application is libvirt Domain (VM)
	LibvirtDomain ApplicationType = "LibvirtDomain"

	// DockerContainer means that application is Docker container
	DockerContainer ApplicationType = "DockerContainer"
)

// ApplicationMetadata represents .metadata.json file
type ApplicationMetadata struct {
	Type ApplicationType `json:"type"`
}

// GetApplication loads application's metadata from disk
func GetApplication(applicationID string) (*Application, error) {
	if applicationID == "" {
		return nil, errors.New("ApplicationID is empty")
	}

	appPath := filepath.Join(RootPath, applicationID)

	dirInfo, err := os.Stat(appPath)
	if err != nil {
		return nil, fmt.Errorf("%s", err.Error())
	}

	if !dirInfo.IsDir() {
		return nil, fmt.Errorf("Expected '%s' to be a directory", appPath)
	}

	metaDataFilePath := filepath.Join(appPath, metadataFileName)
	metaData, err := ioutil.ReadFile(metaDataFilePath)
	if err != nil {
		return nil, fmt.Errorf("Failed to load metadata file: %s", err.Error())
	}

	appData := &Application{}
	err = json.Unmarshal(metaData, appData)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal metadata: %s", err.Error())
	}

	deployedFilePath := filepath.Join(appPath, deployFileName)
	if _, err := os.Stat(deployedFilePath); err == nil {
		appData.IsDeployed = true
	} else if os.IsNotExist(err) {
		appData.IsDeployed = false
	} else {
		return nil, fmt.Errorf("Failed to stat %s", deployedFilePath)
	}

	return appData, nil
}
