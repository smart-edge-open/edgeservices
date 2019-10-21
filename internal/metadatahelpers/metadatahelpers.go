// Copyright 2019 Intel Corporation. All rights reserved
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

package metadatahelpers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	metadata "github.com/otcshare/edgenode/pkg/app-metadata"

	"github.com/onsi/ginkgo"
)

var createdFiles []string

// CreateDir creates directory in specified path for metada to be stored
func CreateDir(path string) {
	err := os.Mkdir(path, os.ModePerm)
	if err != nil {
		ginkgo.Fail(fmt.Sprintf("Failed to create dir: %s because: %v",
			path, err.Error()))
	}

	createdFiles = append(createdFiles, path)
}

// CreateFile creates file with specified content in specified path
func CreateFile(path, content string) {
	err := ioutil.WriteFile(path, []byte(content), 0755)
	if err != nil {
		ginkgo.Fail(fmt.Sprintf("Failed to create file: %s because: %v",
			path, err.Error()))
	}

	createdFiles = append(createdFiles, path)
}

// CleanFiles removes all files in directory specified with CreateDir()
func CleanFiles() {
	for _, path := range createdFiles {
		if err := os.RemoveAll(path); err != nil {
			ginkgo.Fail(fmt.Sprintf("Failed to remove: %s because: %v",
				path, err.Error()))
		}
	}
}

func loadFile(filePath string) []byte {
	if filePath == "" {
		ginkgo.Fail("Filepath parameter is empty")
	}

	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		ginkgo.Fail(fmt.Sprintf("Failed to read metadata file from: %s "+
			"because: %v", filePath, err))
	}

	return bytes
}

// LoadMetadataFile loads and returns app metadata from file
func LoadMetadataFile(filePath string) metadata.AppData {
	bytes := loadFile(filePath)
	md := metadata.AppData{}
	err := json.Unmarshal(bytes, &md)
	if err != nil {
		ginkgo.Fail(fmt.Sprintf("Failed to unmarshal metadata: %v", err))
	}

	return md
}

// LoadDeployedFile loads and returns raw content of filed
func LoadDeployedFile(filePath string) string {
	bytes := loadFile(filePath)
	return string(bytes)
}
