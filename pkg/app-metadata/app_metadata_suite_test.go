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

package metadata_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"

	metadata "github.com/otcshare/edgenode/pkg/app-metadata"
	pb "github.com/otcshare/edgenode/pkg/eva/pb"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var createdFiles []string

func createDir(path string) {
	err := os.Mkdir(path, os.ModePerm)
	if err != nil {
		Fail(fmt.Sprintf("Failed to create dir: %s because: %v",
			path, err.Error()))
	}

	createdFiles = append(createdFiles, path)
}

func createFile(path, content string) {
	err := ioutil.WriteFile(path, []byte(content), 0755)
	if err != nil {
		Fail(fmt.Sprintf("Failed to create file: %s because: %v",
			path, err.Error()))
	}

	createdFiles = append(createdFiles, path)
}

func cleanFiles() {
	for _, path := range createdFiles {
		if err := os.RemoveAll(path); err != nil {
			Fail(fmt.Sprintf("Failed to remove: %s because: %v",
				path, err.Error()))
		}
	}
}

func loadFile(filePath string) []byte {
	if filePath == "" {
		Fail("Filepath parameter is empty")
	}

	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		Fail(fmt.Sprintf("Failed to read metadata file from: %s because: %v",
			filePath, err))
	}

	return bytes
}

func loadMetadataFile(filePath string) metadata.AppData {
	bytes := loadFile(filePath)
	md := metadata.AppData{}
	err := json.Unmarshal(bytes, &md)
	if err != nil {
		Fail(fmt.Sprintf("Failed to unmarshal metadata: %v", err))
	}

	return md
}

func loadDeployedFile(filePath string) string {
	bytes := loadFile(filePath)
	return string(bytes)
}

func TestAppMetadata(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "AppMetadata Suite")
}

var _ = Describe("Application's Metadata", func() {
	appID := "test-app"
	var expectedAppPath string
	var meta metadata.AppMetadata

	BeforeEach(func() {
		meta = metadata.AppMetadata{"/tmp/appliance-app-metadata-tests"}
		createDir(meta.RootPath)
		expectedAppPath = filepath.Join(meta.RootPath, appID)
	})

	AfterEach(func() {
		cleanFiles()
	})

	When("applicationID is empty", func() {
		It("is nil and error is returned", func() {
			app, err := meta.Load("")
			Expect(app).To(BeNil())
			Expect(err).To(MatchError("ApplicationID is empty"))
		})
	})

	Describe("structure on disk is incomplete", func() {
		Describe("app directory", func() {
			Context("does not exists", func() {
				It("returns an error", func() {
					app, err := meta.Load(appID)
					Expect(app).To(BeNil())
					Expect(err).To(MatchError("Failed to load metadata " +
						"file: open " + expectedAppPath +
						"/metadata.json: no such file or directory"))
				})
			})

			Context("is not really a directory", func() {
				It("returns an error", func() {
					createFile(expectedAppPath, "")

					app, err := meta.Load(appID)
					Expect(app).To(BeNil())
					Expect(err).To(MatchError("Failed to load metadata " +
						"file: open " + expectedAppPath +
						"/metadata.json: not a directory"))
				})
			})
		})

		Describe("metadata.json", func() {
			Context("does not exists", func() {
				It("returns an error", func() {
					createDir(expectedAppPath)

					app, err := meta.Load(appID)
					Expect(app).To(BeNil())
					Expect(err).
						To(MatchError("Failed to load metadata file: open " +
							expectedAppPath + "/metadata.json: " +
							"no such file or directory"))
				})
			})

			Context("cannot be unmarshalled", func() {
				It("returns an error", func() {
					createDir(expectedAppPath)
					createFile(
						filepath.Join(expectedAppPath, "metadata.json"), "")

					app, err := meta.Load(appID)
					Expect(app).To(BeNil())
					Expect(err).
						To(MatchError("Failed to unmarshal metadata: " +
							"unexpected end of JSON input"))
				})
			})

			Context("is ok", func() {
				It("returns an object and no error", func() {
					createDir(expectedAppPath)
					createFile(
						filepath.Join(expectedAppPath, "metadata.json"),
						`{"type": "DockerContainer"}`)

					app, err := meta.Load(appID)
					Expect(err).To(BeNil())
					Expect(app).ToNot(BeNil())

					Expect(app.Type).To(Equal(metadata.Container))
				})
			})
		})
	})

	Describe("deployed file", func() {
		When("exists", func() {
			Specify("IsDeployed is true", func() {
				createDir(expectedAppPath)
				createFile(
					filepath.Join(expectedAppPath, "deployed"), " ")
				createFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"type": "DockerContainer"}`)

				app, err := meta.Load(appID)
				Expect(err).To(BeNil())
				Expect(app).ToNot(BeNil())

				Expect(app.IsDeployed).To(BeTrue())
			})
		})

		When("does not exist", func() {
			Specify("IsDeployed is false", func() {
				createDir(expectedAppPath)
				createFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"type": "DockerContainer"}`)

				app, err := meta.Load(appID)
				Expect(err).To(BeNil())
				Expect(app).ToNot(BeNil())

				Expect(app.IsDeployed).To(BeFalse())
			})
		})
	})

	app := pb.Application{
		Id:          appID,
		Name:        "Sample App Name",
		Version:     "1.0.0",
		Vendor:      "",
		Description: "Sample description",
		Cores:       4,
		Memory:      4096,
		Status:      pb.LifecycleStatus_UNKNOWN,
	}

	var deployedApp = meta.NewDeployedApp(metadata.VM, &app)

	Describe("Saving files", func() {
		When("updateOnly is false", func() {
			AfterEach(func() {
				if err := os.RemoveAll(deployedApp.Path); err != nil {
					Fail(fmt.Sprintf("Failed to remove: %s because: %v",
						deployedApp.Path, err.Error()))
				}
			})

			Specify("successfully", func() {
				err := deployedApp.Save(false)
				Expect(err).To(BeNil())
				_, err = os.Stat(path.Join(deployedApp.Path, "metadata.json"))
				Expect(os.IsNotExist(err)).To(BeFalse())
				Expect(loadMetadataFile(path.Join(deployedApp.Path, "metadata.json"))).
					To(Equal(deployedApp.AppData))
			})

			Specify("Path to file already exists", func() {
				err := deployedApp.Save(false)
				Expect(err).To(BeNil())
				_, err = os.Stat(path.Join(deployedApp.Path, "metadata.json"))
				Expect(os.IsNotExist(err)).To(BeFalse())
				Expect(loadMetadataFile(path.Join(deployedApp.Path, "metadata.json"))).
					To(Equal(deployedApp.AppData))

				err = deployedApp.Save(false)
				Expect(err).To(BeNil())
				_, err = os.Stat(path.Join(deployedApp.Path, "metadata.json"))
				Expect(os.IsNotExist(err)).To(BeFalse())
				Expect(loadMetadataFile(path.Join(deployedApp.Path, "metadata.json"))).
					To(Equal(deployedApp.AppData))
			})
		})
	})

	AfterEach(func() {
		if err := os.RemoveAll(deployedApp.Path); err != nil {
			Fail(fmt.Sprintf("Failed to remove: %s because: %v",
				deployedApp.Path, err.Error()))
		}
		deployedApp.App.Status = pb.LifecycleStatus_UNKNOWN
	})

	Describe("Setting Application as Deployed", func() {
		Specify("Successfully", func() {
			err := deployedApp.IsChangeAllowed(pb.LifecycleStatus_DEPLOYING)
			Expect(err).To(BeNil())
			deployedApp.App.Status = pb.LifecycleStatus_DEPLOYING
			err = deployedApp.Save(false)
			Expect(err).To(BeNil())

			err = deployedApp.SetDeployed(appID)
			Expect(err).To(BeNil())
			_, err = os.Stat(path.Join(deployedApp.Path, "deployed"))
			Expect(os.IsNotExist(err)).To(BeFalse())
			Expect(loadDeployedFile(path.Join(deployedApp.Path, "deployed"))).To(Equal(
				appID + "\n"))
		})

		Specify("when directory does not exist", func() {
			err := deployedApp.SetDeployed(appID)
			Expect(err).ToNot(BeNil())
			_, err = os.Stat(path.Join(deployedApp.Path, "deployed"))
			Expect(os.IsNotExist(err)).To(BeTrue())
		})
	})

	Describe("Setting Application as Undeployed", func() {
		Specify("Successfully", func() {
			err := deployedApp.Save(false)
			Expect(err).To(BeNil())

			err = deployedApp.SetDeployed(appID)
			Expect(err).To(BeNil())
			deployedApp.App.Status = pb.LifecycleStatus_READY
			_, err = os.Stat(path.Join(deployedApp.Path, "deployed"))
			Expect(os.IsNotExist(err)).To(BeFalse())

			err = deployedApp.IsChangeAllowed(pb.LifecycleStatus_UNKNOWN)
			Expect(err).To(BeNil())

			err = deployedApp.SetUndeployed()
			Expect(err).To(BeNil())
			_, err = os.Stat(path.Join(deployedApp.Path, "deployed"))
			Expect(os.IsNotExist(err)).To(BeTrue())
		})
	})

})
