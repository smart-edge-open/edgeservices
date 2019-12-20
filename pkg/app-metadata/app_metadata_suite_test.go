// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package metadata_test

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"

	. "github.com/open-ness/edgenode/internal/metadatahelpers"
	metadata "github.com/open-ness/edgenode/pkg/app-metadata"
	pb "github.com/open-ness/edgenode/pkg/eva/pb"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

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
		CreateDir(meta.RootPath)
		expectedAppPath = filepath.Join(meta.RootPath, appID)
	})

	AfterEach(func() {
		CleanFiles()
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
					CreateFile(expectedAppPath, "")

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
					CreateDir(expectedAppPath)

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
					CreateDir(expectedAppPath)
					CreateFile(
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
					CreateDir(expectedAppPath)
					CreateFile(
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
				CreateDir(expectedAppPath)
				CreateFile(
					filepath.Join(expectedAppPath, "deployed"), " ")
				CreateFile(
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
				CreateDir(expectedAppPath)
				CreateFile(
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
				Expect(LoadMetadataFile(path.Join(deployedApp.Path,
					"metadata.json"))).
					To(Equal(deployedApp.AppData))
			})

			Specify("Path to file already exists", func() {
				err := deployedApp.Save(false)
				Expect(err).To(BeNil())
				_, err = os.Stat(path.Join(deployedApp.Path, "metadata.json"))
				Expect(os.IsNotExist(err)).To(BeFalse())
				Expect(LoadMetadataFile(path.Join(deployedApp.Path,
					"metadata.json"))).
					To(Equal(deployedApp.AppData))

				err = deployedApp.Save(false)
				Expect(err).To(BeNil())
				_, err = os.Stat(path.Join(deployedApp.Path, "metadata.json"))
				Expect(os.IsNotExist(err)).To(BeFalse())
				Expect(LoadMetadataFile(path.Join(deployedApp.Path,
					"metadata.json"))).
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
			Expect(LoadDeployedFile(path.Join(deployedApp.Path,
				"deployed"))).To(Equal(appID + "\n"))
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
