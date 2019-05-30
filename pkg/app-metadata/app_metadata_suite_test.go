package metadata_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	metadata "github.com/smartedgemec/appliance-ce/pkg/app-metadata"

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
})
