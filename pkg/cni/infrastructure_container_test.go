// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package cni

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/open-ness/edgenode/internal/stubs"
	"github.com/open-ness/edgenode/internal/wrappers"

	"github.com/docker/docker/api/types"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("makeSureInfraContainerImageExists", func() {
	wrappers.CreateDockerClient = stubs.CreateDockerClientStub
	BeforeEach(func() {
		stubs.DockerCliStub = stubs.DockerClientStub{}
	})

	When("image is absent", func() {
		It("pulls the image", func() {
			stubs.DockerCliStub.ImPullResp = ioutil.NopCloser(strings.NewReader(""))
			err := makeSureInfraContainerImageExists(context.Background(), &stubs.DockerCliStub)

			Expect(err).ToNot(HaveOccurred())
			Expect(stubs.DockerCliStub.ImPullCalled).To(BeTrue())
		})
	})

	When("image is present", func() {
		It("does not pull the image", func() {
			stubs.DockerCliStub.ImListResp = []types.ImageSummary{{}} // 1 element
			err := makeSureInfraContainerImageExists(context.Background(), &stubs.DockerCliStub)

			Expect(err).ToNot(HaveOccurred())
			Expect(stubs.DockerCliStub.ImPullCalled).To(BeFalse())
		})
	})
})

var _ = Describe("InfrastructureContainerInfo", func() {
	appID := "test-app"
	var infraCtr InfrastructureContainerInfo
	wrappers.CreateDockerClient = stubs.CreateDockerClientStub

	BeforeEach(func() {
		infraCtr = NewInfrastructureContainerInfo(appID)
		stubs.DockerCliStub = stubs.DockerClientStub{}
		stubs.DockerCliStub.ImListResp = []types.ImageSummary{{}} // image already present
	})

	When("object is created", func() {
		It("has initial fields filled correctly", func() {
			Expect(infraCtr.AppID).To(Equal(appID))
			Expect(infraCtr.Name).To(Equal(fmt.Sprintf(infraContainerNameTemplate, appID)))
		})
	})

	Describe(".create()", func() {
		When("container does not exist", func() {
			It("will be created", func() {
				stubs.DockerCliStub.CListResp = []types.Container{} // no containers

				stubs.DockerCliStub.CCreateBody = container.ContainerCreateCreatedBody{ID: "f4k3-uu1d-1111-2222-3333"}

				infraCtr.Create(context.Background())

				Expect(stubs.DockerCliStub.CCreateCalled).To(BeTrue())
				Expect(stubs.DockerCliStub.CCreateArgs.Config.Image).To(Equal(infraContainerImageRef))
				Expect(stubs.DockerCliStub.CCreateArgs.HostConfig.NetworkMode).To(Equal(container.NetworkMode("none")))
				Expect(stubs.DockerCliStub.CCreateArgs.ContainerName).
					To(Equal(fmt.Sprintf(infraContainerNameTemplate, appID)))

				Expect(infraCtr.ID).To(Equal("f4k3-uu1d-1111-2222-3333"))
			})
		})

		When("container exists", func() {
			It("will be created", func() {
				stubs.DockerCliStub.CListResp = []types.Container{{ID: "f4k3-uu1d-1111-2222-3333"}} // 1 container
				stubs.DockerCliStub.CInspectResp = types.ContainerJSON{
					ContainerJSONBase: &types.ContainerJSONBase{
						ID: "f4k3-uu1d-1111-2222-3333",
						State: &types.ContainerState{
							Running: false,
						},
					},
				}

				infraCtr.Create(context.Background())

				Expect(stubs.DockerCliStub.CCreateCalled).To(BeFalse())
				Expect(infraCtr.ID).To(Equal("f4k3-uu1d-1111-2222-3333"))
			})
		})
	})

	Describe(".start()", func() {
		When("container is already running", func() {
			It("will not start the container", func() {
				infraCtr.ID = "f4k3-uu1d-1111-2222-3333"
				stubs.DockerCliStub.CInspectResp = types.ContainerJSON{
					ContainerJSONBase: &types.ContainerJSONBase{
						ID: "f4k3-uu1d-1111-2222-3333",
						State: &types.ContainerState{
							Running: true,
							Pid:     123,
						},
					},
				}

				infraCtr.Start(context.Background())

				Expect(stubs.DockerCliStub.CCreateCalled).To(BeFalse())
				Expect(infraCtr.ID).To(Equal("f4k3-uu1d-1111-2222-3333"))
				Expect(infraCtr.PID).To(Equal(123))
			})
		})
	})

	Describe(".Stop()", func() {
		When("container does not exist", func() {
			It("will not try to stop the container", func() {
				err := infraCtr.Stop(context.Background())
				Expect(err).ToNot(HaveOccurred())
				Expect(stubs.DockerCliStub.CStopCalled).To(BeFalse())
			})
		})

		When("container exists", func() {
			It("will try to stop the container", func() {
				stubs.DockerCliStub.CListResp = []types.Container{{ID: "f4k3-uu1d-1111-2222-3333"}} // 1 container
				stubs.DockerCliStub.CInspectResp = types.ContainerJSON{
					ContainerJSONBase: &types.ContainerJSONBase{
						ID: "f4k3-uu1d-1111-2222-3333",
						State: &types.ContainerState{
							Running: false,
						},
					},
				}
				err := infraCtr.Stop(context.Background())
				Expect(err).ToNot(HaveOccurred())
				Expect(stubs.DockerCliStub.CStopCalled).To(BeTrue())
			})
		})
	})

	Describe(".Remove()", func() {
		When("container does not exist", func() {
			It("will not try to remove the container", func() {
				stubs.DockerCliStub.CInspectResp = types.ContainerJSON{
					ContainerJSONBase: &types.ContainerJSONBase{
						ID: "f4k3-uu1d-1111-2222-3333",
						State: &types.ContainerState{
							Running: false,
						},
					},
				}
				err := infraCtr.Remove(context.Background())
				Expect(err).ToNot(HaveOccurred())
				Expect(stubs.DockerCliStub.CRemoveCalled).To(BeFalse())
			})
		})

		When("container exists", func() {
			It("will try to remove the container", func() {
				stubs.DockerCliStub.CInspectResp = types.ContainerJSON{
					ContainerJSONBase: &types.ContainerJSONBase{
						ID: "f4k3-uu1d-1111-2222-3333",
						State: &types.ContainerState{
							Running: false,
						},
					},
				}
				stubs.DockerCliStub.CListResp = []types.Container{{ID: "f4k3-uu1d-1111-2222-3333"}} // 1 container
				err := infraCtr.Remove(context.Background())
				Expect(err).ToNot(HaveOccurred())
				Expect(stubs.DockerCliStub.CRemoveCalled).To(BeTrue())
			})
		})
	})
})
