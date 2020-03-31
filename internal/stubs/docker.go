// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

package stubs

import (
	"context"
	"io"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/open-ness/edgenode/internal/wrappers"
)

// DockerCliStub stores DockerClientStub
var DockerCliStub DockerClientStub

// CreateDCSErr stores error for CreateDockerClientStub
var CreateDCSErr error

// CCreateArgs stores ContainerCreate arguments
type CCreateArgs struct {
	Config           *container.Config
	HostConfig       *container.HostConfig
	NetworkingConfig *network.NetworkingConfig
	ContainerName    string
}

// DockerClientStub struct implementation
type DockerClientStub struct {
	// ImageLoad
	ImLoadResp   types.ImageLoadResponse
	ImLoadErr    error
	ImLoadCalled bool

	// ImageTag
	ImTagErr    error
	ImTagCalled bool

	// ImageRemove
	ImRemoveResp   []types.ImageDeleteResponseItem
	ImRemoveErr    error
	ImRemoveCalled bool

	// ImagePull
	ImPullResp   io.ReadCloser
	ImPullErr    error
	ImPullCalled bool

	// ImageList
	ImListResp   []types.ImageSummary
	ImListErr    error
	ImListCalled bool

	// ContainerCreate
	CCreateBody   container.ContainerCreateCreatedBody
	CCreateErr    error
	CCreateCalled bool
	CCreateArgs   CCreateArgs

	// ContainerRemove
	CRemoveErr    error
	CRemoveCalled bool

	// ContainerStart
	CStartErr    error
	CStartCalled bool

	// ConstainerStop
	CStopErr    error
	CStopCalled bool

	// ConstainerRestart
	CRestartErr    error
	CRestartCalled bool

	// ContainerList
	CListResp   []types.Container
	CListErr    error
	CListCalled bool

	// ContainerInspect
	CInspectResp   types.ContainerJSON
	CInspectErr    error
	CInspectCalled bool
}

// CreateDockerClientStub returns stub implementing DockerClient interface
func CreateDockerClientStub() (wrappers.DockerClient, error) {
	return &DockerCliStub, CreateDCSErr
}

// ImageLoad implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ImageLoad(ctx context.Context, input io.Reader,
	quiet bool) (types.ImageLoadResponse, error) {
	dcs.ImLoadCalled = true
	return dcs.ImLoadResp, dcs.ImLoadErr
}

// ImageTag implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ImageTag(ctx context.Context, source, target string) error {
	dcs.ImTagCalled = true
	return dcs.ImTagErr
}

// ImageRemove implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ImageRemove(ctx context.Context, imageID string,
	options types.ImageRemoveOptions) ([]types.ImageDeleteResponseItem, error) {
	dcs.ImRemoveCalled = true
	return dcs.ImRemoveResp, dcs.ImRemoveErr
}

// ImagePull implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ImagePull(ctx context.Context, ref string,
	options types.ImagePullOptions) (io.ReadCloser, error) {
	dcs.ImPullCalled = true
	return dcs.ImPullResp, dcs.ImPullErr
}

// ImageList implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ImageList(ctx context.Context,
	options types.ImageListOptions) ([]types.ImageSummary, error) {
	dcs.ImListCalled = true
	return dcs.ImListResp, dcs.ImListErr
}

// ContainerCreate implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ContainerCreate(ctx context.Context,
	config *container.Config, hostConfig *container.HostConfig,
	networkingConfig *network.NetworkingConfig,
	containerName string) (container.ContainerCreateCreatedBody, error) {
	dcs.CCreateCalled = true
	dcs.CCreateArgs = CCreateArgs{config, hostConfig, networkingConfig, containerName}
	return dcs.CCreateBody, dcs.CCreateErr
}

// ContainerRemove implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ContainerRemove(ctx context.Context,
	containerID string, options types.ContainerRemoveOptions) error {
	dcs.CRemoveCalled = true
	return dcs.CRemoveErr
}

// ContainerStart implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ContainerStart(ctx context.Context,
	containerID string, options types.ContainerStartOptions) error {
	dcs.CStartCalled = true
	return dcs.CStartErr
}

// ContainerStop implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ContainerStop(ctx context.Context,
	containerID string, timeout *time.Duration) error {
	dcs.CStopCalled = true
	return dcs.CStopErr
}

// ContainerRestart implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ContainerRestart(ctx context.Context,
	containerID string, timeout *time.Duration) error {
	dcs.CRestartCalled = true
	return dcs.CRestartErr
}

// ContainerList implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ContainerList(ctx context.Context,
	options types.ContainerListOptions) ([]types.Container, error) {
	dcs.CListCalled = true
	return dcs.CListResp, dcs.CListErr
}

// ContainerInspect implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ContainerInspect(ctx context.Context,
	containerID string) (types.ContainerJSON, error) {
	dcs.CInspectCalled = true
	return dcs.CInspectResp, dcs.CInspectErr
}
