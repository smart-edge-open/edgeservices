// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

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

// DockerClientStub struct implementation
type DockerClientStub struct {
	ImLoadResp  types.ImageLoadResponse
	ImRemResp   []types.ImageDeleteResponseItem
	CCreateBody container.ContainerCreateCreatedBody
	ImLoadErr   error
	ImTagErr    error
	ImRemoveErr error
	CCreateErr  error
	CRemoveErr  error
	CStartErr   error
	CStopErr    error
	CRestartErr error
}

// CreateDockerClientStub returns stub implementing DockerClient interface
func CreateDockerClientStub() (wrappers.DockerClient, error) {
	return &DockerCliStub, CreateDCSErr
}

// ImageLoad implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ImageLoad(ctx context.Context, input io.Reader,
	quiet bool) (types.ImageLoadResponse, error) {
	return dcs.ImLoadResp, dcs.ImLoadErr
}

// ImageTag implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ImageTag(ctx context.Context, source,
	target string) error {
	return dcs.ImTagErr
}

// ImageRemove implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ImageRemove(ctx context.Context, imageID string,
	options types.ImageRemoveOptions) ([]types.ImageDeleteResponseItem,
	error) {
	return dcs.ImRemResp, dcs.ImLoadErr
}

// ContainerCreate implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ContainerCreate(ctx context.Context,
	config *container.Config, hostConfig *container.HostConfig,
	networkingConfig *network.NetworkingConfig,
	containerName string) (container.ContainerCreateCreatedBody, error) {
	return dcs.CCreateBody, dcs.CCreateErr
}

// ContainerRemove implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ContainerRemove(ctx context.Context,
	containerID string, options types.ContainerRemoveOptions) error {
	return dcs.CRemoveErr
}

// ContainerStart implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ContainerStart(ctx context.Context,
	containerID string, options types.ContainerStartOptions) error {
	return dcs.CStartErr
}

// ContainerStop implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ContainerStop(ctx context.Context,
	containerID string, timeout *time.Duration) error {
	return dcs.CStopErr
}

// ContainerRestart implements stub for corresponding method from DockerClient
func (dcs *DockerClientStub) ContainerRestart(ctx context.Context,
	containerID string, timeout *time.Duration) error {
	return dcs.CRestartErr
}
