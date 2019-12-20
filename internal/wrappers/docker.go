// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package wrappers

import (
	"context"
	"io"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
)

// DockerClient is the interface that wraps Docker client methods
type DockerClient interface {
	ImageLoad(ctx context.Context, input io.Reader,
		quiet bool) (types.ImageLoadResponse, error)
	ImageTag(ctx context.Context, source, target string) error
	ImageRemove(ctx context.Context, imageID string,
		options types.ImageRemoveOptions) ([]types.ImageDeleteResponseItem,
		error)
	ContainerCreate(ctx context.Context, config *container.Config,
		hostConfig *container.HostConfig,
		networkingConfig *network.NetworkingConfig,
		containerName string) (container.ContainerCreateCreatedBody, error)
	ContainerRemove(ctx context.Context, containerID string,
		options types.ContainerRemoveOptions) error
	ContainerStart(ctx context.Context, containerID string,
		options types.ContainerStartOptions) error
	ContainerStop(ctx context.Context, containerID string,
		timeout *time.Duration) error
	ContainerRestart(ctx context.Context, containerID string,
		timeout *time.Duration) error
}

// CreateDockerClient creates Docker client
var CreateDockerClient = func() (DockerClient, error) {
	return client.NewClientWithOpts(client.FromEnv)
}
