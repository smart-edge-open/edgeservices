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
