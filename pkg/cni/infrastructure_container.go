// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package cni

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	logger "github.com/open-ness/common/log"
	"github.com/open-ness/edgenode/internal/wrappers"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
)

var (
	log = logger.DefaultLogger.WithField("cni", nil)
)

const (
	// Reference (URL and name) of the infrastructure container
	infraContainerImageRef     = "gcr.io/google-containers/pause:3.1"
	infraContainerNameTemplate = "OPENNESS-CNI-INFRASTRUCTURE_%s"
)

// InfrastructureContainerInfo contains information regarding the infrastructure container
type InfrastructureContainerInfo struct {
	ID    string // Infrastructure Container's ID (SHA)
	PID   int    // Infrastructure Container's PID
	AppID string // ID of an application tied to the infrastructure container
	Name  string // Docker name of infrastructure container

	docker wrappers.DockerClient
}

// NewInfrastructureContainerInfo creates new InfrastructureContainerInfo
func NewInfrastructureContainerInfo(appID string) InfrastructureContainerInfo {
	return InfrastructureContainerInfo{
		AppID: appID,
		Name:  fmt.Sprintf(infraContainerNameTemplate, appID),
	}
}

// QueryDocker tries to obtain Container's ID and PIDs
func (i *InfrastructureContainerInfo) QueryDocker(ctx context.Context) error {
	if err := i.createDockerClient(); err != nil {
		return err
	}

	if err := i.obtainContainerID(ctx); err != nil {
		return err
	}

	if err := i.obtainContainerPID(ctx); err != nil {
		return err
	}

	return nil
}

func (i *InfrastructureContainerInfo) createDockerClient() error {
	if i.docker == nil {
		docker, err := wrappers.CreateDockerClient()
		if err != nil {
			log.Errf("failed to create a docker client: %s", err.Error())
			return err
		}
		i.docker = docker
	}
	return nil
}

func makeSureInfraContainerImageExists(ctx context.Context, docker wrappers.DockerClient) error {
	filterArgs := filters.NewArgs()
	filterArgs.Add("reference", infraContainerImageRef)

	imageSummaries, err := docker.ImageList(ctx, types.ImageListOptions{Filters: filterArgs})
	if err != nil {
		return err
	}

	if len(imageSummaries) == 0 {
		log.Debugf("Infra container: image not present - pulling '%s'", infraContainerImageRef)
		rc, err := docker.ImagePull(ctx, infraContainerImageRef, types.ImagePullOptions{})
		if err != nil {
			log.Errf("Infra container: image pull failed: %s", err.Error())
			return err
		}
		defer func() {
			if closeErr := rc.Close(); closeErr != nil {
				log.Errf("Infra container: failed to close the rc: %s", closeErr.Error())
			}
		}()

		if _, err = io.Copy(ioutil.Discard, rc); err != nil { // rc needs to be consumed
			log.Errf("Infra container: image pull failed: %s", err.Error())
			return err
		}

		log.Debugf("Infra container: image pull successful")
	}

	return nil
}

func (i *InfrastructureContainerInfo) obtainContainerID(ctx context.Context) error {

	filterArgs := filters.NewArgs()
	filterArgs.Add("name", i.Name)

	containerSummaries, err := i.docker.ContainerList(ctx, types.ContainerListOptions{All: true, Filters: filterArgs})
	if err != nil {
		log.Errf("Infra container: search failed. Name='%s', Reason='%+v'", i.Name, err)
		return err
	}

	if len(containerSummaries) != 0 {
		i.ID = containerSummaries[0].ID
	}

	return nil
}

// Create creates the infrastructure docker container
func (i *InfrastructureContainerInfo) Create(ctx context.Context) error {
	if err := i.QueryDocker(ctx); err != nil {
		return err
	}

	if err := makeSureInfraContainerImageExists(ctx, i.docker); err != nil {
		return err
	}

	if err := i.obtainContainerID(ctx); err != nil {
		return err
	}

	if i.ID == "" {
		log.Debugf("Infra container: creating. App='%s'", i.AppID)

		result, err := i.docker.ContainerCreate(ctx,
			&container.Config{Image: infraContainerImageRef},
			&container.HostConfig{NetworkMode: "none"},
			&network.NetworkingConfig{},
			i.Name)

		if err != nil {
			log.Errf("Infra container: failed to create. AppID='%s', Reason='%+v'", i.AppID, err)
			return err
		}
		log.Debugf("Infra container: created. AppID='%s', ContainerID='%s'", i.AppID, result.ID[:8])
		i.ID = result.ID
	} else {
		log.Debugf("Infra container: already exists. AppID='%s', ContainerID='%s'", i.AppID, i.ID)
	}

	return nil
}

func (i *InfrastructureContainerInfo) obtainContainerPID(ctx context.Context) error {
	if i.ID == "" {
		return nil
	}

	containerInfo, err := i.docker.ContainerInspect(ctx, i.ID)
	if err != nil {
		return err
	}

	if containerInfo.State.Running {
		i.PID = containerInfo.State.Pid
	}

	return nil
}

// Start starts the infrastructure docker container
func (i *InfrastructureContainerInfo) Start(ctx context.Context) error {
	if err := i.QueryDocker(ctx); err != nil {
		return err
	}

	if i.PID == 0 {
		if err := i.docker.ContainerStart(ctx, i.ID, types.ContainerStartOptions{}); err != nil {
			log.Errf("Infra container: failed to start. ContainerID='%s', Reason='%+v'", i.ID[:8], err)
			return err
		}

		if err := i.obtainContainerPID(ctx); err != nil {
			log.Errf("Infra container: failed to get PID. ContainerID='%s', Reason='%+v'", i.ID[:8], err)
			return err
		}
		log.Debugf("Infra container: started. AppID='%s', ContainerID='%s', PID='%v'", i.AppID, i.ID[:8], i.PID)
	} else {
		log.Debugf("Infra container: already running. AppID='%s', ContainerID='%s', PID='%v'", i.AppID, i.ID[:8], i.PID)
	}

	return nil
}

// Stop stops infrastructure container
// It does not return an error if container does not exist or is already stopped
func (i *InfrastructureContainerInfo) Stop(ctx context.Context) error {
	if err := i.QueryDocker(ctx); err != nil {
		return err
	}

	if i.ID == "" {
		log.Debugf("Infra container: does not exist - won't stop. AppID='%s'", i.AppID)
		return nil
	}

	log.Debugf("Infra container: stopping. AppID='%s', ContainerID='%s'", i.ID[:8], i.AppID)

	timeout := time.Second * 10
	if err := i.docker.ContainerStop(ctx, i.ID, &timeout); err != nil {
		log.Debugf("Infra container: failed to stop. AppID='%s', ContainerID='%s', Reason='%+v'", i.AppID, i.ID, err)
		return err
	}

	log.Debugf("Infra container: stopped. AppID='%s', ContainerID='%s'", i.ID[:8], i.AppID)

	return nil
}

// Remove removes infrastructure container
// It does not return an error if container does not exist.
func (i *InfrastructureContainerInfo) Remove(ctx context.Context) error {
	if err := i.QueryDocker(ctx); err != nil {
		return err
	}

	if i.ID == "" {
		log.Debugf("Infra container: does not exist - won't remove. AppID='%s'", i.AppID)
		return nil
	}

	log.Debugf("Infra container: removing. AppID='%s', ContainerID='%s'", i.AppID, i.ID[:8])

	if err := i.docker.ContainerRemove(ctx, i.ID, types.ContainerRemoveOptions{Force: true}); err != nil {
		log.Debugf("Infra container: failed to remove. AppID='%s', ContainerID='%s', Reason='%+v'", i.AppID, i.ID, err)
		return err
	}
	log.Debugf("Infra container: removed. AppID='%s', ContainerID='%s'", i.AppID, i.ID[:8])

	return nil
}
