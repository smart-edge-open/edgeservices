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

package eva

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes/empty"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/pkg/errors"
	metadata "github.com/smartedgemec/appliance-ce/pkg/app-metadata"
	"github.com/smartedgemec/appliance-ce/pkg/ela/pb"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type DeploySrv struct {
	cfg  *Config
	meta *metadata.AppMetadata
}

const imageFile string = "image"

func downloadImage(url string) error {
	var input io.Reader

	if strings.Contains(url, "http://") {
		client := &http.Client{Timeout: time.Minute * 5}
		resp, err := client.Get(url)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		input = resp.Body
	} else {
		file, err := os.Open(url)
		if err != nil {
			return err
		}
		defer file.Close()
		input = file
	}

	output, err := os.Create(imageFile)
	if err != nil {
		return err
	}
	_, err = io.Copy(output, input)
	output.Close()

	log.Infof("Downloaded %v", url)

	return err
}

func (s *DeploySrv) sanitizeApplication(app *pb.Application) error {
	c := s.cfg

	if app.Cores <= 0 {
		return fmt.Errorf("Cores value incorrect: %v", app.Cores)
	} else if app.Cores > c.MaxCores {
		return fmt.Errorf("Cores value over limit: %v > %v",
			app.Cores, c.MaxCores)
	}

	if app.Memory <= 0 {
		return fmt.Errorf("Memory value incorrect: %v", app.Memory)
	} else if app.Memory > c.MaxAppMem {
		return fmt.Errorf("Memory value over limit: %v > %v",
			app.Memory, c.MaxAppMem)
	}

	return nil
}

func (s *DeploySrv) deployCommon(ctx context.Context,
	dapp *metadata.DeployedApp) error {

	if err := s.sanitizeApplication(dapp.App); err != nil {
		return err
	}
	app2, err := s.meta.Load(dapp.App.Id)
	if err == nil && app2.IsDeployed {
		return fmt.Errorf("app %s already deployed", dapp.App.Id)
	}

	// TODO: either fix unmarshall of dapp.App.Source
	// or store the url directly in the DeployedApp structure
	source := dapp.App.Source
	dapp.App.Source = nil // reset source as can't unmarshall this
	if err = dapp.Save(); err != nil {
		return err
	}

	/* Now download the image. */
	switch s := source.(type) {
	case *pb.Application_HttpUri:
		return downloadImage(s.HttpUri.HttpUri)
	default:
		return errors.New("Unimplemented Application.Source")
	}
}

func parseImageName(body io.Reader) (string, error) {
	type jsonOut struct {
		Stream string
	}
	var parsed jsonOut

	bytes, err := ioutil.ReadAll(body)
	if err != nil {
		return "", errors.Wrap(err, "failed to get docker image name from JSON")
	}
	err = json.Unmarshal(bytes, &parsed)
	if err != nil {
		return "", errors.Wrap(err, "failed to parse out docker image name")
	}
	out := strings.Replace(parsed.Stream, "Loaded image ID: ", "", 1)
	out = strings.Replace(out, "Loaded image: ", "", 1)

	return out[0 : len(out)-1], nil // cut '\n'
}

func (s *DeploySrv) DeployContainer(ctx context.Context,
	pbapp *pb.Application) (*empty.Empty, error) {

	var imageName string
	dapp := s.meta.NewDeployedApp(metadata.Container, pbapp)
	if err := s.deployCommon(ctx, dapp); err != nil {
		return nil, err
	}

	/* Now call the docker API. */
	docker, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create a docker client")
	}

	/* NOTE: this could read directly from our HTTP stream that's
	 * downloading the image, thus removing the need for storing the image as
	 * a file. But store for now for easier debugging. */
	file, err := os.Open(imageFile)
	if err != nil {
		return nil, err /* shouldn't happen as we just wrote it */
	}
	if resp, err := docker.ImageLoad(ctx, file, true); err == nil {
		defer resp.Body.Close()
		if !resp.JSON {
			return nil, fmt.Errorf("No JSON output loading app %s", pbapp.Id)
		}
		imageName, err = parseImageName(resp.Body)
		if err != nil {
			return nil, err
		}
		if err = docker.ImageTag(ctx, imageName, pbapp.Id); err != nil {
			return nil, err
		}
		log.Infof("Image imported as '%v'", imageName)
	} else {
		return nil, errors.Wrap(err, "Failed to ImageLoad() the docker image")
	}

	resources := container.Resources{
		Memory:    int64(pbapp.Memory) * 1024,
		CPUShares: int64(pbapp.Cores),
	}
	if resp, err := docker.ContainerCreate(ctx,
		&container.Config{Image: pbapp.Id},
		&container.HostConfig{Resources: resources},
		nil, pbapp.Id); err == nil {

		log.Infof("Created a container with id %v", resp.ID)
		if err = dapp.SetDeployed(resp.ID); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.Wrap(err, "ContinerCreate failed")
	}

	return &empty.Empty{}, nil
}

func (s *DeploySrv) DeployVM(ctx context.Context,
	pbapp *pb.Application) (*empty.Empty, error) {

	dapp := s.meta.NewDeployedApp(metadata.VM, pbapp)
	if err := s.deployCommon(ctx, dapp); err != nil {
		return nil, err
	}

	/* Now call the libvirt API. */

	return &empty.Empty{}, nil
}

func (s *DeploySrv) Redeploy(ctx context.Context,
	app *pb.Application) (*empty.Empty, error) {

	return nil, nil
}

func dockerUndeploy(ctx context.Context,
	dapp *metadata.DeployedApp) error {
	docker, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return errors.Wrap(err, "Failed to create a docker client")
	}

	if dapp.DeployedID != "" {
		err = docker.ContainerRemove(ctx, dapp.DeployedID,
			types.ContainerRemoveOptions{RemoveVolumes: false,
				RemoveLinks: false, Force: false})
		if err != nil {
			return errors.Wrapf(err, "Undeploy(%s)", dapp.DeployedID)
		}
		log.Infof("Removed container %v", dapp.DeployedID)
	}
	_, err = docker.ImageRemove(ctx, dapp.App.Id,
		types.ImageRemoveOptions{Force: false, PruneChildren: true})
	log.Infof("Docker image %v removed", dapp.App.Id)
	if err != nil {
		return err
	}

	return dapp.SetUndeployed()
}

func (s *DeploySrv) Undeploy(ctx context.Context,
	app *pb.ApplicationID) (*empty.Empty, error) {

	log.Infof("Undeploy(%s) running", app.Id)
	dapp, err := s.meta.Load(app.Id)
	if err != nil {
		return nil, errors.Wrapf(err, "Application %v not found", app.Id)
	}
	if !dapp.IsDeployed {
		return nil, fmt.Errorf("Application %v is not deployed", app.Id)
	}

	switch dapp.Type {
	case metadata.Container:
		err = dockerUndeploy(ctx, dapp)
	default:
		err = status.Errorf(codes.Unimplemented, "not implemented")
	}

	if err == nil {
		if os.Remove(imageFile) == nil {
			log.Infof("Deleted image file %s", imageFile)
		}
	}

	return &empty.Empty{}, err
}
