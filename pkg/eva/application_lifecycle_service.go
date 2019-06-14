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
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	metadata "github.com/smartedgemec/appliance-ce/pkg/app-metadata"
	elapb "github.com/smartedgemec/appliance-ce/pkg/ela/pb"
	pb "github.com/smartedgemec/appliance-ce/pkg/eva/pb"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	libvirt "github.com/libvirt/libvirt-go"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ApplicationLifecycleServiceServer struct {
	cfg  *Config
	meta *metadata.AppMetadata
}

type ContainerHandler struct {
	meta *metadata.DeployedApp
}

type VMHandler struct {
	meta *metadata.DeployedApp
}

type ApplicationLifecycleServiceHandler interface {
	UpdateStatus(elapb.LifecycleStatus_Status) error
	StartHandler(context.Context, time.Duration) error
	StopHandler(context.Context, time.Duration) error
	RestartHandler(context.Context, time.Duration) error
}

func (c *ContainerHandler) UpdateStatus(
	status elapb.LifecycleStatus_Status) error {
	return updateStatus(c.meta, status)
}

func (v *VMHandler) UpdateStatus(status elapb.LifecycleStatus_Status) error {
	return updateStatus(v.meta, status)
}

func updateStatus(m *metadata.DeployedApp,
	status elapb.LifecycleStatus_Status) error {
	m.App.Status = status
	err := m.Save(true)
	if err != nil {
		log.Errf("Failed to set LifecycleStatus:%v for:%v err:%v", status,
			m.DeployedID, err)
	}
	return err
}

func (c ContainerHandler) StartHandler(ctx context.Context,
	timeout time.Duration) error {

	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return errors.Wrap(err, "failed to create docker client")
	}

	err = cli.ContainerStart(ctx, c.meta.DeployedID,
		types.ContainerStartOptions{})
	if err != nil {
		return errors.Wrapf(err, "failed to start container with ID: %v",
			c.meta.DeployedID)
	}

	log.Infof("Container ID:%v started", c.meta.DeployedID)
	return nil
}

func (c ContainerHandler) StopHandler(ctx context.Context,
	timeout time.Duration) error {

	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return errors.Wrap(err, "failed to create docker client")
	}

	err = cli.ContainerStop(ctx, c.meta.DeployedID, &timeout)
	if err != nil {
		return errors.Wrapf(err, "failed to stop container with ID: %v",
			c.meta.DeployedID)
	}

	log.Infof("Container ID:%v stopped", c.meta.DeployedID)
	return nil
}

func (c ContainerHandler) RestartHandler(ctx context.Context,
	timeout time.Duration) error {

	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return errors.Wrap(err, "failed to create docker client")
	}

	err = cli.ContainerRestart(ctx, c.meta.DeployedID, &timeout)
	if err != nil {
		return errors.Wrapf(err, "failed to restart container with ID: %v",
			c.meta.DeployedID)
	}

	log.Infof("Container ID:%v restarted", c.meta.DeployedID)
	return nil
}

func waitForDomStateChange(dom *libvirt.Domain, expected libvirt.DomainState,
	timeoutDuration time.Duration) (bool, error) {

	tout := time.After(timeoutDuration)

	for {
		select {
		case <-tout:
			return true, nil
		default:
			state, _, err := dom.GetState()
			if err != nil {
				return false, err
			}

			if state == expected {
				return false, nil
			}
		}
	}
}

func (v VMHandler) StartHandler(ctx context.Context,
	timeout time.Duration) error {

	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return err
	}
	defer conn.Close()

	d, err := conn.LookupDomainByName(v.meta.DeployedID)
	if err != nil {
		return err
	}
	defer func() { _ = d.Free() }()

	err = d.Create()
	if err != nil {
		return err
	}

	tout, err := waitForDomStateChange(d, libvirt.DOMAIN_RUNNING, timeout)
	if err != nil {
		return err
	}

	if tout {
		return errors.New("Timeout when starting domain: " + v.meta.DeployedID)
	}

	return nil
}

func (v VMHandler) StopHandler(ctx context.Context,
	timeout time.Duration) error {

	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return err
	}
	defer conn.Close()

	d, err := conn.LookupDomainByName(v.meta.DeployedID)
	if err != nil {
		return err
	}
	defer func() { _ = d.Free() }()

	state, _, err := d.GetState()
	if err != nil {
		return err
	}

	if state == libvirt.DOMAIN_SHUTOFF {
		return nil
	}

	err = d.Shutdown()
	if err != nil {
		return err
	}

	tout, err := waitForDomStateChange(d, libvirt.DOMAIN_SHUTDOWN, timeout)
	if err != nil {
		return err
	}

	if tout {
		return d.Destroy()
	}

	return nil
}

func (v VMHandler) RestartHandler(ctx context.Context,
	timeout time.Duration) error {

	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return err
	}
	defer conn.Close()

	d, err := conn.LookupDomainByName(v.meta.DeployedID)
	if err != nil {
		return err
	}
	defer func() { _ = d.Free() }()

	err = d.Reboot(libvirt.DOMAIN_REBOOT_DEFAULT)
	if err != nil {
		return err
	}

	tout, err := waitForDomStateChange(d, libvirt.DOMAIN_SHUTDOWN, timeout)
	if err != nil {
		return err
	}

	if tout {
		err := d.Destroy()
		if err != nil {
			return err
		}

		err = d.Create()
		if err != nil {
			return err
		}
		return nil
	}

	return nil
}

func (s *ApplicationLifecycleServiceServer) Start(ctx context.Context,
	l *pb.LifecycleCommand) (*empty.Empty, error) {

	if l == nil {
		return nil, errors.New("Start failed because LifecycleCommand is nil")
	}

	d, err := s.getAppLifecycleHandler(l.Id)
	if err != nil {
		log.Errf("Start failed because application type identification failed:"+
			" %+v", err)
		return nil,
			errors.Wrapf(err,
				"failed to identify type of application with ID: %s",
				l.Id)
	}

	if err = d.UpdateStatus(elapb.LifecycleStatus_STARTING); err != nil {
		return nil, errors.Wrapf(err, "Failed to update status for appID: %s",
			l.Id)
	}

	err = d.StartHandler(ctx, s.cfg.AppStartTimeout.Duration)
	if err != nil {
		log.Errf("Start failed because: %+v", err)
		return nil,
			errors.Wrapf(err, "failed to handle Start for app with ID: %s",
				l.Id)
	}

	_ = d.UpdateStatus(elapb.LifecycleStatus_RUNNING)

	return &empty.Empty{}, nil
}

func (s *ApplicationLifecycleServiceServer) Stop(ctx context.Context,
	l *pb.LifecycleCommand) (*empty.Empty, error) {

	if l == nil {
		return nil, errors.New("Stop failed because LifecycleCommand is nil")
	}

	d, err := s.getAppLifecycleHandler(l.Id)
	if err != nil {
		log.Errf("Stop failed because application type identification failed:"+
			" %+v", err)
		return nil,
			errors.Wrapf(err,
				"failed to identify type of application with ID: %s",
				l.Id)
	}

	if err = d.UpdateStatus(elapb.LifecycleStatus_STOPPING); err != nil {
		return nil, errors.Wrapf(err, "Failed to update status for appID: %s",
			l.Id)
	}

	err = d.StopHandler(ctx, s.cfg.AppStopTimeout.Duration)
	if err != nil {
		log.Errf("Stop failed because: %+v", err)
		return nil,
			errors.Wrapf(err, "failed to handle Stop for app with ID: %s",
				l.Id)
	}

	_ = d.UpdateStatus(elapb.LifecycleStatus_STOPPED)

	return &empty.Empty{}, nil
}

func (s *ApplicationLifecycleServiceServer) Restart(ctx context.Context,
	l *pb.LifecycleCommand) (*empty.Empty, error) {

	if l == nil {
		return nil, errors.New("Restart failed because LifecycleCommand is nil")
	}

	d, err := s.getAppLifecycleHandler(l.Id)
	if err != nil {
		log.Errf("Restart failed because application type identification "+
			"failed: %+v", err)
		return nil,
			errors.Wrapf(err,
				"failed to identify type of application with ID: %s",
				l.Id)
	}

	if err = d.UpdateStatus(elapb.LifecycleStatus_STARTING); err != nil {
		return nil, errors.Wrapf(err, "Failed to update status for appID: %s",
			l.Id)
	}

	err = d.RestartHandler(ctx, s.cfg.AppRestartTimeout.Duration)
	if err != nil {
		log.Errf("Restart failed because: %+v",
			err)
		return nil,
			errors.Wrapf(err, "failed to handle Restart for app with ID: %s",
				l.Id)
	}

	_ = d.UpdateStatus(elapb.LifecycleStatus_RUNNING)

	return &empty.Empty{}, nil
}

func (s *ApplicationLifecycleServiceServer) GetStatus(ctx context.Context,
	app *pb.ApplicationID) (*elapb.LifecycleStatus, error) {

	dapp, err := s.meta.Load(app.Id)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "App %v not found: %v",
			app.Id, err)
	}

	return &elapb.LifecycleStatus{Status: dapp.App.Status}, nil
}

func (s *ApplicationLifecycleServiceServer) getAppLifecycleHandler(
	appID string) (ApplicationLifecycleServiceHandler, error) {

	a, err := s.meta.Load(appID)
	if err != nil {
		return nil, err
	}
	if a.DeployedID == "" {
		return nil, errors.New("deployed ID is empty")
	}

	var handler ApplicationLifecycleServiceHandler
	if a.Type == metadata.Container {
		handler = &ContainerHandler{a}
	} else {
		handler = &VMHandler{a}
	}

	return handler, nil
}
