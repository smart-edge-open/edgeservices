// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

package eva

import (
	"context"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/open-ness/edgenode/internal/wrappers"
	metadata "github.com/open-ness/edgenode/pkg/app-metadata"
	"github.com/open-ness/edgenode/pkg/cni"
	pb "github.com/open-ness/edgenode/pkg/eva/pb"

	"github.com/docker/docker/api/types"
	libvirt "github.com/libvirt/libvirt-go"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// contextDurationAddition is a duration added to timeouts to make sure
	// context does not end before libvirt/docker timeouts
	contextDurationAddition = 2 * time.Second
)

// ApplicationLifecycleServiceServer describers
// application lifecycle service server
type ApplicationLifecycleServiceServer struct {
	cfg  *Config
	meta *metadata.AppMetadata
}

// ContainerHandler describes handler for container
type ContainerHandler struct {
	meta   *metadata.DeployedApp
	useCNI bool
}

// VMHandler VM Handler interface
type VMHandler struct {
	meta *metadata.DeployedApp
}

// ApplicationLifecycleServiceHandler interface for handlers
type ApplicationLifecycleServiceHandler interface {
	UpdateStatus(pb.LifecycleStatus_Status) error
	StartHandler(context.Context, time.Duration) error
	StopHandler(context.Context, time.Duration) error
	RestartHandler(context.Context, time.Duration) error
	getMetadata() *metadata.DeployedApp
}

func (c *ContainerHandler) getMetadata() *metadata.DeployedApp {
	return c.meta
}

func (v *VMHandler) getMetadata() *metadata.DeployedApp {
	return v.meta
}

// CreateLibvirtConnection stores function returning ConnectInterface
var CreateLibvirtConnection = func(uri string) (wrappers.ConnectInterface,
	error) {
	return wrappers.NewConnect(uri)
}

// UpdateStatus updates a status
func (c *ContainerHandler) UpdateStatus(
	status pb.LifecycleStatus_Status) error {
	return updateStatus(c.meta, status)
}

// UpdateStatus update a status
func (v *VMHandler) UpdateStatus(status pb.LifecycleStatus_Status) error {
	return updateStatus(v.meta, status)
}

func updateStatus(m *metadata.DeployedApp,
	status pb.LifecycleStatus_Status) error {
	m.App.Status = status
	err := m.Save(true)
	if err != nil {
		log.Errf("Failed to set LifecycleStatus:%v for:%v err:%v", status,
			m.DeployedID, err)
	}
	return err
}

// StartHandler is a start handler
func (c ContainerHandler) StartHandler(ctx context.Context,
	timeout time.Duration) error {

	if c.useCNI {
		err := cni.StartInfrastructureContainer(ctx, c.meta)

		if err != nil {
			log.Errf("Failed to start infrastructure container. AppID=%s, Reason=%s", c.meta.App.Id, err.Error())
			return err
		}
	}

	cli, err := wrappers.CreateDockerClient()
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

// StopHandler is a stop handler
func (c ContainerHandler) StopHandler(ctx context.Context,
	timeout time.Duration) error {

	cli, err := wrappers.CreateDockerClient()
	if err != nil {
		return errors.Wrap(err, "failed to create docker client")
	}

	err = cli.ContainerStop(ctx, c.meta.DeployedID, &timeout)
	if err != nil {
		return errors.Wrapf(err, "failed to stop container with ID: %v",
			c.meta.DeployedID)
	}

	log.Infof("Container ID:%v stopped", c.meta.DeployedID)

	if c.useCNI {
		err := cni.StopInfrastructureContainer(ctx, c.meta)
		if err != nil {
			log.Errf("Failed to start infrastructure container. AppID=%s, Reason=%s", c.meta.App.Id, err.Error())
			return err
		}
	}

	return nil
}

// RestartHandler is a restart handler
func (c ContainerHandler) RestartHandler(ctx context.Context,
	timeout time.Duration) error {

	cli, err := wrappers.CreateDockerClient()
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

func waitForDomStateChange(dom wrappers.DomainInterface,
	expected libvirt.DomainState, timeoutDuration time.Duration) (bool, error) {

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

// StartHandler is a handler for start
func (v VMHandler) StartHandler(ctx context.Context,
	timeout time.Duration) error {

	conn, err := CreateLibvirtConnection("qemu:///system")
	if err != nil {
		return err
	}
	defer func() {
		if c, err1 := conn.Close(); err1 != nil || c < 0 {
			log.Errf("Failed to close libvirt connection: code: %v, error: %v",
				c, err1)
		}
	}()

	d, err := conn.LookupDomainByName(v.meta.DeployedID)
	if err != nil {
		return err
	}
	defer func() { _ = d.Free() }()

	return startVM(d, timeout, v)
}

// StopHandler is a stop handler
func (v VMHandler) StopHandler(ctx context.Context,
	timeout time.Duration) error {

	conn, err := CreateLibvirtConnection("qemu:///system")
	if err != nil {
		return err
	}
	defer func() {
		if c, err1 := conn.Close(); err1 != nil || c < 0 {
			log.Errf("Failed to close libvirt connection: code: %v, error: %v",
				c, err1)
		}
	}()

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

// RestartHandler is a restart handler
func (v VMHandler) RestartHandler(ctx context.Context,
	timeout time.Duration) error {

	conn, err := CreateLibvirtConnection("qemu:///system")
	if err != nil {
		return err
	}
	defer func() {
		if c, err1 := conn.Close(); err1 != nil || c < 0 {
			log.Errf("Failed to close libvirt connection: code: %v, error: %v",
				c, err1)
		}
	}()

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
		return startVM(d, timeout, v)
	}
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

func startVM(d wrappers.DomainInterface, timeout time.Duration,
	v VMHandler) error {
	if err := d.Create(); err != nil {
		return err
	}

	tout, err := waitForDomStateChange(d, libvirt.DOMAIN_RUNNING, timeout)
	if err != nil {
		return err
	}

	if tout {
		return errors.New("Timeout when starting domain: " +
			v.meta.DeployedID)
	}
	return nil
}

// Start do the start
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

	metadata := d.getMetadata()
	if err = metadata.IsChangeAllowed(pb.LifecycleStatus_STARTING); err != nil {
		return nil, err
	}

	if err = d.UpdateStatus(pb.LifecycleStatus_STARTING); err != nil {
		return nil, errors.Wrapf(err, "Failed to update status for appID: %s",
			l.Id)
	}

	go func() {
		startCtx, cancel := context.WithTimeout(context.Background(),
			s.cfg.AppStartTimeout.Duration+contextDurationAddition)
		defer cancel()

		if err := d.StartHandler(startCtx,
			s.cfg.AppStartTimeout.Duration); err != nil {

			log.Errf("Start(%s) failed because: %+v", metadata.App.Id, err)
			_ = d.UpdateStatus(pb.LifecycleStatus_ERROR)
			return
		}

		_ = d.UpdateStatus(pb.LifecycleStatus_RUNNING)
	}()

	return &empty.Empty{}, nil
}

// Stop stops the app
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

	metadata := d.getMetadata()
	if err = metadata.IsChangeAllowed(pb.LifecycleStatus_STOPPING); err != nil {
		return nil, err
	}

	if err = d.UpdateStatus(pb.LifecycleStatus_STOPPING); err != nil {
		return nil, errors.Wrapf(err, "Failed to update status for appID: %s",
			l.Id)
	}

	go func() {
		stopCtx, cancel := context.WithTimeout(context.Background(),
			s.cfg.AppStopTimeout.Duration+contextDurationAddition)
		defer cancel()

		if err := d.StopHandler(stopCtx,
			s.cfg.AppStopTimeout.Duration); err != nil {

			log.Errf("Stop(%s) failed because: %+v", metadata.App.Id, err)
			_ = d.UpdateStatus(pb.LifecycleStatus_ERROR)
			return
		}

		_ = d.UpdateStatus(pb.LifecycleStatus_STOPPED)
	}()

	return &empty.Empty{}, nil
}

// Restart do the restart
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

	metadata := d.getMetadata()
	if err = metadata.IsChangeAllowed(pb.LifecycleStatus_STARTING); err != nil {
		return nil, err
	}

	if err = d.UpdateStatus(pb.LifecycleStatus_STARTING); err != nil {
		return nil, errors.Wrapf(err, "Failed to update status for appID: %s",
			l.Id)
	}

	go func() {
		restartCtx, cancel := context.WithTimeout(context.Background(),
			s.cfg.AppRestartTimeout.Duration+contextDurationAddition)
		defer cancel()

		err := d.RestartHandler(restartCtx, s.cfg.AppRestartTimeout.Duration)
		if err != nil {
			log.Errf("Restart(%s) failed because: %+v", metadata.App.Id, err)
			_ = d.UpdateStatus(pb.LifecycleStatus_ERROR)
			return
		}

		_ = d.UpdateStatus(pb.LifecycleStatus_RUNNING)
	}()

	return &empty.Empty{}, nil
}

// GetStatus gets a status
func (s *ApplicationLifecycleServiceServer) GetStatus(ctx context.Context,
	app *pb.ApplicationID) (*pb.LifecycleStatus, error) {

	dapp, err := s.meta.Load(app.Id)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "App %v not found: %v",
			app.Id, err)
	}
	log.Debugf("GetStatus(%v): returning %v", app.Id, dapp.App.Status)

	return &pb.LifecycleStatus{Status: dapp.App.Status}, nil
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
		handler = &ContainerHandler{a, s.cfg.UseCNI}
	} else {
		handler = &VMHandler{a}
	}

	return handler, nil
}
