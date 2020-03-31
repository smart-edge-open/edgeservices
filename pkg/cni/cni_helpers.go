// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package cni

import (
	"context"

	metadata "github.com/open-ness/edgenode/pkg/app-metadata"
	ovncni "github.com/open-ness/edgenode/pkg/ovncni"
	"github.com/pkg/errors"
)

// Type defines enum for CNIs types
type Type string

const (
	// OVN mean that OVN CNI is used (github.com/open-ness/edgenode/pkg/ovncni)
	OVN Type = "ovn"
)

// CreateInfrastructureContainer creates new infrastructure container for application
func CreateInfrastructureContainer(ctx context.Context, app *metadata.DeployedApp) (string, error) {
	if app == nil || app.App == nil || app.App.CniConf == nil {
		return "", errors.New("received nil args")
	}

	if t, err := GetTypeFromCNIConfig(app.App.CniConf.CniConfig); err != nil {
		return "", err
	} else if Type(t) == OVN {
		if _, err := OVNCNICreatePort(app); err != nil {
			return "", err
		}
	}

	infraCtr := NewInfrastructureContainerInfo(app.App.Id)
	if err := infraCtr.Create(ctx); err != nil {
		return "", err
	}

	return infraCtr.ID, nil
}

// RemoveInfrastructureContainer removes infrastructure container for application
func RemoveInfrastructureContainer(ctx context.Context, app *metadata.DeployedApp) error {
	if app == nil || app.App == nil || app.App.CniConf == nil {
		return errors.New("received nil args")
	}

	if t, err := GetTypeFromCNIConfig(app.App.CniConf.CniConfig); err != nil {
		return err
	} else if Type(t) == OVN {
		if err := OVNCNIDeletePort(app); err != nil {
			return err
		}
	}

	infraCtr := NewInfrastructureContainerInfo(app.App.Id)
	return infraCtr.Remove(ctx)
}

// StartInfrastructureContainer starts infrastructure container for application and invokes CNI exec with ADD action
func StartInfrastructureContainer(ctx context.Context, app *metadata.DeployedApp) error {
	if app == nil || app.App == nil || app.App.CniConf == nil {
		return errors.New("received nil arg")
	}

	infraCtr := NewInfrastructureContainerInfo(app.App.Id)
	if err := infraCtr.Start(ctx); err != nil {
		return err
	}

	cniInvoker := NewCNIInvoker(infraCtr, app.App.CniConf, Add)
	if _, err := cniInvoker.Invoke(); err != nil {
		log.Errf("Failed to run CNI. appId=%s, Reason=%s", app.App.Id, err.Error())
		return err
	}

	return nil
}

// StopInfrastructureContainer stops infrastructure container for application and invokes CNI exec with DEL action
func StopInfrastructureContainer(ctx context.Context, app *metadata.DeployedApp) error {
	if app == nil || app.App == nil || app.App.CniConf == nil {
		return errors.New("received nil arg")
	}

	infraCtr := NewInfrastructureContainerInfo(app.App.Id)
	if err := infraCtr.QueryDocker(ctx); err != nil {
		return err
	}

	cniInvoker := NewCNIInvoker(infraCtr, app.App.CniConf, Del)
	if _, err := cniInvoker.Invoke(); err != nil {
		log.Errf("Failed to run CNI. appId=%s, Reason=%s", app.App.Id, err.Error())
		return err
	}

	if err := infraCtr.Stop(ctx); err != nil {
		return err
	}

	return nil
}

// OVNCNICreatePort creates OVN port for application
func OVNCNICreatePort(app *metadata.DeployedApp) (ovncni.LPort, error) {
	lSwitch, err := ovncni.GetCNIArg("subnetID", app.App.CniConf.Args)
	if err != nil {
		return ovncni.LPort{}, errors.Wrapf(err, "failed to get subnetID from CNI args. appId=%s, CNI_ARGS:%s",
			app.App.Id, app.App.CniConf.Args)
	}

	ovncli := ovncni.GetOVNClient("", 0)
	port, err := ovncli.CreatePort(lSwitch, app.App.Id, "" /* empty ip = dynamic */)
	if err != nil {
		return ovncni.LPort{}, errors.Wrapf(err, "failed to create OVN port. appId=%s", app.App.Id)
	}

	return port, nil
}

// OVNCNIDeletePort removes OVN port for application
func OVNCNIDeletePort(app *metadata.DeployedApp) error {
	ovncli := ovncni.GetOVNClient("", 0)
	if err := ovncli.DeletePort(app.App.Id); err != nil {
		return errors.Wrapf(err, "failed to delete OVN port. appId=%s", app.App.Id)
	}

	return nil
}
