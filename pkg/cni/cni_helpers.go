// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package cni

import (
	"context"

	evapb "github.com/otcshare/edgenode/pkg/eva/pb"
)

// CreateInfrastructureContainer creates new infrastructure container for application
func CreateInfrastructureContainer(ctx context.Context, appID string) (string, error) {
	infraCtr := NewInfrastructureContainerInfo(appID)
	if err := infraCtr.Create(ctx); err != nil {
		return "", err
	}

	return infraCtr.ID, nil
}

// RemoveInfrastructureContainer removes infrastructure container for application
func RemoveInfrastructureContainer(ctx context.Context, appID string) error {
	infraCtr := NewInfrastructureContainerInfo(appID)
	return infraCtr.Remove(ctx)
}

// StartInfrastructureContainer starts infrastructure container for application and invokes CNI exec with ADD action
func StartInfrastructureContainer(ctx context.Context, appID string, cniConf *evapb.CNIConfiguration) error {
	infraCtr := NewInfrastructureContainerInfo(appID)
	if err := infraCtr.Start(ctx); err != nil {
		return err
	}

	cniInvoker := NewCNIInvoker(infraCtr, cniConf, Add)
	if _, err := cniInvoker.Invoke(); err != nil {
		log.Errf("Failed to run CNI. appID=%s, Reason=%s", appID, err.Error())
		return err
	}

	return nil
}

// StopInfrastructureContainer stops infrastructure container for application and invokes CNI exec with DEL action
func StopInfrastructureContainer(ctx context.Context, appID string, cniConf *evapb.CNIConfiguration) error {
	infraCtr := NewInfrastructureContainerInfo(appID)
	if err := infraCtr.QueryDocker(ctx); err != nil {
		return err
	}

	cniInvoker := NewCNIInvoker(infraCtr, cniConf, Del)
	if _, err := cniInvoker.Invoke(); err != nil {
		log.Errf("Failed to run CNI. appID=%s, Reason=%s", appID, err.Error())
		return err
	}

	if err := infraCtr.Stop(ctx); err != nil {
		return err
	}

	return nil
}
