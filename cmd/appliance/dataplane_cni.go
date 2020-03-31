// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

// +build cni

package main

import (
	"github.com/open-ness/edgenode/pkg/eva"
	"github.com/open-ness/edgenode/pkg/ela"
	"github.com/open-ness/edgenode/pkg/service"
)

// EdgeServices array contains function pointers to services start functions
var EdgeServices = []service.StartFunction{eva.Run, ela.Run}
