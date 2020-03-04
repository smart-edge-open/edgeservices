// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

// +build nts

package main

import (
	"github.com/otcshare/edgenode/pkg/eda"
	"github.com/otcshare/edgenode/pkg/ela"
	"github.com/otcshare/edgenode/pkg/eva"
	"github.com/otcshare/edgenode/pkg/service"
)

// EdgeServices array contains function pointers to services start functions
var EdgeServices = []service.StartFunction{ela.Run, eva.Run, eda.Run}
