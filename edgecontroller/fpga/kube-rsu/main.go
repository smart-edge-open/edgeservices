// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package main

import (
	"os"
	"rsu"
)

func main() {

	if err := rsu.Execute(); err != nil {
		os.Exit(1)
	}
	return
}
