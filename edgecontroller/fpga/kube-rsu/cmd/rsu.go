// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package rsu

import (
	"github.com/spf13/cobra"
)

// rsuCmd represents the base command when called without any subcommands
var rsuCmd = &cobra.Command{
	Use:          "rsu",
	Long:         "Remote System Update (RSU) command line for Intel FPGA OPAE",
	SilenceUsage: true,
}

// Execute rsu agent
func Execute() error {
	return rsuCmd.Execute()
}
