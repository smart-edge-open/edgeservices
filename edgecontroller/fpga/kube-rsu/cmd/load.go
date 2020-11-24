// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package rsu

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

// copy image
func copyRTLFile(node string, file string) error {
	var err error
	var cmd *exec.Cmd

	// #nosec
	cmd = exec.Command("scp", file, node+":/temp/vran_images/")

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	go func() {
		if _, err = io.Copy(os.Stdout, stdout); err != nil {
			fmt.Println(err.Error())
		}
	}()
	go func() {
		if _, err = io.Copy(os.Stderr, stderr); err != nil {
			fmt.Println(err.Error())
		}
	}()

	err = cmd.Start()
	if err != nil {
		return err
	}

	err = cmd.Wait()
	if err != nil {
		return err
	}
	return nil
}

// loadCmd represents the load command
var loadCmd = &cobra.Command{
	Use:   "load",
	Short: "Load FPGA RTL image to a target node for RSU",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		RTLFile, _ := cmd.Flags().GetString("filename")
		if RTLFile == "" {
			fmt.Println(errors.New("RTL image file missing"))
			return
		}

		node, _ := cmd.Flags().GetString("node")
		if node == "" {
			fmt.Println(errors.New("target node missing"))
			return
		}

		// copy RTL image to target node
		err := copyRTLFile(node, RTLFile)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
	},
}

func init() {

	const help = `Load FPGA RTL image to a target node for RSU

Usage:
  rsu load -f <signed-RTL-img-file> -n <target-node>

Example:
  rsu load -f <signed-RTL-img-file> -n <target-node>

Flags:
  -h, --help       help
  -f, --filename   Signed RTL image file to be loaded
  -n, --node       where the target FPGA card is plugged in
`
	// add `load` command
	rsuCmd.AddCommand(loadCmd)
	loadCmd.Flags().StringP("filename", "f", "", "RTL image file")
	loadCmd.MarkFlagRequired("filename")
	loadCmd.Flags().StringP("node", "n", "", "where the target FPGA card is plugged in")
	loadCmd.MarkFlagRequired("node")
	loadCmd.SetHelpTemplate(help)
}
