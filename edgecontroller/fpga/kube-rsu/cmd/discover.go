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

func listImages(node string) error {
	var err error
	var cmd *exec.Cmd

	// #nosec
	cmd = exec.Command("ssh", "root@"+node,
		"ls -lh", "/temp/vran_images/", "| awk '{print $6,$7,\"\t\",$5,\"\t\",$9}'")

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

	fmt.Printf("\nAvailable RTL images:\n---------------------")
	err = cmd.Start()
	if err != nil {
		return err
	}

	err = cmd.Wait()
	if err != nil {
		return err
	}
	fmt.Printf("\n")
	return nil
}

func listDevices(node string) error {
	var err error
	var cmd *exec.Cmd

	// #nosec
	cmd = exec.Command("ssh", node, "lspci", "-knnd:0b30")

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

	fmt.Printf("FPGA devices installed:\n-----------------------\n")
	err = cmd.Start()
	if err != nil {
		return err
	}

	err = cmd.Wait()
	if err != nil {
		return err
	}
	fmt.Printf("\n")
	return nil
}

// discoverCmd represents the discover command
var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover FPGA card(s) and RTL images on a target node",
	Args:  cobra.MaximumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {

		node, _ := cmd.Flags().GetString("node")
		if node == "" {
			fmt.Println(errors.New("target node missing"))
			return
		}

		err := listImages(node)
		if err != nil {
			fmt.Println(err)
			return
		}

		err = listDevices(node)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
	},
}

func init() {

	const help = `Discover FPGA card(s) and RTL images on a target node

Usage:
  rsu discover -n <target-node>

Flags:
  -h, --help       help
  -n, --node       where the FPGA card(s) to be discovered
`
	// add `discover` command
	rsuCmd.AddCommand(discoverCmd)
	discoverCmd.Flags().StringP("node", "n", "", "where the target FPGA card is plugged in")
	discoverCmd.MarkFlagRequired("node")
	discoverCmd.SetHelpTemplate(help)
}
