// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package rsu

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

var dontSign bool

// loadCmd represents the load command
var loadCmd = &cobra.Command{
	Use:   "load",
	Short: "Load & sign FPGA RTL image to a target node for RSU",
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

		// get base filename if provided as an absolute path
		RTLFile = filepath.Base(RTLFile)

		if dontSign {
			fmt.Printf("Success: RTL image file `%s` loaded but not signed\n", RTLFile)
			return
		}

		// get k8 clientset
		clientset, err := GetK8Clientset()
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		// edit K8 job with `program` command specifics
		podSpec := &(RSUJob.Spec.Template.Spec)
		containerSpec := &(RSUJob.Spec.Template.Spec.Containers[0])
		RSUJob.ObjectMeta.Name = "fpga-opae-" + node

		containerSpec.Args = []string{
			"./check_if_modules_loaded.sh && yes Y | " +
				"python3 /usr/local/bin/PACSign SR -t UPDATE -H openssl_manager -i " +
				"/root/images/" + RTLFile + " -o /root/images/SIGNED_" + RTLFile,
		}

		containerSpec.VolumeMounts = []corev1.VolumeMount{
			{
				Name:      "image-dir",
				MountPath: "/root/images",
				ReadOnly:  false,
			},
		}
		podSpec.NodeSelector["kubernetes.io/hostname"] = node
		podSpec.Volumes = []corev1.Volume{
			{
				Name: "image-dir",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/temp/vran_images",
					},
				},
			},
		}

		// create job in K8 environment
		jobsClient := clientset.BatchV1().Jobs(namespace)
		k8Job, err := jobsClient.Create(RSUJob)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		// print logs from pod
		logs, err := PrintJobLogs(clientset, k8Job)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		defer logs.Process.Kill()
		defer logs.Wait()

		for {
			// wait
			time.Sleep(1 * time.Second)
			// get job
			k8Job, err := jobsClient.Get(RSUJob.Name, metav1.GetOptions{})
			if err != nil {
				fmt.Println(err.Error())
				return
			}

			if k8Job.Status.Failed > 0 {
				fmt.Println("Job `" + k8Job.Name + "` failed!")
				break
			}

			if (k8Job.Status.Succeeded > 0) && (k8Job.Status.Active == 0) {
				fmt.Println("Job `" + k8Job.Name + "` completed successfully!")
				break
			}
		}

		// delete job after completion
		err = jobsClient.Delete(k8Job.Name, &metav1.DeleteOptions{})
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		// delete pod belonging to the job
		err = DeletePod(clientset, k8Job)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
	},
}

func init() {

	const help = `Load & sign FPGA RTL image to a target node for RSU

Usage:
  rsu load -f <RTL-img-file> -n <target-node> [ --no-sign ]

Example:
  rsu load -f <unsigned-RTL-img-file> -n <target-node>
  rsu load -f <signed-RTL-img-file> -n <target-node> --no-sign

Flags:
  -h, --help       help
  -f, --filename   RTL image file to be loaded & signed
  -n, --node       where the target FPGA card is plugged in
      --no-sign    skip signing the RTL image
`
	// add `load` command
	rsuCmd.AddCommand(loadCmd)
	loadCmd.Flags().StringP("filename", "f", "", "RTL image file")
	loadCmd.MarkFlagRequired("filename")
	loadCmd.Flags().StringP("node", "n", "", "where the target FPGA card is plugged in")
	loadCmd.MarkFlagRequired("node")
	loadCmd.Flags().BoolVarP(&dontSign, "no-sign", "", false, "skip signing the RTL image")
	loadCmd.SetHelpTemplate(help)
}
