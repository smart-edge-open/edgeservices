// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package rsu

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// flashCmd represents the flash command
var flashCmd = &cobra.Command{
	Use:   "flash",
	Short: "Flash FPGA with OPAE factory image",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		node, _ := cmd.Flags().GetString("node")
		if node == "" {
			fmt.Println(errors.New("target node missing"))
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
			"./check_if_modules_loaded.sh && " +
				"/home/fpga_opae/intelrtestack/bin/fpga-n3000-2x2x25G-setup.sh",
		}

		containerSpec.VolumeMounts = []corev1.VolumeMount{
			{
				Name:      "class",
				MountPath: "/sys/devices",
				ReadOnly:  false,
			},
			{
				Name:      "dev",
				MountPath: "/dev",
				ReadOnly:  false,
			},
		}
		podSpec.NodeSelector["kubernetes.io/hostname"] = node
		podSpec.Volumes = []corev1.Volume{
			{
				Name: "class",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/sys/devices",
					},
				},
			},
			{
				Name: "dev",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/dev",
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

		// no timeout (this is a long process)
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
				fmt.Println("RSU job failed!")
				break
			}
			if (k8Job.Status.Succeeded > 0) && (k8Job.Status.Active == 0) {
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

	const help = `Flash FPGA with OPAE factory image

Usage:
  rsu flash -n <target-node>

Flags:
  -h, --help       help
  -n, --node       where the target FPGA card(s) is/are plugged in
`
	// add `flash` command
	rsuCmd.AddCommand(flashCmd)
	flashCmd.Flags().StringP("node", "n", "", "where the target FPGA card is plugged in")
	flashCmd.MarkFlagRequired("node")
	flashCmd.SetHelpTemplate(help)
}
