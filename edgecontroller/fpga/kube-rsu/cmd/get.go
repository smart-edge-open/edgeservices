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

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get FPGA telemetry",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var jobArgs string

		node, _ := cmd.Flags().GetString("node")
		if node == "" {
			fmt.Println(errors.New("target node missing"))
			return
		}

		switch args[0] {
		case "power":
			jobArgs = "./check_if_modules_loaded.sh && fpgainfo power"

		case "temp":
			jobArgs = "./check_if_modules_loaded.sh && fpgainfo temp"

		case "fme":
			jobArgs = "./check_if_modules_loaded.sh && fpgainfo fme"

		case "port":
			fmt.Println(errors.New("Not supported"))
			return

		case "bmc":
			fmt.Println(errors.New("Not supported"))
			return

		case "phy":
			fmt.Println(errors.New("Not supported"))
			return

		case "mac":
			fmt.Println(errors.New("Not supported"))
			return

		default:
			fmt.Println(errors.New("Undefined or missing metric"))
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

		containerSpec.Args = []string{jobArgs}
		containerSpec.VolumeMounts = []corev1.VolumeMount{
			{
				Name:      "class",
				MountPath: "/sys/devices",
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

	const help = `Get FPGA telemetry

Usage:
  rsu get <metric> -n <target-node>

Metrics:
  power            print power metrics
  temp             print thermal metrics
  fme              print FME information
  port             print accelerator port information
  bmc              print all Board Management Controller sensor values
  phy              print all PHY information
  mac              print MAC information

Flags:
  -h, --help       help
  -n, --node       where the target FPGA card(s) is/are plugged in
`
	// add `get` command
	rsuCmd.AddCommand(getCmd)
	getCmd.Flags().StringP("node", "n", "", "where the target FPGA card is plugged in")
	getCmd.MarkFlagRequired("node")
	getCmd.SetHelpTemplate(help)
}
