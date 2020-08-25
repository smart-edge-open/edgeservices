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

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	k8corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
)

// default values
var (
	privileged   = true
	backoffLimit = int32(0)
	namespace    = "default"
	timeout      = 60 //seconds
)

// RSUJob struct to hold RSU job specification for K8
var RSUJob = &batchv1.Job{
	TypeMeta: metav1.TypeMeta{
		Kind:       "Job",
		APIVersion: "v1",
	},
	ObjectMeta: metav1.ObjectMeta{
		Name: "fpga-opae-job",
	},
	Spec: batchv1.JobSpec{
		Template: corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:    "fpga-opae", // to be edited by command
						Image:   "fpga-opae-pacn3000:1.0",
						Command: []string{"sudo", "/bin/bash", "-c", "--"},
						Args:    []string{""}, // to be added by command
						SecurityContext: &corev1.SecurityContext{
							Privileged: &privileged,
						},
						ImagePullPolicy: corev1.PullPolicy(corev1.PullNever),
						Env:             []corev1.EnvVar{},
						VolumeMounts:    []corev1.VolumeMount{}, // to be added by command
					},
				},
				RestartPolicy:    corev1.RestartPolicyNever,
				Volumes:          []corev1.Volume{}, // to be added by command
				ImagePullSecrets: []corev1.LocalObjectReference{},
				NodeSelector:     make(map[string]string), // to be added by command
			},
		},
		BackoffLimit: &backoffLimit,
	},
}

func k8LogCmd(pod string) (*exec.Cmd, error) {
	var err error
	var cmd *exec.Cmd

	// #nosec
	cmd = exec.Command("kubectl", "logs", "-f", pod)

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
		return cmd, err
	}
	return cmd, nil
}

// PrintJobLogs prints logs from k8 pod belonging to the given job
func PrintJobLogs(clientset *kubernetes.Clientset, job *batchv1.Job) (*exec.Cmd, error) {
	var cmd *exec.Cmd
	var pods *corev1.PodList
	var podsClient k8corev1.PodInterface
	var pod *corev1.Pod
	// get pod of job based on labels
	set := labels.Set(job.Spec.Selector.MatchLabels)
	listOptions := metav1.ListOptions{LabelSelector: set.AsSelector().String()}
	// wait for pod creation
	for i := 0; i < timeout; i++ {
		podsClient = clientset.CoreV1().Pods(namespace)
		pods, _ = podsClient.List(listOptions)
		if len(pods.Items) > 0 {
			break
		}
		time.Sleep(time.Second)
	}
	if len(pods.Items) < 1 {
		return cmd, errors.New("Pod creation timeout")
	}
	// wait for pod to create container
	for i := 0; i < timeout; i++ {
		pod, _ = podsClient.Get(pods.Items[0].Name, metav1.GetOptions{})
		if pod.Status.Phase != corev1.PodPending {
			break
		}
		time.Sleep(time.Second)
	}
	if pod.Status.Phase == corev1.PodPending {
		return cmd, errors.New("Container creation timeout")
	}
	// print logs
	cmd, err := k8LogCmd(pod.Name)
	if err != nil {
		return cmd, err
	}
	return cmd, nil
}

// DeletePod deletes k8 pod belonging to the given job
func DeletePod(clientset *kubernetes.Clientset, job *batchv1.Job) error {
	// get pod of job based on labels
	set := labels.Set(job.Spec.Selector.MatchLabels)
	listOptions := metav1.ListOptions{LabelSelector: set.AsSelector().String()}
	podsClient := clientset.CoreV1().Pods(namespace)
	pods, _ := podsClient.List(listOptions)
	if len(pods.Items) < 1 {
		return errors.New("Failed to retrieve pod")
	}
	// delete job after completion
	return podsClient.Delete(pods.Items[0].Name, &metav1.DeleteOptions{})
}

// GetK8Clientset returns the clientset for kubernetes
func GetK8Clientset() (*kubernetes.Clientset, error) {
	var clientset *kubernetes.Clientset
	// retrieve .kube/config file
	kubeconfig := filepath.Join(
		os.Getenv("HOME"), ".kube", "config",
	)
	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return clientset, err
	}
	// create the clientset
	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		return clientset, err
	}
	return clientset, nil
}
