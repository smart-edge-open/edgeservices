// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"

	"eaa"
)

// VASInfo describes the video analytics service
type VASInfo struct {
	Platform    string   `json:"platform"`
	ID          string   `json:"id"`
	Namespace   string   `json:"namespace"`
	EndpointURI string   `json:"endpointURI"`
	Description string   `json:"description"`
	Framework   string   `json:"framework"`
	Pipelines   []string `json:"pipelines"`
}

// VASGetPipelines described the return of GET /pipelines API
// https://github.com/intel/video-analytics-serving/blob/master/interfaces.md#get-pipelines
type VASGetPipelines struct {
	Description string `json:"description,omitempty"`
	Name        string `json:"name,omitempty"`
	Type        string `json:"type,omitempty"`
	Version     string `json:"version,omitempty"`
}

// Connectivity constants
const (
	EAAEndpoint   = "eaa.openness"
	EAAHttpsPort  = "443"
	EAACommonName = "eaa.openness"
	CertPath      = "./certs/cert.pem"
	RootCAPath    = "./certs/root.pem"
	KeyPath       = "./certs/key.pem"
)

var platform string
var framework string
var namespace string
var servingPort string
var stayAlive bool

// createEncryptedClient creates tls client with certs prorvided in
// CertPath, KeyPath
func createEncryptedClient() (*http.Client, error) {

	log.Println("Loading certificate and key")
	cert, err := tls.LoadX509KeyPair(CertPath, KeyPath)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load client certificate")
	}

	certPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile(RootCAPath)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load CA Cert")
	}
	ok := certPool.AppendCertsFromPEM(caCert)
	if !ok {
		return nil, errors.New("Failed to append cert")
	}

	// HTTPS client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      certPool,
				Certificates: []tls.Certificate{cert},
				ServerName:   EAACommonName,
			},
		},
		Timeout: 0,
	}
	log.Printf("%#v", client)

	return client, nil
}

func activateService(client *http.Client, payload []byte) error {

	req, err := http.NewRequest("POST",
		"https://"+EAAEndpoint+":"+EAAHttpsPort+"/services",
		bytes.NewReader(payload))
	if err != nil {
		return errors.New("Service-activation request creation failed: " + err.Error())
	}

	resp, err := client.Do(req)
	if err != nil {
		return errors.New("Service-activation request failed: " + err.Error())
	}

	err = resp.Body.Close()
	if err != nil {
		return err
	}

	return nil
}

func deactivateService(client *http.Client) {

	req, err := http.NewRequest("DELETE",
		"https://"+EAAEndpoint+":"+EAAHttpsPort+"/services", nil)
	if err != nil {
		log.Printf("Unsubscription request creation failed:", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Unsubscription request failed:", err)
		return
	}

	err = resp.Body.Close()
	if err != nil {
		return
	}
}

func getPipelinesFromVAS() ([]string, error) {

	// HTTP client
	client := &http.Client{
		Timeout: 0,
	}

	pipelines := make([]string, 0)
	VASPipelines := make([]VASGetPipelines, 0)

	req, err := http.NewRequest("GET",
		"http://localhost:"+servingPort+"/pipelines", nil)
	if err != nil {
		return pipelines, errors.New("GET /pipelines creation failed: " + err.Error())
	}
	resp, err := client.Do(req)
	if err != nil {
		return pipelines, errors.New("GET /pipelines request failed: " + err.Error())
	}

	err = json.NewDecoder(resp.Body).Decode(&VASPipelines)
	if err != nil {
		return pipelines, errors.New("Service-list decode failed: " + err.Error())
	}

	err = resp.Body.Close()
	if err != nil {
		return pipelines, err
	}

	for _, p := range VASPipelines {
		pipelines = append(pipelines, p.Name+"/"+p.Version)
	}

	return pipelines, nil
}

func main() {
	log.Printf("Video Analytics Serving sidecar started..")

	// get service from env variables
	platform = os.Getenv("PLATFORM")
	if platform == "" {
		log.Fatal("ERROR: env variable PLATFORM undefined")
		return
	}

	// get framework from env variables
	framework = os.Getenv("FRAMEWORK")
	if framework == "" {
		log.Fatal("ERROR: env variable FRAMEWORK undefined")
		return
	}

	// get namespace from env variables
	namespace = os.Getenv("NAMESPACE")
	if namespace == "" {
		log.Fatal("ERROR: env variable NAMESPACE undefined")
		return
	}

	// get VAS port from env variables
	servingPort = os.Getenv("VAS_PORT")
	if servingPort == "" {
		log.Fatal("ERROR: env variable VAS_PORT undefined")
		return
	}

	var endpoint string
	if namespace == "default" {
		endpoint = "http://analytics-" + framework + ":" + servingPort
	} else {
		endpoint = "http://analytics-" + framework + "." + namespace + ":" + servingPort
	}

	info := VASInfo{
		Platform:    platform,
		ID:          "analytics-" + framework,
		Namespace:   namespace,
		EndpointURI: endpoint,
		Description: "Video Analytics Serving",
		Framework:   framework,
	}

	pipelines, err := getPipelinesFromVAS()
	if err != nil {
		log.Fatal(err)
		return
	}
	info.Pipelines = pipelines

	log.Printf("%+v\n", info)

	servURN := eaa.URN{
		ID:        info.ID,
		Namespace: info.Namespace,
	}

	serv := eaa.Service{
		URN:         &servURN,
		Description: "Video Analytics Service",
		EndpointURI: info.EndpointURI,
	}

	// Authentication
	client, err := createEncryptedClient()
	if err != nil {
		log.Fatal(err)
		return
	}

	serv.Info, _ = json.Marshal(info)

	requestByte, _ := json.Marshal(serv)

	err = activateService(client, requestByte)
	if err != nil {
		log.Fatal(err)
		return
	}

	log.Printf("Video Analytics service registered successfully!")

	stayAlive = true
	for stayAlive {
		time.Sleep(60 * time.Second)
	}

	deactivateService(client)
}
