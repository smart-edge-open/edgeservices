// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

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
	EAAAuthPort   = "80"
	EAACommonName = "eaa.openness"
)

var platform string
var framework string
var namespace string
var servingPort string
var stayAlive bool

func getCredentials(prvKey *ecdsa.PrivateKey) (eaa.AuthCredentials, error) {

	var prodCreds eaa.AuthCredentials

	certTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   namespace + ":analytics-" + framework,
			Organization: []string{"Intel Corporation"},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		EmailAddresses:     []string{"hello@openness.org"},
	}

	prodCsrBytes, err := x509.CreateCertificateRequest(rand.Reader,
		&certTemplate, prvKey)
	if err != nil {
		return prodCreds, err
	}
	csrMem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST",
		Bytes: prodCsrBytes})

	prodID := eaa.AuthIdentity{
		Csr: string(csrMem),
	}

	reqBody, err := json.Marshal(prodID)
	if err != nil {
		return prodCreds, err
	}
	resp, err := http.Post("http://"+EAAEndpoint+":"+EAAAuthPort+"/auth",
		"", bytes.NewBuffer(reqBody))
	if err != nil {
		return prodCreds, err
	}

	err = json.NewDecoder(resp.Body).Decode(&prodCreds)
	if err != nil {
		return prodCreds, err
	}

	return prodCreds, nil
}

func authenticate(prvKey *ecdsa.PrivateKey) (*http.Client, error) {

	prodCreds, err := getCredentials(prvKey)
	if err != nil {
		return nil, err
	}

	x509Encoded, err := x509.MarshalECPrivateKey(prvKey)
	if err != nil {
		return nil, err
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY",
		Bytes: x509Encoded})
	prodCert, err := tls.X509KeyPair([]byte(prodCreds.Certificate),
		pemEncoded)
	if err != nil {
		return nil, err
	}

	prodCertPool := x509.NewCertPool()
	for _, cert := range prodCreds.CaPool {
		ok := prodCertPool.AppendCertsFromPEM([]byte(cert))
		if !ok {
			return nil, errors.New("Error: failed to append cert")
		}
	}

	// HTTPS client
	prodClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      prodCertPool,
				Certificates: []tls.Certificate{prodCert},
				ServerName:   EAACommonName,
			},
		},
		Timeout: 0,
	}

	return prodClient, nil
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

	// perform CSR to authenticate and retrieve certificate
	prodPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
		return
	}

	client, err := authenticate(prodPriv)
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
