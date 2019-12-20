// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package stubs

import (
	"net/http"

	"github.com/open-ness/edgenode/internal/wrappers"
)

// HTTPCliStub stores HTTPClientStub
var HTTPCliStub HTTPClientStub

// HTTPClientStub struct implementation
type HTTPClientStub struct {
	HTTPResp http.Response
	DoErr    error
}

// CreateHTTPClientStub returns stub implementing HTTPClient interface
func CreateHTTPClientStub() wrappers.HTTPClient {
	return &HTTPCliStub
}

// Do implements stub for corresponding method from HTTPClient
func (hcs *HTTPClientStub) Do(req *http.Request) (*http.Response, error) {
	return &hcs.HTTPResp, hcs.DoErr
}
