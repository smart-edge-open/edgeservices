// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package wrappers

import "net/http"

// HTTPClient is the interface that wraps Do method
// Do sends an HTTP request and returns an HTTP response
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// CreateHTTPClient creates http client
var CreateHTTPClient = func() HTTPClient {
	return http.DefaultClient
}
