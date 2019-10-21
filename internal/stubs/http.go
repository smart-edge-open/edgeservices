// Copyright 2019 Intel Corporation. All rights reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stubs

import (
	"net/http"

	"github.com/otcshare/edgenode/internal/wrappers"
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
