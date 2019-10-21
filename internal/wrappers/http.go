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
