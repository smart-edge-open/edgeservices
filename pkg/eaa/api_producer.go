// Copyright 2019 Intel Corporation and Smart-Edge.com, Inc. All rights reserved
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

package eaa

import (
	"errors"
	"net/http"
)

func addService(serv Service) error {
	if eaaCtx.serviceInfo == nil {
		return errors.New(
			"EAA context is not initialized. Call Init() function first")
	}
	eaaCtx.serviceInfo[serv.URN.ID+"."+serv.URN.Namespace] = serv
	return nil
}

func removeService(commonName string) (int, error) {
	if eaaCtx.serviceInfo == nil {

		return http.StatusInternalServerError,
			errors.New("500: EAA context not initialized. ")
	}

	urn, err := CommonNameStringToURN(commonName)
	if err != nil {
		return http.StatusUnauthorized,
			err
	}
	_, servicefound := eaaCtx.serviceInfo[urn.ID+"."+urn.Namespace]
	if servicefound {
		delete(eaaCtx.serviceInfo, urn.ID+"."+urn.Namespace)
		return http.StatusNoContent, nil
	}

	return http.StatusNotFound,
		errors.New(http.StatusText(http.StatusNotFound))
}
