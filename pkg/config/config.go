// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package config

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
)

// LoadJSONConfig reads a file located at configPath and unmarshals it to
// config structure
func LoadJSONConfig(configPath string, config interface{}) error {
	cfgData, err := ioutil.ReadFile(filepath.Clean(configPath))
	if err != nil {
		return err
	}
	return json.Unmarshal(cfgData, config)
}
