// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
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

// LoadJSONConfigWithLimit loads a config from a JSON file if it's not greater than szLimit bytes
func LoadJSONConfigWithLimit(configPath string, szLimit int64, config interface{}) error {
	sz, err := getFileSize(configPath)
	if err != nil {
		return errors.Wrap(err, "Load config failed")
	}

	if sz > szLimit {
		return fmt.Errorf("Config file size can not be greater than %v bytes", szLimit)
	}

	return LoadJSONConfig(configPath, config)
}

func getFileSize(path string) (int64, error) {
	fInfo, err := os.Stat(filepath.Clean(path))
	if err != nil {
		return 0, err
	}

	return fInfo.Size(), nil
}
