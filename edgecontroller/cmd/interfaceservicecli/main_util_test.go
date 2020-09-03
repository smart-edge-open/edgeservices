// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

type wreckFile struct {
	filePath    string
	originData  []byte
	wreckedData []byte
}

func newWreckFile(filePath string) (*wreckFile, error) {
	if fileInfo, err := os.Stat(filePath); fileInfo.IsDir() || err != nil {
		if fileInfo.IsDir() {
			return nil, fmt.Errorf("Failed to create wreckFile: %s is not a file path", filePath)
		}
		return nil, fmt.Errorf("Failed to create wreckFile: %v", err)
	}

	return &wreckFile{
		filePath:    filePath,
		wreckedData: []byte("wreck"),
	}, nil
}

func (f *wreckFile) wreckFile() error {
	data, err := ioutil.ReadFile(f.filePath)
	if err != nil {
		return err
	}
	f.originData = data
	if err := ioutil.WriteFile(f.filePath, f.wreckedData, 0600); err != nil {
		return fmt.Errorf("Failed to save toxic data to %s: %v", f.filePath, err)
	}
	return nil
}

func (f *wreckFile) recoverFile() error {
	if err := ioutil.WriteFile(f.filePath, f.originData, 0600); err != nil {
		return fmt.Errorf("Failed to save original data to %s: %v", f.filePath, err)
	}
	return nil

}
