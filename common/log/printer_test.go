// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package log_test

import (
	"bytes"
	"log/syslog"
	"regexp"
	"testing"

	"github.com/smart-edge-open/edgeservices/common/log"
)

func TestPrinterPrint(t *testing.T) {
	tests := map[string]struct {
		printerLvl syslog.Priority
		inputLvl   syslog.Priority
		inputMsg   string
		expect     *regexp.Regexp
	}{
		"debug message at debug level": {
			printerLvl: syslog.LOG_DEBUG,
			inputLvl:   syslog.LOG_DEBUG,
			inputMsg:   "hello",
			expect:     regexp.MustCompile(`: hello\n$`),
		},
		"debug message at info level": {
			printerLvl: syslog.LOG_INFO,
			inputLvl:   syslog.LOG_DEBUG,
			inputMsg:   "hello",
			expect:     regexp.MustCompile(`^$`),
		},
	}

	for desc, test := range tests {
		var buf bytes.Buffer

		log := new(log.Logger)
		log.SetLevel(test.printerLvl)
		log.SetOutput(&buf)

		log.Print(test.inputLvl, test.inputMsg)
		if actual := buf.String(); !test.expect.MatchString(actual) {
			t.Errorf("[%s] expected to match regexp %q, got %q", desc, test.expect, actual)
		}
	}
}
