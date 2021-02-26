// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package log_test

import (
	"bytes"
	"log/syslog"
	"strings"
	"testing"

	"github.com/otcshare/edgeservices/common/log"
)

func TestLoggerSetOutput(t *testing.T) {
	log := new(log.Logger)

	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.Info("hello")
	if !strings.HasSuffix(buf.String(), "hello\n") {
		t.Errorf("expected %q to end with 'hello\\n'", buf.String())
	}
}

func TestLoggerPriority(t *testing.T) {
	var (
		defaultLevel    = log.DefaultLevel
		defaultFacility = log.DefaultFacility
		log             = new(log.Logger)
	)

	// Test default priority
	if lvl := log.GetLevel(); lvl != defaultLevel {
		t.Errorf("expected default syslog level %d, got %d", defaultLevel, lvl)
	}
	if fac := log.GetFacility(); fac != defaultFacility {
		t.Errorf("expected default syslog facility %d, got %d", defaultLevel, fac)
	}

	// Test setting severity
	log.SetLevel(syslog.LOG_DEBUG)
	if lvl := log.GetLevel(); lvl != syslog.LOG_DEBUG {
		t.Errorf("expected syslog level %d, got %d", syslog.LOG_DEBUG, lvl)
	}
	log.SetLevel(syslog.LOG_CRIT)
	if lvl := log.GetLevel(); lvl != syslog.LOG_CRIT {
		t.Errorf("expected syslog level %d, got %d", syslog.LOG_CRIT, lvl)
	}

	// Test setting facility
	log.SetFacility(syslog.LOG_MAIL)
	if fac := log.GetFacility(); fac != syslog.LOG_MAIL {
		t.Errorf("expected syslog facility %d, got %d", syslog.LOG_MAIL, fac)
	}
	log.SetFacility(syslog.LOG_LOCAL5)
	if fac := log.GetFacility(); fac != syslog.LOG_LOCAL5 {
		t.Errorf("expected syslog facility %d, got %d", syslog.LOG_LOCAL5, fac)
	}
}
