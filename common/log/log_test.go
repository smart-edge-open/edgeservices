// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package log_test

import (
	"bytes"
	"log/syslog"
	"strings"
	"testing"

	"github.com/open-ness/edgeservices/common/log"
)

func TestDefaultLoggerSetOutput(t *testing.T) {
	defer func() { log.DefaultLogger = new(log.Logger) }()

	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.Info("hello")
	if !strings.HasSuffix(buf.String(), "hello\n") {
		t.Errorf("expected %q to end with 'hello\\n'", buf.String())
	}
}

func TestParseLevel(t *testing.T) {
	lvls := map[string]syslog.Priority{
		"emerg":       syslog.LOG_EMERG,
		"emergency":   syslog.LOG_EMERG,
		"alert":       syslog.LOG_ALERT,
		"crit":        syslog.LOG_CRIT,
		"critical":    syslog.LOG_CRIT,
		"err":         syslog.LOG_ERR,
		"error":       syslog.LOG_ERR,
		"warn":        syslog.LOG_WARNING,
		"warning":     syslog.LOG_WARNING,
		"notice":      syslog.LOG_NOTICE,
		"info":        syslog.LOG_INFO,
		"information": syslog.LOG_INFO,
		"debug":       syslog.LOG_DEBUG,
	}

	for lvlStr, lvl := range lvls {
		l, err := log.ParseLevel(lvlStr)
		if err != nil {
			t.Errorf("ParseLevel failed with %s", err.Error())
		}
		if l != lvl {
			t.Errorf("expected syslog priority %d, got %d", lvl, l)
		}
	}

	_, err := log.ParseLevel("invalid")
	if err == nil {
		t.Errorf("ParseLevel was expected to fail")
	}
}

func TestDefaultLoggerPriority(t *testing.T) {
	defer func() { log.DefaultLogger = new(log.Logger) }()

	var (
		defaultLevel    = log.DefaultLevel
		defaultFacility = log.DefaultFacility
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
