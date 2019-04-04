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

package logger

import (
	"errors"
	"github.com/sirupsen/logrus"
	syslogHook "github.com/sirupsen/logrus/hooks/syslog"
	"log/syslog"
)

// Logger configuration structure
type Config struct {
	Level string `json:"level"`

	SyslogConfig struct {
		Enable   bool   `json:"enable"`
		Protocol string `json:"protocol"`
		Address  string `json:"address"`
		Tag      string `json:"tag"`
	} `json:"syslog"`
}

// NewLogger creates a new instance of a logrus logger.
// It disables colors and enables full timestamps.
// The default output is stderr and the log level is set to "info".
// It returns a log entry with a component field passed in the argument.
//
// TODO: When this package has more use, change the return value from a
// pointer at a concrete type to an interface. This will allow better usage
// and testing in the long term.
func NewLogger(component string) *logrus.Entry {
	log := logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		DisableColors: true,
	})
	return log.WithField("component", component)
}

// SetLevel sets a log level on an underlying logger.
// Supported level values: panic, fatal,
// error, warning, warn, info, debug, trace.
// It returns an error if a provided level is not supported
// and nil otherwise.
//
// This is a convenience function to adjust the entry. Since
// it currently accepts a pointer to a concrete type, the
// caller could also adjust the log level directly onto that
// concrete type.
func SetLevel(logEntry *logrus.Entry, level string) error {
	if logEntry == nil {
		return errors.New("log entry is not valid(nil)")
	}

	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		return err
	}

	logEntry.Logger.SetLevel(lvl)
	return nil
}

// ConfigSyslog configures a syslog hook for an underlying logger.
// If net is empty it connects to the local syslog server.
// Otherwise it will try to connect to the remote syslog server and return a
// result.
func ConfigSyslog(logEntry *logrus.Entry, net, addr, tag string) error {
	if logEntry == nil {
		return errors.New("log entry is not valid(nil)")
	}
	// default severity(LOG_INFO) is not used by the logger
	hook, err := syslogHook.NewSyslogHook(net, addr,
		syslog.LOG_USER|syslog.LOG_INFO, tag)

	if err != nil {
		return err
	}
	logEntry.Logger.Hooks.Add(hook)
	return nil
}

// ConfigLogger configures an underlying logger using
// ConfigSyslog and SetLevel functions.
// All required fields are passed through cfg parameter.
func ConfigLogger(logEntry *logrus.Entry, cfg *Config) error {
	if logEntry == nil {
		return errors.New("log entry is not valid(nil)")
	}

	syslogCfg := &cfg.SyslogConfig
	if syslogCfg.Enable {
		err := ConfigSyslog(logEntry,
			syslogCfg.Protocol, syslogCfg.Address, syslogCfg.Tag)
		if err != nil {
			return err
		}
	}

	return SetLevel(logEntry, cfg.Level)
}
