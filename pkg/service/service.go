// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package service

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/pkg/errors"

	logger "github.com/open-ness/common/log"
	"github.com/open-ness/edgenode/pkg/config"
	"github.com/open-ness/edgenode/pkg/util"
)

// StartFunction is func typedef for starting service
type StartFunction func(context.Context, string) error

// EnrollConfig is struct that stores configuration of enrollment read from json file
type EnrollConfig struct {
	Endpoint    string        `json:"Endpoint"`
	ConnTimeout util.Duration `json:"ConnectionTimeout"`
	CertsDir    string        `json:"CertsDirectory"`
}

// MainConfig is struct that stores configuration read from json file
type MainConfig struct {
	UseSyslog  bool              `json:"UseSyslog"`
	SyslogAddr string            `json:"SyslogAddr"`
	LogLevel   string            `json:"LogLevel"`
	Services   map[string]string `json:"Services"`
	Enroll     EnrollConfig      `json:"Enrollment"`
}

// Cfg is variable that stores config
var Cfg MainConfig

// Log is varable that represents logger object
var Log = logger.DefaultLogger.WithField("main", nil)
var cfgPath string

func init() {
	flag.StringVar(&cfgPath, "config", "configs/appliance.json",
		"config file path")
}

// InitConfig load configuration from cfg file
func InitConfig(cfgPath string) error {
	err := config.LoadJSONConfig(cfgPath, &Cfg)
	if err != nil {
		return errors.Wrapf(err,
			"Failed to load config: %s", cfgPath)
	}

	if Cfg.UseSyslog {
		err = logger.ConnectSyslog(Cfg.SyslogAddr)
		if err != nil {
			return errors.Wrapf(err,
				"Failed to connect to syslog: %s", Cfg.SyslogAddr)
		}
	}

	lvl, err := logger.ParseLevel(Cfg.LogLevel)
	if err != nil {
		return errors.Wrapf(err,
			"Failed to parse log level: %s", Cfg.LogLevel)
	}
	logger.SetLevel(lvl)
	return nil
}

// WaitForServices waits for services to finish
func WaitForServices(wg *sync.WaitGroup,
	errors <-chan error, cancel context.CancelFunc) bool {

	waitFinished := make(chan struct{})
	ret := true
	go func() {
		defer close(waitFinished)
		wg.Wait()
	}()

	for {
		select {
		case <-waitFinished:
			return ret
		case err := <-errors:
			if err != nil {
				// nolint 'Cancelling' spelling is correct
				Log.Errf("Cancelling services because of error"+
					" from one of the services: %#v", err)
				cancel()
				ret = false
			}
		}
	}
}

// RunServices starts the services provided in slice
func RunServices(services []StartFunction) bool {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	flag.Parse()
	if err := InitConfig(cfgPath); err != nil {
		Log.Errf("InitConfig failed %v\n", err)
		os.Exit(1)
	}
	// Handle SIGINT and SIGTERM by calling cancel()
	// which is propagated to services
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-osSignals
		Log.Infof("Received signal: %#v", sig)
		cancel()
	}()

	results := make(chan error)

	Log.Infof("Starting services")
	for _, runner := range services {
		funcName := runtime.FuncForPC(reflect.ValueOf(runner).Pointer()).Name()
		srvName := funcName[:strings.LastIndex(funcName, ".")]

		Log.Infof("Starting: %v", srvName)
		wg.Add(1)
		go func(wg *sync.WaitGroup, start StartFunction, cfg string) {
			defer wg.Done()
			err := start(ctx, cfg)
			results <- err
		}(&wg, runner, Cfg.Services[srvName])
	}

	return WaitForServices(&wg, results, cancel)
}
