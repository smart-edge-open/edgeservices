// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package log

import (
	"log/syslog"
	"os"
	"sync"
)

// GrpcLogger implements grpclog's Logger and LoggerV2 interfaces.
type GrpcLogger struct {
	// Logger is the underlying Logger to write to. If none is specified, then
	// the default logger (package var) is used.
	Logger *Logger

	// PrintLevel specifies the level that all print messages will be written
	// at. If none is specified, the default of INFO will be used.
	PrintLevel syslog.Priority

	once sync.Once
}

func (l *GrpcLogger) init() {
	if l.Logger == nil {
		l.Logger = DefaultLogger
	}
	if l.PrintLevel == 0 {
		l.PrintLevel = syslog.LOG_INFO
	}
}

// Print logs to the level set at init. Arguments are handled in the manner
// of fmt.Print.
//
// This function partially implements the grpclog.Logger interface.
func (l *GrpcLogger) Print(args ...interface{}) {
	l.once.Do(l.init)
	l.Logger.Print(l.PrintLevel, args...)
}

// Println logs to the level set at init. Arguments are handled in the
// manner of fmt.Println.
//
// This function partially implements the grpclog.Logger interface.
func (l *GrpcLogger) Println(args ...interface{}) {
	l.Print(args...)
}

// Printf logs to the level set at init. Arguments are handled in the
// manner of fmt.Printf.
//
// This function partially implements the grpclog.Logger interface.
func (l *GrpcLogger) Printf(format string, args ...interface{}) {
	l.once.Do(l.init)
	l.Logger.Printf(l.PrintLevel, format, args...)
}

// Info initializes and logs to info logger. All arguments are forwarded.
//
// This function partially implements the grpclog.LoggerV2 interface.
func (l *GrpcLogger) Info(args ...interface{}) {
	l.once.Do(l.init)
	l.Logger.Info(args...)
}

// Infoln logs to info logger. All arguments are forwarded to Info func
//
// This function partially implements the grpclog.LoggerV2 interface.
func (l *GrpcLogger) Infoln(args ...interface{}) { l.Info(args...) }

// Info initializes and logs to infof logger. All arguments are forwarded.
//
// This function partially implements the grpclog.LoggerV2 interface.
func (l *GrpcLogger) Infof(format string, args ...interface{}) {
	l.once.Do(l.init)
	l.Logger.Infof(format, args...)
}

// Warning initializes and logs to warning logger. All arguments are forwarded.
//
// This function partially implements the grpclog.LoggerV2 interface.
func (l *GrpcLogger) Warning(args ...interface{}) {
	l.once.Do(l.init)
	l.Logger.Warning(args...)
}

// Warningln logs to warning logger. Arguments are forwarded to Warning func
//
// This function partially implements the grpclog.LoggerV2 interface.
func (l *GrpcLogger) Warningln(args ...interface{}) { l.Warning(args...) }

// Warningf initializes and logs to warning logger. All arguments are forwarded.
//
// This function partially implements the grpclog.LoggerV2 interface.
func (l *GrpcLogger) Warningf(format string, args ...interface{}) {
	l.once.Do(l.init)
	l.Logger.Warningf(format, args...)
}

// Error initializes and logs to error logger. All arguments are forwarded.
//
// This function partially implements the grpclog.LoggerV2 interface.
func (l *GrpcLogger) Error(args ...interface{}) {
	l.once.Do(l.init)
	l.Logger.Err(args...)
}

// Errorln logs to error logger.
// Arguments are handled in the manner of fmt.Println.
//
// This function partially implements the grpclog.LoggerV2 interface.
func (l *GrpcLogger) Errorln(args ...interface{}) { l.Error(args...) }

// Errorf logs to error logger. All arguments are forwarded.
//
// This function partially implements the grpclog.LoggerV2 interface.
func (l *GrpcLogger) Errorf(format string, args ...interface{}) {
	l.once.Do(l.init)
	l.Logger.Errf(format, args...)
}

// Fatal initializes, logs to alert logger and
// calls os.exit with value 1. All arguments are forwarded to logger.
//
// This function partially implements the grpclog.Logger and grpclog.LoggerV2
// interfaces.
func (l *GrpcLogger) Fatal(args ...interface{}) {
	l.once.Do(l.init)
	l.Logger.Alert(args...)
	os.Exit(1)
}

// Fatalln executes Fatal func and forwards all arguments.
//
// This function partially implements the grpclog.Logger and grpclog.LoggerV2
// interfaces.
func (l *GrpcLogger) Fatalln(args ...interface{}) { l.Fatal(args...) }

// Fatalf initializes, logs to alertf logger and
// calls os.exit with value 1. All arguments are forwarded to logger.
//
// This function partially implements the grpclog.Logger and grpclog.LoggerV2
// interfaces.
func (l *GrpcLogger) Fatalf(format string, args ...interface{}) {
	l.once.Do(l.init)
	l.Logger.Alertf(format, args...)
	os.Exit(1)
}

// V reports whether verbosity level l is at least the requested verbose level.
//
// Levels are _not_ identical to Syslog and are defined by the grpclog library
// as:
//
//     0: FATAL and ERROR
//     1: FATAL and ERROR and WARNING
//     2: FATAL and ERROR and WARNING and INFO
//
// This function partially implements the grpclog.LoggerV2 interface.
func (l *GrpcLogger) V(level int) bool {
	l.once.Do(l.init)
	switch level {
	case 0:
		return l.Logger.GetLevel() >= syslog.LOG_ERR
	case 1:
		return l.Logger.GetLevel() >= syslog.LOG_WARNING
	case 2:
		return l.Logger.GetLevel() >= syslog.LOG_INFO
	default:
		return false
	}
}
