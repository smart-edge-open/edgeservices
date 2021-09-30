```text
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2019 Intel Corporation
```

# Log

Common logging library with Syslog support

## Getting Started

In its most basic form, the log package from `smart-edge-open/edgeservices/common`
repository can be used by calling package level print funcs, i.e.
`Debug(f|ln)`, `Info(f|ln)`, `Err(f|ln)`, etc.

By default, all logs will be printed to stderr and a remote syslog service, if
connected. To change the default print output destination, use `SetOutput`. For
example, to turn off printing of all logs, regardless of severity level, use
`SetOutput(ioutil.Discard)`.

The default severity level is INFO and the default syslog facility is LOCAL0.
To change these `SetLevel` and `SetFacility` can be used, respectively, to
alter the default logger. Regardless of the severity level set, all logs will
be sent to any connected remote syslog service. Severity only affects what is
written to output.

To connect the default logger to a remote syslog service, use `ConnectSyslog`,
providing the address of the UDP server or an empty string to connect to the
local machine's service via domain socket. To disconnect, use the corresponding
`DisconnectSyslog` func.

### Structured Logging / Tags

Minimal support for structured tagging exists via `(*Logger).WithField(s)`.
Key-value pairs can be set before printing in order to automatically prepend
data to each log. The data is in the message portion, not the tag, of the
syslog message, so this is essentially just default formatting.

As an example, one may wish to create a logger for a software package within a
larger monolith that tags itself. This may look like

```
package api

import "github.com/smart-edge-open/edgeservices/common/log"

var log = log.DefaultLogger.WithField("component", "api")

func Hello(name string) {
	log.Infof("Hello %s!", name)
	// Output: "[component=api] Hello <name>!"
}
```

As an edge case, if the value is `nil`, then the prepended data will look like
`[key]` rather than `[key=<nil>]`. This may be useful if a key such as
"component" is implied.

### Advanced Usage

Each `Logger` instance can have one non-syslog writer - for which print levels
can be set - and one remote syslog connection. Package level functions use a
default `Logger` instance. For cases where the default logger is not sufficient
more can be created with `new(Logger)`.

For dynamic print level changes via OS signals, see `SignalVerbosityChanges`.

## Testing

```
go test -v -race
```

