// Temporary main.go file mockup to run Edge Application Agent for testing.
// Should be replaced by monolith app frame.

package main

import (
	eaa "github.com/smartedgemec/appliance-ce/pkg/eaa"
)

func main() {
	eaa.RunEaa()
}
