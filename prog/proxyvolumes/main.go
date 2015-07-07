// proxyvolumes
// Parse the cli args, and docker default args, to determine which volumes need
// mounting into the proxy's container.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/weaveworks/weave/proxy"
)

func main() {
	c := proxy.Config{}

	justVersion, _ := proxy.ParseFlags(&c)

	if justVersion {
		os.Exit(0)
	}

	// Format & output volume mounts
	if c.TLSConfig.Enabled || c.TLSConfig.Verify {
		args := []string{}
		args = mountIfNotBlank(args, c.TLSConfig.Key)
		args = mountIfNotBlank(args, c.TLSConfig.CACert)
		args = mountIfNotBlank(args, c.TLSConfig.Cert)
		fmt.Print(strings.Join(args, " "))
	}
}

func mountIfNotBlank(args []string, file string) []string {
	if file != "" {
		return append(args, fmt.Sprintf("-v %s:%s", file, file))
	}
	return args
}
