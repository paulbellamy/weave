package main

import (
	"fmt"
	"os"
	"strings"

	. "github.com/weaveworks/weave/common"
	"github.com/weaveworks/weave/proxy"
)

var (
	version = "(unreleased version)"
)

func main() {
	c := proxy.Config{
		Version: version,
	}

	justVersion, logLevel := proxy.ParseFlags(&c)

	if justVersion {
		fmt.Printf("weave proxy %s\n", version)
		os.Exit(0)
	}

	if c.WithDNS && c.WithoutDNS {
		Log.Fatalf("Cannot use both '--with-dns' and '--without-dns' flags")
	}

	SetLogLevel(logLevel)

	Log.Infoln("weave proxy", version)
	Log.Infoln("Command line arguments:", strings.Join(os.Args[1:], " "))

	p, err := proxy.NewProxy(c)
	if err != nil {
		Log.Fatalf("Could not start proxy: %s", err)
	}

	p.ListenAndServe()
}
