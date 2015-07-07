package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/pkg/mflag"
	. "github.com/weaveworks/weave/common"
	"github.com/weaveworks/weave/proxy"
)

var (
	version = "(unreleased version)"
)

type listOpts struct {
	value      *[]string
	hasBeenSet bool
}

func ListVar(p *[]string, names []string, value []string, usage string) {
	FlagSetListVar(mflag.CommandLine, p, names, value, usage)
}

func FlagSetListVar(flagset *mflag.FlagSet, p *[]string, names []string, value []string, usage string) {
	*p = value
	flagset.Var(&listOpts{p, false}, names, usage)
}

func (opts *listOpts) Set(value string) error {
	if opts.hasBeenSet {
		(*opts.value) = append((*opts.value), value)
	} else {
		(*opts.value) = []string{value}
		opts.hasBeenSet = true
	}
	return nil
}

func (opts *listOpts) String() string {
	return fmt.Sprintf("%v", []string(*opts.value))
}

func main() {
	var (
		justVersion bool
		logLevel    = "info"
		c           = proxy.Config{ListenAddrs: []string{}}
	)

	c.Version = version

	if err := loadDockerDefaults(&c); err != nil {
		Log.Fatalf("Error loading default arguments from docker: %s", err)
	}

	mflag.BoolVar(&justVersion, []string{"#version", "-version"}, false, "print version and exit")
	mflag.StringVar(&logLevel, []string{"-log-level"}, "info", "logging level (debug, info, warning, error)")
	ListVar(&c.ListenAddrs, []string{"H"}, nil, "addresses on which to listen")
	mflag.StringVar(&c.HostnameMatch, []string{"-hostname-match"}, "(.*)", "Regexp pattern to apply on container names (e.g. '^aws-[0-9]+-(.*)$')")
	mflag.StringVar(&c.HostnameReplacement, []string{"-hostname-replacement"}, "$1", "Expression to generate hostnames based on matches from --hostname-match (e.g. 'my-app-$1')")
	mflag.BoolVar(&c.NoDefaultIPAM, []string{"#-no-default-ipam", "-no-default-ipalloc"}, false, "do not automatically allocate addresses for containers without a WEAVE_CIDR")
	mflag.BoolVar(&c.NoRewriteHosts, []string{"no-rewrite-hosts"}, false, "do not automatically rewrite /etc/hosts. Use if you need the docker IP to remain in /etc/hosts")
	mflag.StringVar(&c.TLSConfig.CACert, []string{"#tlscacert", "-tlscacert"}, c.TLSConfig.CACert, "Trust certs signed only by this CA")
	mflag.StringVar(&c.TLSConfig.Cert, []string{"#tlscert", "-tlscert"}, c.TLSConfig.Cert, "Path to TLS certificate file")
	mflag.BoolVar(&c.TLSConfig.Enabled, []string{"#tls", "-tls"}, c.TLSConfig.Enabled, "Use TLS; implied by --tls-verify")
	mflag.StringVar(&c.TLSConfig.Key, []string{"#tlskey", "-tlskey"}, c.TLSConfig.Key, "Path to TLS key file")
	mflag.BoolVar(&c.TLSConfig.Verify, []string{"#tlsverify", "-tlsverify"}, c.TLSConfig.Verify, "Use TLS and verify the remote")
	mflag.BoolVar(&c.WithDNS, []string{"-with-dns", "w"}, false, "instruct created containers to always use weaveDNS as their nameserver")
	mflag.BoolVar(&c.WithoutDNS, []string{"-without-dns"}, false, "instruct created containers to never use weaveDNS as their nameserver")
	mflag.Parse()

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

func loadDockerDefaults(c *proxy.Config) error {
	procfs := os.Getenv("PROCFS")
	// find the docker PID
	statusFile, err := os.Open(filepath.Join(procfs, "self/status"))
	if err != nil {
		return err
	}
	defer statusFile.Close()
	dockerPID := ""
	scanner := bufio.NewScanner(statusFile)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == "PPid:" {
			dockerPID = fields[1]
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	if err := parseDockerEnv(procfs, dockerPID); err != nil {
		return err
	}

	argBytes, err := ioutil.ReadFile(filepath.Join(procfs, dockerPID, "cmdline"))
	if err != nil {
		return err
	}

	args := nullTermToStrings(argBytes)[1:]

	//filter down to only the flags we expect, so parsing
	//them doesn't bail
	filteredArgs := []string{}
	for i := 0; i < len(args); i++ {
		arg := strings.SplitN(args[i], "=", 2)
		switch arg[0] {
		case "--tls", "--tlsverify":
			filteredArgs = append(filteredArgs, args[i])
		case "--tlscacert", "--tlscert",
			"--tlskey":
			filteredArgs = append(filteredArgs, args[i])
			if !strings.Contains(args[i], "=") {
				i++
				if i < len(args) {
					filteredArgs = append(filteredArgs, args[i])
				}
			}
		}
	}

	dockerFlags := &mflag.FlagSet{}
	dockerFlags.BoolVar(&c.TLSConfig.Enabled, []string{"-tls"}, false, "")
	dockerFlags.BoolVar(&c.TLSConfig.Verify, []string{"-tlsverify"}, false, "")
	dockerFlags.StringVar(&c.TLSConfig.CACert, []string{"-tlscacert"}, "", "")
	dockerFlags.StringVar(&c.TLSConfig.Cert, []string{"-tlscert"}, "", "")
	dockerFlags.StringVar(&c.TLSConfig.Key, []string{"-tlskey"}, "", "")
	if err := dockerFlags.Parse(filteredArgs); err != nil {
		return err
	}

	return nil
}

func parseDockerEnv(procfs, dockerPID string) error {
	envBytes, err := ioutil.ReadFile(filepath.Join(procfs, dockerPID, "environ"))
	if err != nil {
		return err
	}
	options := []string{"DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY"}
	for _, line := range nullTermToStrings(envBytes) {
		for _, option := range options {
			prefix := fmt.Sprint(option, "=")
			if strings.HasPrefix(line, prefix) {
				os.Setenv(option, strings.TrimPrefix(line, prefix))
			}
		}
	}
	return nil
}

func nullTermToStrings(b []byte) []string {

	strs := []string{}
	for {
		i := bytes.IndexByte(b, 0)
		if i == -1 {
			break
		}
		strs = append(strs, string(b[0:i]))
		b = b[i+1:]
	}
	return strs
}
