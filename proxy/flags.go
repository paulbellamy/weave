package proxy

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/pkg/homedir"
	"github.com/docker/docker/pkg/mflag"
)

type listOpts struct {
	value      *[]string
	hasBeenSet bool
}

func FlagSetListVar(f *mflag.FlagSet, p *[]string, names []string, value []string, usage string) {
	*p = value
	f.Var(&listOpts{p, false}, names, usage)
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

func ParseFlags(c *Config) (justVersion bool, logLevel string) {
	if err := loadDockerDefaults(c); err != nil {
		fmt.Fprintf(mflag.CommandLine.Out(), "Error loading default arguments from docker: %s\n", err)
		os.Exit(1)
	}

	f := mflag.NewFlagSet("weaveproxy", mflag.ExitOnError)
	addFlags(f, c, &justVersion, &logLevel)
	f.Parse(os.Args[1:])

	return
}

func addFlags(f *mflag.FlagSet, c *Config, justVersion *bool, logLevel *string) {
	f.BoolVar(justVersion, []string{"#version", "-version"}, false, "print version and exit")
	f.StringVar(logLevel, []string{"-log-level"}, "info", "logging level (debug, info, warning, error)")
	FlagSetListVar(f, &c.ListenAddrs, []string{"H", "-host"}, c.ListenAddrs, "addresses on which to listen")
	f.StringVar(&c.HostnameMatch, []string{"-hostname-match"}, "(.*)", "Regexp pattern to apply on container names (e.g. '^aws-[0-9]+-(.*)$')")
	f.StringVar(&c.HostnameReplacement, []string{"-hostname-replacement"}, "$1", "Expression to generate hostnames based on matches from --hostname-match (e.g. 'my-app-$1')")
	f.BoolVar(&c.NoDefaultIPAM, []string{"#-no-default-ipam", "-no-default-ipalloc"}, false, "do not automatically allocate addresses for containers without a WEAVE_CIDR")
	f.BoolVar(&c.NoRewriteHosts, []string{"no-rewrite-hosts"}, false, "do not automatically rewrite /etc/hosts. Use if you need the docker IP to remain in /etc/hosts")
	f.StringVar(&c.TLSConfig.CACert, []string{"#tlscacert", "-tlscacert"}, c.TLSConfig.CACert, "Trust certs signed only by this CA")
	f.StringVar(&c.TLSConfig.Cert, []string{"#tlscert", "-tlscert"}, c.TLSConfig.Cert, "Path to TLS certificate file")
	f.BoolVar(&c.TLSConfig.Enabled, []string{"#tls", "-tls"}, c.TLSConfig.Enabled, "Use TLS; implied by --tls-verify")
	f.StringVar(&c.TLSConfig.Key, []string{"#tlskey", "-tlskey"}, c.TLSConfig.Key, "Path to TLS key file")
	f.BoolVar(&c.TLSConfig.Verify, []string{"#tlsverify", "-tlsverify"}, c.TLSConfig.Verify, "Use TLS and verify the remote")
	f.BoolVar(&c.WithDNS, []string{"-with-dns", "w"}, false, "instruct created containers to always use weaveDNS as their nameserver")
	f.BoolVar(&c.WithoutDNS, []string{"-without-dns"}, false, "instruct created containers to never use weaveDNS as their nameserver")
}

func loadDockerDefaults(c *Config) error {
	procfs := os.Getenv("PROCFS")
	// find the docker PID
	dockerPID, args, err := findDocker(procfs, "self")
	if err != nil {
		return err
	}

	if err := parseDockerEnv(procfs, dockerPID, c); err != nil {
		return err
	}

	//filter down to only the flags we expect, so parsing
	//them doesn't bail
	filteredArgs := []string{}
	for i := 0; i < len(args); i++ {
		arg := strings.SplitN(args[i], "=", 2)
		switch arg[0] {
		case "-tls", "--tls",
			"-tlsverify", "--tlsverify":
			filteredArgs = append(filteredArgs, args[i])
		case "-tlscacert", "--tlscacert",
			"-tlscert", "--tlscert",
			"-tlskey", "--tlskey":
			filteredArgs = append(filteredArgs, args[i])
			if !strings.Contains(args[i], "=") {
				if i++; i < len(args) {
					filteredArgs = append(filteredArgs, args[i])
				}
			}
		}
	}

	var justVersion bool
	var logLevel string
	f := mflag.NewFlagSet("weaveproxy", mflag.ContinueOnError)
	addFlags(f, c, &justVersion, &logLevel)
	if err := f.Parse(filteredArgs); err != nil {
		return err
	}

	return nil
}

func findDocker(procfs, pid string) (dockerPID string, args []string, err error) {
	statusFile, err := os.Open(filepath.Join(procfs, pid, "status"))
	if err != nil {
		return "", nil, err
	}
	defer statusFile.Close()
	scanner := bufio.NewScanner(statusFile)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == "PPid:" {
			dockerPID = fields[1]
			break
		}
	}
	if err = scanner.Err(); err != nil {
		return
	}

	argBytes, err := ioutil.ReadFile(filepath.Join(procfs, dockerPID, "cmdline"))
	if err != nil {
		return "", nil, err
	}

	args = nullTermToStrings(argBytes)[1:]
	if len(args) == 0 || args[0] == "/home/weave/weave" {
		return findDocker(procfs, dockerPID)
	}

	return dockerPID, args, nil
}

func parseDockerEnv(procfs, dockerPID string, c *Config) error {
	var configDir, dockerCertPath string

	envBytes, err := ioutil.ReadFile(filepath.Join(procfs, dockerPID, "environ"))
	if err != nil {
		return err
	}
	for _, line := range nullTermToStrings(envBytes) {
		switch {
		case strings.HasPrefix(line, "DOCKER_CONFIG="):
			if s := strings.SplitN(line, "=", 2); len(s) > 1 {
				configDir = s[1]
			}
		case strings.HasPrefix(line, "DOCKER_CERT_PATH="):
			if s := strings.SplitN(line, "=", 2); len(s) > 1 {
				dockerCertPath = s[1]
			}
		case strings.HasPrefix(line, "DOCKER_TLS_VERIFY="):
			c.TLSConfig.Verify = true
		}
	}

	if configDir == "" {
		configDir = filepath.Join(homedir.Get(), ".docker")
	}
	if dockerCertPath == "" {
		dockerCertPath = configDir
	}

	c.TLSConfig.CACert = filepath.Join(dockerCertPath, "ca.pem")
	c.TLSConfig.Cert = filepath.Join(dockerCertPath, "cert.pem")
	c.TLSConfig.Key = filepath.Join(dockerCertPath, "key.pem")
	return nil
}

func nullTermToStrings(b []byte) []string {
	return strings.Split(string(b[:len(b)-1]), "\000")
}
