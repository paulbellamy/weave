package main

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"code.google.com/p/getopt"
	"github.com/fsouza/go-dockerclient"
	. "github.com/weaveworks/weave/common"
	"github.com/weaveworks/weave/proxy"
)

var (
	version           = "(unreleased version)"
	defaultDockerAddr = "unix:///var/run/docker.sock"
	defaultListenAddr = ":12375"
	containerName     = "weaveproxy"
)

func main() {
	var (
		launchFlag  bool
		debug       bool
		justVersion bool
		c           = proxy.Config{
			DockerAddr: defaultDockerAddr,
			ListenAddr: defaultListenAddr,
		}
	)

	c.Version = version
	getopt.BoolVarLong(&launchFlag, "launch", 0, "Parse arguments and launch the proxy docker container (must be the first option)")
	getopt.BoolVarLong(&debug, "debug", 'd', "log debugging information")
	getopt.BoolVarLong(&justVersion, "version", 0, "print version and exit")
	getopt.StringVar(&c.ListenAddr, 'L', fmt.Sprintf("address on which to listen (default %s)", defaultListenAddr))
	getopt.StringVar(&c.DockerAddr, 'H', fmt.Sprintf("docker daemon URL to proxy (default %s)", defaultDockerAddr))
	getopt.StringVarLong(&c.TLSConfig.CACert, "tlscacert", 0, "Trust certs signed only by this CA")
	getopt.StringVarLong(&c.TLSConfig.Cert, "tlscert", 0, "Path to TLS certificate file")
	getopt.BoolVarLong(&c.TLSConfig.Enabled, "tls", 0, "Use TLS; implied by --tlsverify")
	getopt.StringVarLong(&c.TLSConfig.Key, "tlskey", 0, "Path to TLS key file")
	getopt.BoolVarLong(&c.TLSConfig.Verify, "tlsverify", 0, "Use TLS and verify the remote")
	getopt.BoolVarLong(&c.WithDNS, "with-dns", 'w', "instruct created containers to use weaveDNS as their nameserver")
	getopt.BoolVarLong(&c.WithIPAM, "with-ipam", 'i', "automatically allocate addresses for containers without a WEAVE_CIDR")
	getopt.Parse()

	if justVersion {
		fmt.Printf("weave proxy %s\n", version)
		os.Exit(0)
	}

	if debug {
		InitDefaultLogging(true)
	}

	if launchFlag {
		launch(c)
		return
	}

	p, err := proxy.NewProxy(c)
	if err != nil {
		Error.Fatalf("Could not start proxy: %s", err)
	}

	if err := p.ListenAndServe(); err != nil {
		Error.Fatalf("Could not listen on %s: %s", p.ListenAddr, err)
	}
}

func launch(c proxy.Config) {
	// TODO: support args with spaces in them, in DOCKER_CLIENT_ARGS and
	// WEAVEPROXY_DOCKER_ARGS
	execImage := os.Getenv("EXEC_IMAGE")
	args := strings.Fields(os.Getenv("DOCKER_CLIENT_ARGS"))
	args = append(args,
		"run",
		"--privileged",
		"-d",
		"--name", containerName,
		"--net=host",
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		"-v", "/proc:/hostproc",
		"-e", "PROCFS=/hostproc",
		"--entrypoint=/home/weave/weaveproxy",
	)
	args = append(args, strings.Fields(os.Getenv("WEAVEPROXY_DOCKER_ARGS"))...)

	port := 12375
	if c.ListenAddr != "" {
		_, p, err := net.SplitHostPort(c.ListenAddr)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		pInt64, err := strconv.ParseInt(p, 10, 32)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		port = int(pInt64)
	}
	args = append(args, "-p", fmt.Sprintf("%d:%d/tcp", port, port))

	if c.TLSConfig.CACert != "" {
		args = append(args, mountArgs(c.TLSConfig.CACert)...)

	}

	if c.TLSConfig.Cert != "" {
		args = append(args, mountArgs(c.TLSConfig.Cert)...)
	}

	if c.TLSConfig.Key != "" {
		args = append(args, mountArgs(c.TLSConfig.Key)...)
	}

	args = append(args, execImage)
	args = append(args, os.Args[2:]...)

	containerID := &bytes.Buffer{}
	cmd := exec.Command("docker", args...)
	cmd.Stdout = containerID
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}

	if err := waitForProxyToBoot(c.DockerAddr, port); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println(containerID.String())
}

func mountArgs(path string) []string {
	return []string{"-v", fmt.Sprintf("%s:%s", path, path)}
}

// Stub Proof of Concept here, for now.
func waitForProxyToBoot(dockerAddr string, port int) error {
	url := fmt.Sprintf("http://127.0.0.1:%d/status", port)
	dockerClient, err := docker.NewClient(dockerAddr)
	if err != nil {
		return err
	}

	for {
		if _, err := http.Get(url); err == nil {
			break
		}

		if _, err := dockerClient.InspectContainer(containerName); err != nil {
			switch err.(type) {
			case *docker.NoSuchContainer:
				return fmt.Errorf("%s container has died", containerName)
			default:
				return err
			}
		}

		time.Sleep(100 * time.Millisecond)
	}
	return nil
}
