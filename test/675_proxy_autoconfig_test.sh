#! /bin/bash

. ./config.sh

wait_for() {
  for i in {0..10}; do
    if "$@" 2>&1 >/dev/null ; then
      return 0
    fi
    sleep 1
  done
  echo "Timed out waiting for $@" >&2
  return 1
}

PIDFILE=/var/run/docker-ssd.pid

after_suite() {
  run_on $HOST1 "
    [ ! -f '$PIDFILE' ] || sudo start-stop-daemon --stop --pidfile '$PIDFILE'
    service docker status | grep -q 'docker start/running' >/dev/null ||
      sudo service docker start"
  wait_for docker_on $HOST1 ps
}

start_suite "Boot the proxy with TLS and Listening autoconfigured from Docker"

# Reboot docker daemon with tls
run_on $HOST1 sudo service docker stop 2>&1 >/dev/null || true
PWD=$($SSH $HOST1 pwd)
run_on $HOST1 sudo start-stop-daemon --start --background \
  --exec /usr/bin/docker \
  --pidfile "$PIDFILE" \
  --make-pidfile \
  -- \
    -d \
    -H unix:///var/run/docker.sock \
    -H tcp://0.0.0.0:2375 \
    --tlsverify \
    --tlscacert $PWD/tls/ca.pem \
    --tlscert   $PWD/tls/$HOST1.pem \
    --tlskey    $PWD/tls/$HOST1-key.pem \
    2>&1 >/dev/null

wait_for docker_tls_on $HOST1 ps

# Boot proxy and check it uses dockers tls config
run_on $HOST1 sudo weave launch-router
run_on $HOST1 sudo weave launch-proxy

assert_raises "proxy docker_tls_on $HOST1 ps"

end_suite
