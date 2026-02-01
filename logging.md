# Logging & monitoring cheatsheet


## Rsyslog

`rsyslog` is ..., but anyway, TLS client fowarding:

``` shell
global(
  DefaultNetstreamDriverCAFile="<path>"
  DefaultNetstreamDriverCertFile="<path>"
  DefaultNetstreamDriverKeyFile="<path>"
)

# Set up the action for all messages
*.* action(
  type="omfwd"
  StreamDriver="gtls"
  StreamDriverMode="1"
  StreamDriverAuthMode="anon"
  target="127.0.0.1" port="12345" protocol="tcp"
))
```

Since 8.2108.0, one should be able to define TLS settings in _omfwd_ module directly:

``` shell
  StreamDriver.CAFile="<path>"
  StreamDriver.KeyFile="<path>"
  StreamDriver.CertFile="<path>"
```


### Rsyslog: on SLES

``` shell
$ systemctl stop rsyslog.service syslog.socket
$ ls -l /dev/log
lrwxrwxrwx 1 root root 28 Nov 30 15:47 /dev/log -> /run/systemd/journal/dev-log

$ pgrep -c rsyslogd
0

$ rsyslogd -iNONE -d -n 2>&1 | tee /tmp/rsyslogd.out.txt
...

$ lsof -np $(pgrep rsyslogd) | grep -P 'unix\b.*DGRAM'
rsyslogd 27268 root    4u  unix 0xffff997cf9256a80      0t0      63700 /run/systemd/journal/syslog type=DGRAM
rsyslogd 27268 root    6u  unix 0xffff997cf9257740      0t0      63702 type=DGRAM
```


### Vector

**NOTE**: as of Dec 21 2022, _vector_ can't write to datagram-oriented
unix sockets (SOCK_DGRAM), so eg. using a sink for a rsyslog unix
socket won't work!

> Vector is a high-performance observability data pipeline that puts
> organizations in control of their observability data. Collect,
> transform, and route all your logs, metrics, and traces to any
> vendors...

Vector is written in Rust...

A primitive configuration could be something like this:

``` shell
$ cat vector.toml
[sources.my_source_id]
type = "syslog"
address = "127.0.0.1:12345"
mode = "tcp"
tls.key_file = "<path>"
tls.crt_file = "<path>"
tls.ca_file = "<path>"
tls.enabled = true

[sinks.my_sink_id]
type = "console"
inputs = [ "my_source_id" ]
target = "stdout"
encoding.codec = "text"

$ vector -c vector.toml
2022-10-04T14:00:18.142247Z  INFO vector::app: Log level is enabled. level="vector=info,codec=info,vrl=info,file_source=info,tower_limit=trace,rdkafka=info,buffers=info,kube=info"
2022-10-04T14:00:18.142319Z  INFO vector::app: Loading configs. paths=["vector.toml"]
2022-10-04T14:00:18.146363Z  INFO vector::topology::running: Running healthchecks.
2022-10-04T14:00:18.146482Z  INFO vector::topology::builder: Healthcheck: Passed.
2022-10-04T14:00:18.146493Z  INFO vector: Vector has started. debug="false" version="0.24.1" arch="x86_64" build_id="8935681 2022-09-12"
2022-10-04T14:00:18.146516Z  INFO vector::app: API is disabled, enable by setting `api.enabled` to `true` and use commands like `vector top`.
2022-10-04T14:00:18.149903Z  INFO source{component_kind="source" component_id=my_source_id component_type=syslog component_name=my_source_id}: vector::sources::util::tcp: Listening. addr=127.0.0.1:12345
```


### sysstat aka sar

To get a graphical output from `sar` files, one can:

``` shell
$ sadf -O showtoc,showinfo -g -- -A <sa file> > /tmp/out.svg
```

Reading `sar` files is `TZ` dependent:

``` shell
$ ag --nofilename --nocolor --nogroup '^2024-06-30T.*Linux version' | grep -Pv '^\s*(#|$)' | sort -u | cut -c1-80
2024-06-30T14:36:48.584469+08:00 example01 kernel: [    0.000000][    T0] Linux ve
2024-06-30T16:09:14.103268+08:00 example01 kernel: [    0.000000][    T0] Linux ve
2024-06-30T16:25:42.728050+08:00 example01 kernel: [    0.000000][    T0] Linux ve
2024-06-30T16:59:41.364945+08:00 example01 kernel: [    0.000000][    T0] Linux ve
2024-06-30T17:16:39.920318+08:00 example01 kernel: [    0.000000][    T0] Linux ve
2024-06-30T17:26:30.210241+08:00 example02 kernel: [    0.000000][    T0] Linux ve

$ TZ=Asia/Taipei LC_TIME=POSIX sar -n UDP -f scc_example01_240701_1645/sar/sa20240630 | grep RESTART
14:36:48     LINUX RESTART      (8 CPU)
16:09:14     LINUX RESTART      (8 CPU)
16:25:42     LINUX RESTART      (8 CPU)
16:59:41     LINUX RESTART      (8 CPU)
17:16:39     LINUX RESTART      (8 CPU)

## versus ##

$ LC_TIME=POSIX sar -n UDP -f scc_example01_240701_1645/sar/sa20240630 | grep RESTART
08:36:48     LINUX RESTART      (8 CPU)
10:09:14     LINUX RESTART      (8 CPU)
10:25:42     LINUX RESTART      (8 CPU)
10:59:41     LINUX RESTART      (8 CPU)
11:16:39     LINUX RESTART      (8 CPU)
```
