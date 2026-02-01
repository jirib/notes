# Containers cheatsheet


## docker


### making all containers to use a proxy

``` shell
cat > /root/.docker/config.json <<EOF
{
  "proxies": {
    "default": {
      "httpProxy": "<url>",
      "httpsProxy": "<url>"
    }
  }
}
EOF

systemctl restart docker
```

``` shell
# a test proxy
pip install --user proxy.py
proxy --hostname 0.0.0.0 --port 8080 --log-level DEBUG

# a test container
docker run -d -it opensuse/leap:15.2 /bin/bash -c 'while :; do sleep 1; done'
docker exec -it <container> /bin/bash -c 'echo $http_proxy'
> <url>
docker exec -it <container> /usr/bin/zypper ref # and see traffic in proxy stdout
```


### making docker daemon to use a proxy

``` shell
# cat /etc/systemd/system/docker.service.d/override.conf
[Service]
Environment="HTTP_PROXY=http://127.0.0.1:8080"
Environment="HTTPS_PROXY=http://127.0.0.1:8080"
Environment="NO_PROXY=localhost,127.0.0.1"

# systemctl daemon-reload
# systemctl restart docker

# systemctl show -p Environment docker
Environment=HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=https://127.0.0.1:8080 NO_PROXY=localhost,127.0.0.1
```


## podman

``` shell
$ podman ps --format {{.<tab>
{{.AutoRemove}}                                                  {{.ImageID}}                                                     {{.PodName}}
{{.CGROUPNS}}                                                    {{.Image}}                                                       {{.Pod}}
{{.CIDFile}}                                                     {{.IsInfra}}                                                     {{.Ports}}
{{.Cgroup}}                                                      {{.Label                                                         {{.Restarts}}
{{.Command}}                                                     {{.Labels.                                                       {{.RunningFor}}
{{.Created.                                                      {{.ListContainer.                                                {{.Size}}
{{.CreatedAt}}                                                   {{.MNT}}                                                         {{.StartedAt}}
{{.CreatedHuman}}                                                {{.Mounts}}                                                      {{.State}}
{{.ExitCode}}                                                    {{.NET}}                                                         {{.Status}}
{{.ExitedAt}}                                                    {{.Namespaces.                                                   {{.USERNS}}
{{.Exited}}                                                      {{.Names}}                                                       {{.UTS}}
{{.ExposedPorts.                                                 {{.Networks}}                                                    {{.User}}
{{.ID}}                                                          {{.PIDNS}}                                                       
{{.IPC}}                                                         {{.Pid}}                                                         
```


### podman: secrets

podman secrets are nice, see [Exploring the new Podman secret command
](https://web.archive.org/web/20250520114616/https://www.redhat.com/en/blog/new-podman-secrets-command).

``` shell
$ podman secret ls
ID                         NAME            DRIVER      CREATED        UPDATED
9a50fdd4367b502dfa601ff78  rmt-server.crt  file        12 months ago  12 months ago
21d0def4f89c551112fbb602d  rmt.conf        file        12 months ago  12 months ago
6c7204f5e97475e18e2d1c2b8  rmt-server.key  file        12 months ago  12 months ago
8861071cf4e95ee0d617b1f0c  rmt-ca.crt      file        12 months ago  12 months ago

$ podman secret inspect rmt.conf 
[
    {
        "ID": "21d0def4f89c551112fbb602d",
        "CreatedAt": "2024-04-26T05:47:03.494575314-04:00",
        "UpdatedAt": "2024-04-26T05:47:03.494575314-04:00",
        "Spec": {
            "Name": "rmt.conf",
            "Driver": {
                "Name": "file",
                "Options": {
                    "path": "/var/lib/containers/storage/secrets/filedriver"
                }
            },
            "Labels": {}
        }
    }
]

$ jq -r '."21d0def4f89c551112fbb602d"' /var/lib/containers/storage/secrets/filedriver/secretsdata.json | base64 -d
---
database:
  host: localhost
  database: *******
  username: *******
  password: '******
  adapter: mysql2
  encoding: utf8
  timeout: 5000
  pool: 5
scc:
  username: **********
  password: **********
  sync_systems: true
mirroring:
  mirror_src: false
  verify_rpm_checksums: false
  dedup_method: hardlink
http_client:
  verbose: false
  proxy: 
  proxy_auth: 
  proxy_user: 
  proxy_password: 
  low_speed_limit: 512
  low_speed_time: 120
log_level:
  rails: debug
  cli: debug
web_server:
  min_threads: 5
  max_threads: 5
  workers: 2
```
