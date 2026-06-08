# Cloud cheatsheet

## Azure

``` shell
$ asdf plugin add azure-client
$ asdf install azure-client latest
$ asdf global azure-cli 2.70.0
```

``` shell
$ az login
```

``` shell
$ cat ~/.azure/config
[cloud]
name = AzureCloud

[defaults]
group = <resource group>
location = germanywestcentral
vm = <vmprefix>

[storage]
account = <account name>
```

``` shell
$ az vm image list --offer sles-15-sp3-byos --all | jq '.[-1]'
{
  "offer": "sles-15-sp3-byos",
  "publisher": "SUSE",
  "sku": "gen2",
  "urn": "SUSE:sles-15-sp3-byos:gen2:2022.05.05",
  "version": "2022.05.05"
}
```

``` shell
$ az sshkey create --public-key "$(ssh-add -L | grep ssh-rsa)" --name <key name>
```

``` shell
$ az vm create --name <vm name> --image SUSE:sles-15-sp3-byos:gen2:2022.05.05 \
    --ssh-key-name <key name> --boot-diagnostics-storage csjbelka --eviction-policy Delete --nic-delete-option Delete --os-disk-delete-option Delete --admin-username sysadmin1

```

``` shell
$ az vm show --name <vm name>  | \
    jq -r '.osProfile | .linuxConfiguration.ssh.publicKeys[].path'
/home/jiri/.ssh/authorized_keys
```

``` shell
$ az vm list-ip-addresses -n csjbelka01 | grep ipAddress # for public IP
```


## Deployment


### cloud-init

Not really cloud specific, but anyway... 

How to make "scripts" to run during every boot? See
https://stackoverflow.com/questions/6475374/how-do-i-make-cloud-init-startup-scripts-run-every-time-my-ec2-instance-boots.


`cloud-init devel net-convert` might be helpful to see what final
configuration would be from cloud-init instance data (well, there
'route' is missing for some unknown reason):

``` shell
$ cat ~/metadata.yaml
instance-id: cloud-vm
local-hostname: cloud-vm
network:
  version: 2
  ethernets:
    eth0:
      match:
        macaddress: '00:0c:29:21:f1:61'
      dhcp4: false
      addresses:
        - 172.16.171.139/24
      nameservers:
        addresses: [172.16.171.254]
      routes:
        - to: 0.0.0.0/0
          via: 172.16.171.254

$ cloud-init devel net-convert \
    -m eth0,00:0c:29:21:f1:61 \
    --network-data ~/metadata.yaml \
    --kind yaml \
    --output-kind sysconfig \
    -D sles -d ./
Read input format 'yaml' from '/root/metadata.yaml'.
Wrote output format 'sysconfig' to './'

$ find ./etc/
./etc/
./etc/resolv.conf
./etc/NetworkManager
./etc/NetworkManager/conf.d
./etc/NetworkManager/conf.d/99-cloud-init.conf
./etc/udev
./etc/udev/rules.d
./etc/udev/rules.d/85-persistent-net-cloud-init.rules
./etc/sysconfig
./etc/sysconfig/network
./etc/sysconfig/network/ifcfg-eth0

$ cat ./etc/sysconfig/network/ifcfg-eth0
# Created by cloud-init on instance boot automatically, do not edit.
#
BOOTPROTO=static
IPADDR=172.16.171.139
LLADDR=00:0c:29:21:f1:61
NETMASK=255.255.255.0
STARTMODE=auto
```

Pushing _cloud-init_ data to VMware:

``` shell
$ grep -H '' metadata.yaml userdata.yaml
metadata.yaml:instance-id: cloud-vm
metadata.yaml:local-hostname: cloud-vm
metadata.yaml:network:
metadata.yaml:  version: 2
metadata.yaml:  ethernets:
metadata.yaml:    eth0:
metadata.yaml:      match:
metadata.yaml:        macaddress: '00:0c:29:21:f1:61'
metadata.yaml:      dhcp4: false
metadata.yaml:      addresses:
metadata.yaml:        - 172.16.171.139/24
metadata.yaml:      nameservers:
metadata.yaml:        addresses: [172.16.171.254]
metadata.yaml:      routes:
metadata.yaml:        - to: 0.0.0.0/0
metadata.yaml:          via: 172.16.171.254
userdata.yaml:#cloud-config
userdata.yaml:
userdata.yaml:users:
userdata.yaml:  - default

$ export METADATA=$(gzip -c9 <metadata.yaml | { base64 -w0 2>/dev/null || base64; }) \
    USERDATA=$(gzip -c9 <userdata.yaml | { base64 -w0 2>/dev/null || base64; })

$ printenv | grep GOVC | sed 's/=.*/=******/'
GOVC_PASSWORD=******
GOVC_URL=******
GOVC_USERNAME=******
GOVC_INSECURE=******

$ export VM=/ha-datacenter/vm/test01
$ govc vm.change -vm "${VM}" -e guestinfo.metadata="${METADATA}" \
    -e guestinfo.metadata.encoding="gzip+base64" \
    -e guestinfo.userdata="${USERDATA}" \
    -e guestinfo.userdata.encoding="gzip+base64"

$ vmtoolsd --cmd "info-get guestinfo.metadata" | base64 -d | zcat -
instance-id: cloud-vm
local-hostname: cloud-vm
network:
  version: 2
  ethernets:
    eth0:
      match:
        macaddress: '00:0c:29:21:f1:61'
      dhcp4: false
      addresses:
        - 172.16.171.139/24
      nameservers:
        addresses: [172.16.171.254]
      routes:
        - to: 0.0.0.0/0
          via: 172.16.171.254

$ vmtoolsd --cmd "info-get guestinfo.userdata" | base64 -d | zcat -
#cloud-config

users:
  - default
```

Some _cloud-init_ commands:
- `cloud-init collect-logs -uv`
- `cloud-init clean -l --machine-id -s` # remove logs, zero machine-id and remove CI seed dir
- `DEBUG_LEVEL=2 DI_LOG=stderr /usr/lib/cloud-init/ds-identify --force` # detect datasources
- `cloud-id` # which datasource is being used by CI
  ``` shell
  # not yet run, or `cloud-init clean -s' was used
  $ cloud-id
  not run
  ```


### Interactive cloud-init during the first boot

Just a proof of concept. BTW, `bootcmd` runs too late! Some code
stolen fro JeOS-firstboot ;)

(FYI, 'seedfrom' needs >= cloud-init-25...)

``` shell
$ grep -H '' \
  /etc/cloud/cloud.cfg.d/00-datasource.cfg \
  /etc/ask-cloud-init.sh \
  /etc/systemd/system/ask-cloud-init.service \
  /etc/systemd/system/cloud-init-local.service.d/override.conf
/etc/cloud/cloud.cfg.d/00-datasource.cfg:datasource_list: [ NoCloud, None ]
/etc/cloud/cloud.cfg.d/00-datasource.cfg:datasource:
/etc/cloud/cloud.cfg.d/00-datasource.cfg:  NoCloud:
/etc/cloud/cloud.cfg.d/00-datasource.cfg:    seedfrom: file:///etc/cloud/seed/nocloud
/etc/ask-cloud-init.sh:#!/bin/bash
/etc/ask-cloud-init.sh:set -euo pipefail
/etc/ask-cloud-init.sh:
/etc/ask-cloud-init.sh:CFG_DIR="/etc/cloud/seed/nocloud"
/etc/ask-cloud-init.sh:mkdir -p "$CFG_DIR"
/etc/ask-cloud-init.sh:
/etc/ask-cloud-init.sh:exec </dev/console >/dev/console 2>&1
/etc/ask-cloud-init.sh:
/etc/ask-cloud-init.sh:cleanup() {
/etc/ask-cloud-init.sh:    # Re-enable systemd status output.
/etc/ask-cloud-init.sh:    if ! dbus-send --system --print-reply \
/etc/ask-cloud-init.sh:        --dest=org.freedesktop.systemd1 \
/etc/ask-cloud-init.sh:        /org/freedesktop/systemd1 \
/etc/ask-cloud-init.sh:        org.freedesktop.systemd1.Manager.SetShowStatus string: \
/etc/ask-cloud-init.sh:        &>/dev/null; then
/etc/ask-cloud-init.sh:        kill -s SIGRTMAX-10 1 2>/dev/null || true
/etc/ask-cloud-init.sh:    fi
/etc/ask-cloud-init.sh:
/etc/ask-cloud-init.sh:    # Re-enable kernel messages on console.
/etc/ask-cloud-init.sh:    setterm -msg on 2>/dev/null || true
/etc/ask-cloud-init.sh:
/etc/ask-cloud-init.sh:    echo
/etc/ask-cloud-init.sh:}
/etc/ask-cloud-init.sh:trap cleanup EXIT INT TERM
/etc/ask-cloud-init.sh:
/etc/ask-cloud-init.sh:read_nonempty() {
/etc/ask-cloud-init.sh:    local input=""
/etc/ask-cloud-init.sh:    local prompt="$1"
/etc/ask-cloud-init.sh:    while [[ -z "$input" ]]; do
/etc/ask-cloud-init.sh:        read -r -p "$prompt" input
/etc/ask-cloud-init.sh:    done
/etc/ask-cloud-init.sh:    printf '%s\n' "$input"
/etc/ask-cloud-init.sh:}
/etc/ask-cloud-init.sh:
/etc/ask-cloud-init.sh:# Disable kernel messages on console.
/etc/ask-cloud-init.sh:setterm -msg off 2>/dev/null || true
/etc/ask-cloud-init.sh:
/etc/ask-cloud-init.sh:# Disable systemd status messages on console.
/etc/ask-cloud-init.sh:if ! dbus-send --system --print-reply \
/etc/ask-cloud-init.sh:    --dest=org.freedesktop.systemd1 \
/etc/ask-cloud-init.sh:    /org/freedesktop/systemd1 \
/etc/ask-cloud-init.sh:    org.freedesktop.systemd1.Manager.SetShowStatus string:off \
/etc/ask-cloud-init.sh:    &>/dev/null; then
/etc/ask-cloud-init.sh:    kill -s SIGRTMAX-9 1 2>/dev/null || true
/etc/ask-cloud-init.sh:    sleep 1
/etc/ask-cloud-init.sh:fi
/etc/ask-cloud-init.sh:
/etc/ask-cloud-init.sh:stty sane 2>/dev/null || true
/etc/ask-cloud-init.sh:stty erase '^H' 2>/dev/null || true
/etc/ask-cloud-init.sh:clear || true
/etc/ask-cloud-init.sh:
/etc/ask-cloud-init.sh:echo
/etc/ask-cloud-init.sh:echo "=================================================="
/etc/ask-cloud-init.sh:echo "          INITIAL SYSTEM CONFIGURATION"
/etc/ask-cloud-init.sh:echo "=================================================="
/etc/ask-cloud-init.sh:echo
/etc/ask-cloud-init.sh:
/etc/ask-cloud-init.sh:CHOSEN_HOSTNAME="$(read_nonempty 'Enter System Hostname (e.g. suse-node01): ')"
/etc/ask-cloud-init.sh:
/etc/ask-cloud-init.sh:read -r MAC <<< "$(
/etc/ask-cloud-init.sh:    ip -o link show |
/etc/ask-cloud-init.sh:    awk '$2 !~ /^lo:/ {
/etc/ask-cloud-init.sh:        for (i = 1; i <= NF; i++) {
/etc/ask-cloud-init.sh:            if ($i == "link/ether") {
/etc/ask-cloud-init.sh:                print $(i + 1)
/etc/ask-cloud-init.sh:                exit
/etc/ask-cloud-init.sh:            }
/etc/ask-cloud-init.sh:        }
/etc/ask-cloud-init.sh:    }'
/etc/ask-cloud-init.sh:)"
/etc/ask-cloud-init.sh:
/etc/ask-cloud-init.sh:echo
/etc/ask-cloud-init.sh:echo "Detected primary interface with HW address: $MAC"
/etc/ask-cloud-init.sh:echo "--------------------------------------------------"
/etc/ask-cloud-init.sh:
/etc/ask-cloud-init.sh:IP_ADDR="$(read_nonempty 'nter Static IP with Prefix (e.g. 192.168.1.50/24): ')"
/etc/ask-cloud-init.sh:GATEWAY="$(read_nonempty 'Enter Gateway IP (e.g. 192.168.1.1): ')"
/etc/ask-cloud-init.sh:DNS_SERVER="$(read_nonempty 'Enter DNS Server IP (e.g. 8.8.8.8): ')"
/etc/ask-cloud-init.sh:
/etc/ask-cloud-init.sh:cat > "$CFG_DIR/meta-data" <<EOF
/etc/ask-cloud-init.sh:instance-id: iid-$CHOSEN_HOSTNAME
/etc/ask-cloud-init.sh:local-hostname: $CHOSEN_HOSTNAME
/etc/ask-cloud-init.sh:dsmode: local
/etc/ask-cloud-init.sh:EOF
/etc/ask-cloud-init.sh:
/etc/ask-cloud-init.sh:cat > "$CFG_DIR/user-data" <<EOF
/etc/ask-cloud-init.sh:#cloud-config
/etc/ask-cloud-init.sh:{}
/etc/ask-cloud-init.sh:EOF
/etc/ask-cloud-init.sh: 
/etc/ask-cloud-init.sh:cat > "$CFG_DIR/network-config" <<EOF
/etc/ask-cloud-init.sh:network:
/etc/ask-cloud-init.sh:  version: 2
/etc/ask-cloud-init.sh:  ethernets:
/etc/ask-cloud-init.sh:    interface0:
/etc/ask-cloud-init.sh:      match:
/etc/ask-cloud-init.sh:        macaddress: '$MAC'
/etc/ask-cloud-init.sh:      set-name: eth0
/etc/ask-cloud-init.sh:      dhcp4: false
/etc/ask-cloud-init.sh:      dhcp6: false
/etc/ask-cloud-init.sh:      addresses:
/etc/ask-cloud-init.sh:        - $IP_ADDR
/etc/ask-cloud-init.sh:      routes:
/etc/ask-cloud-init.sh:        - to: 0.0.0.0/0
/etc/ask-cloud-init.sh:          via: $GATEWAY
/etc/ask-cloud-init.sh:      nameservers:
/etc/ask-cloud-init.sh:        addresses:
/etc/ask-cloud-init.sh:          - $DNS_SERVER
/etc/ask-cloud-init.sh:EOF
/etc/ask-cloud-init.sh:
/etc/ask-cloud-init.sh:chmod 644 "$CFG_DIR"/{meta-data,user-data,network-config}
/etc/ask-cloud-init.sh:
/etc/ask-cloud-init.sh:echo
/etc/ask-cloud-init.sh:echo "--> NoCloud configuration written successfully:"
/etc/ask-cloud-init.sh:echo
/etc/ask-cloud-init.sh:echo "--> Hostname: $CHOSEN_HOSTNAME"
/etc/ask-cloud-init.sh:echo "--> Interface HW address: $MAC"
/etc/ask-cloud-init.sh:echo "--> IP address: $IP_ADDR"
/etc/ask-cloud-init.sh:echo "--> Gateway: $GATEWAY"
/etc/ask-cloud-init.sh:echo "--> DNS: $DNS_SERVER"
/etc/ask-cloud-init.sh:echo
/etc/ask-cloud-init.sh:echo "--> Handing control over to cloud-init..."
/etc/ask-cloud-init.sh:sleep 2
/etc/systemd/system/ask-cloud-init.service:[Unit]
/etc/systemd/system/ask-cloud-init.service:Description=Interactive cloud-init setup
/etc/systemd/system/ask-cloud-init.service:DefaultDependencies=no
/etc/systemd/system/ask-cloud-init.service:After=local-fs.target plymouth-start.service
/etc/systemd/system/ask-cloud-init.service:Conflicts=plymouth-start.service
/etc/systemd/system/ask-cloud-init.service:Before=cloud-init-local.service
/etc/systemd/system/ask-cloud-init.service:Before=getty@tty1.service serial-getty@ttyS0.service systemd-user-sessions.service
/etc/systemd/system/ask-cloud-init.service:ConditionPathExists=!/etc/cloud/cloud.cfg.d/80_ask_cloud_init.cfg
/etc/systemd/system/ask-cloud-init.service:
/etc/systemd/system/ask-cloud-init.service:[Service]
/etc/systemd/system/ask-cloud-init.service:Type=oneshot
/etc/systemd/system/ask-cloud-init.service:Environment=TERM=linux
/etc/systemd/system/ask-cloud-init.service:ExecStartPre=/bin/sh -c "/usr/bin/plymouth quit 2>/dev/null || :"
/etc/systemd/system/ask-cloud-init.service:ExecStart=/etc/ask-cloud-init.sh
/etc/systemd/system/ask-cloud-init.service:StandardInput=tty
/etc/systemd/system/ask-cloud-init.service:StandardOutput=tty
/etc/systemd/system/ask-cloud-init.service:StandardError=tty
/etc/systemd/system/ask-cloud-init.service:TTYPath=/dev/console
/etc/systemd/system/ask-cloud-init.service:RemainAfterExit=yes
/etc/systemd/system/ask-cloud-init.service:
/etc/systemd/system/ask-cloud-init.service:[Install]
/etc/systemd/system/ask-cloud-init.service:WantedBy=sysinit.target
/etc/systemd/system/cloud-init-local.service.d/override.conf:[Unit]
/etc/systemd/system/cloud-init-local.service.d/override.conf:Requires=ask-cloud-init.service
/etc/systemd/system/cloud-init-local.service.d/override.conf:After=ask-cloud-init.service
```

```
==================================================
          INITIAL SYSTEM CONFIGURATION
==================================================

Enter System Hostname (e.g. suse-node01): kukurice

Detected primary interface with HW address: 52:54:00:57:fc:7b
--------------------------------------------------
nter Static IP with Prefix (e.g. 192.168.1.50/24): 192.168.252.78/24
Enter Gateway IP (e.g. 192.168.1.1): 192.168.252.1
Enter DNS Server IP (e.g. 8.8.8.8): 1.1.1.1

--> NoCloud configuration written successfully:

--> Hostname: kukurice
--> Interface HW address: 52:54:00:57:fc:7b
--> IP address: 192.168.252.78/24
--> Gateway: 192.168.252.1
--> DNS: 1.1.1.1

--> Handing control over to cloud-init...

[  OK  ] Finished Interactive cloud-init setup.
```


## Ignition

Note, that *ignition* needs to match `ignition.platform.id` and
provided that, that is, if you would have `ignition.platform.id=metal`
and would in fact use QEMU sysinfo, it won't work!

``` shell
$ for i in /var/lib/libvirt/images/iso/SUSE-Manager-Server.x86_64-5.0.0*; do \
    echo '#' image: $i ; virt-cat -a $i /boot/grub2/grub.cfg | grep -Po -m1 'ignition.platform.id=\S+'; \
  done
# image: /var/lib/libvirt/images/iso/SUSE-Manager-Server.x86_64-5.0.0-Qcow-GM.qcow2
ignition.platform.id=qemu
# image: /var/lib/libvirt/images/iso/SUSE-Manager-Server.x86_64-5.0.0-Raw-GM.raw
ignition.platform.id=metal

$ virsh dumpxml jbelka-jbmrt55qe01 | xmllint --xpath '//sysinfo' -
<sysinfo type="fwcfg">
    <entry name="opt/com.coreos/config" file="/var/lib/libvirt/images/jbelka/jbmrt55qe01.config.ign"/>
    <entry name="opt/org.opensuse.combustion/script" file="/var/lib/libvirt/images/jbelka/jbmrt55qe01.combustion.sh"/>
  </sysinfo>
```

[*Ignition*](https://coreos.github.io/butane/config-fcos-v1_5/) config
can be generated, eg. https://opensuse.github.io/fuel-ignition.

``` shell
$ cat jbm155qe01.config.ign
{
  "ignition": {
    "version": "3.2.0"
  },
  "passwd": {
    "users": [
      {
        "name": "root",
        "passwordHash": "$2a$10$UQcdA3i2uB5p/XNeDzYfCemxBW1hdDfj6yCgRqDENHxxhbsB7DqRW",
        "sshAuthorizedKeys": [
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE1x+93H1K9QT62tvFbO3M8Ze5JvjtDB4QeslJJx60xi"
        ]
      }
    ]
  },
  "storage": {
    "Files": [
      {
        "path": "/etc/hostname",
        "mode": 420,
        "overwrite": true,
        "contents": {
          "source": "data:,jbm55qe01"
        }
      },
      {
        "path": "/etc/NetworkManager/system-connections/eth0.nmconnection",
        "mode": 384,
        "overwrite": true,
        "contents": {
          "source": "data:text/plain;charset=utf-8;base64,Cltjb25uZWN0aW9uXQppZD1ldGgwCnR5cGU9ZXRoZXJuZXQKaW50ZXJmYWNlLW5hbWU9ZXRoMAoKW2lwdjRdCmRucy1zZWFyY2g9Cm1ldGhvZD1hdXRvCgpbaXB2Nl0KZG5zLXNlYXJjaD0KYWRkci1nZW4tbW9kZT1ldWk2NAptZXRob2Q9aWdub3JlCg==",
          "human_read": "\n[connection]\nid=eth0\ntype=ethernet\ninterface-name=eth0\n\n[ipv4]\ndns-search=\nmethod=auto\n\n[ipv6]\ndns-search=\naddr-gen-mode=eui64\nmethod=ignore\n"
        }
      },
      {
        "path": "/etc/NetworkManager/conf.d/noauto.conf",
        "mode": 420,
        "overwrite": true,
        "contents": {
          "source": "data:text/plain;charset=utf-8;base64,W21haW5dCiMgRG8gbm90IGRvIGF1dG9tYXRpYyAoREhDUC9TTEFBQykgY29uZmlndXJhdGlvbiBvbiBldGhlcm5ldCBkZXZpY2VzCiMgd2l0aCBubyBvdGhlciBtYXRjaGluZyBjb25uZWN0aW9ucy4Kbm8tYXV0by1kZWZhdWx0PSoK",
          "human_read": "[main]\n# Do not do automatic (DHCP/SLAAC) configuration on ethernet devices\n# with no other matching connections.\nno-auto-default=*\n"
        }
      }
    ]
  }
}

```
