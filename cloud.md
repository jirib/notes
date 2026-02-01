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
