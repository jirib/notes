## VMware cheatsheet

### esxi

A bit old boot parameters are described at [ESXi 7.0 Update 3i Build
20842708 Kernel Settings
](https://github.com/lamw/esxi-advanced-and-kernel-settings/blob/master/esxi-70u3i-kernel-settings.md).


#### cli

``` shell
# esxcli system version get
   Product: VMware ESXi
   Version: 6.7.0
   Build: Releasebuild-14320388
   Update: 3
   Patch: 73

# esxcli system time get
2021-08-13T08:46:15Z

# esxcli storage core device list | \
  grep -e '^t' -e 'Is SSD:' -e 'Size:' -e 'Model:'
t10.ATA_____Crucial_CT500MX200SSD1__________________________16151246A1D2
   Size: 476940
   Model: Crucial_CT500MX2
   Is SSD: true
   Queue Full Sample Size: 0
t10.ATA_____ST1000VN0002D1HJ162__________________________________W513PSZ8
   Size: 953869
   Model: ST1000VN000-1HJ1
   Is SSD: false
   Queue Full Sample Size: 0
t10.ATA_____ST1000VN0002D1HJ162__________________________________W513PRQF
   Size: 953869
   Model: ST1000VN000-1HJ1
   Is SSD: false
   Queue Full Sample Size: 0

# esxcli storage filesystem list
Mount Point                                        Volume Name  UUID                                 Mounted  Type            Size          Free
-------------------------------------------------  -----------  -----------------------------------  -------  ------  ------------  ------------
/vmfs/volumes/611624d3-0014912e-65a2-525400f29a2a  datastore1   611624d3-0014912e-65a2-525400f29a2a     true  VMFS-6   77846282240   76336332800
/vmfs/volumes/61162d2b-5f009ee4-baf7-525400f29a2a  suse-ssd     61162d2b-5f009ee4-baf7-525400f29a2a     true  VMFS-6  127775277056  126264279040
/vmfs/volumes/59c94171-6bfc5643-4f06-be7836afec3a               59c94171-6bfc5643-4f06-be7836afec3a     true  vfat       261853184     106246144
/vmfs/volumes/611624cd-6458f9a6-e893-525400f29a2a               611624cd-6458f9a6-e893-525400f29a2a     true  vfat       299712512     117448704
/vmfs/volumes/611624d4-365d7e53-f419-525400f29a2a               611624d4-365d7e53-f419-525400f29a2a     true  vfat      4293591040    4288217088
/vmfs/volumes/67d90978-7172b177-19e6-fd87141790fe               67d90978-7172b177-19e6-fd87141790fe     true  vfat       261853184     261849088
```

#### logs

See [ESXi Log File
Locations](https://docs.vmware.com/en/VMware-vSphere/6.7/com.vmware.vsphere.monitoring.doc/GUID-832A2618-6B11-4A28-9672-93296DA931D0.html)
for ESXi logs details.

#### ssh

OpenSSH daemon is located at `/usr/lib/vmware/openssh/bin/sshd`, thus

``` shell
# /usr/lib/vmware/openssh/bin/sshd -T | grep pubkeyacceptedkeytypes
pubkeyacceptedkeytypes ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa

# /usr/lib/vmware/openssh/bin/sshd -T | grep authorizedkeysfile
authorizedkeysfile /etc/ssh/keys-%u/authorized_keys
```

To allow *ssh-ed25519* as ssh pub key, then do

``` shell
# ssh -Q PubkeyAcceptedKeyTypes
ssh-ed25519
ssh-ed25519-cert-v01@openssh.com
sk-ssh-ed25519@openssh.com
sk-ssh-ed25519-cert-v01@openssh.com
ssh-rsa
rsa-sha2-256
rsa-sha2-512
ssh-dss
ecdsa-sha2-nistp256
ecdsa-sha2-nistp384
ecdsa-sha2-nistp521
sk-ecdsa-sha2-nistp256@openssh.com
ssh-rsa-cert-v01@openssh.com
rsa-sha2-256-cert-v01@openssh.com
rsa-sha2-512-cert-v01@openssh.com
ssh-dss-cert-v01@openssh.com
ecdsa-sha2-nistp256-cert-v01@openssh.com
ecdsa-sha2-nistp384-cert-v01@openssh.com
ecdsa-sha2-nistp521-cert-v01@openssh.com
sk-ecdsa-sha2-nistp256-cert-v01@openssh.com

# printf "PubkeyAcceptedKeyTypes ssh-ed25519,%s\n" \
  $(ssh -Q PubkeyAcceptedKeyTypes | xargs | sed 's/ /,/g') \
  >> /etc/ssh/sshd_config
# /usr/lib/vmware/openssh/bin/sshd -t
# /etc/init.d/hostd restart
# /etc/init.d/vpxa restart
```

#### network trace

``` shell
# esxcfg-vmknic -l # list physical adapters and their link state
# tcpdump-uw -i vmk0 -nNA 'tcp[(tcp[12]>>2):4] = 0x5353482D'
tcpdump-uw: verbose output suppressed, use -v or -vv for full protocol decode
listening on vmk0, link-type EN10MB (Ethernet), capture size 262144 bytes
07:01:32.489653 IP 10.156.122.245.60592 > 10.156.232.145.22: Flags [P.], seq 1659572510:1659572531, ack 2088459198, win 502, options [nop,nop,TS val 2339620356 ecr 2358490613], length 21
E..I.^@.=...
.z.
.......b...|{[.....j7.....
.s......SSH-2.0-OpenSSH_8.4

07:01:32.504702 IP 10.156.232.145.22 > 10.156.122.245.60592: Flags [P.], seq 1:22, ack 21, win 128, options [nop,nop,TS val 2358490616 ecr 2339620356], length 21
E..IV9@.@.k.
...
.z.....|{[.b..3....x......
.....s..SSH-2.0-OpenSSH_8.3
```

The above is an example of new SSH connection only.

#### esxi on KVM

``` shell
# customize for kvm_intel if not using amd

cat > /etc/modprobe.d/kvm.conf <<EOF
options kvm ignore_msrs=1 report_ignored_msrs=0
options kvm_amd nested=1
EOF

modprobe kvm
```

``` shell
cat > /tmp/esxi <<EOF
<domain type='kvm'>
  <name>esxi1</name>
  <memory unit='KiB'>8388608</memory>
  <currentMemory unit='KiB'>8388608</currentMemory>
  <vcpu placement='static'>16</vcpu>
  <resource>
    <partition>/machine</partition>
  </resource>
  <os>
    <type arch='x86_64' machine='pc-i440fx-6.0'>hvm</type>
    <boot dev='cdrom'/>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
  </features>
  <cpu mode='host-passthrough' check='none' migratable='on'/>
  <clock offset='utc'>
    <timer name='rtc' tickpolicy='catchup'/>
    <timer name='pit' tickpolicy='delay'/>
    <timer name='hpet' present='no'/>
  </clock>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <pm>
    <suspend-to-mem enabled='no'/>
    <suspend-to-disk enabled='no'/>
  </pm>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/var/lib/libvirt/images/esxi1.qcow2' index='2'/>
      <backingStore/>
      <target dev='hda' bus='ide'/>
      <alias name='ide0-0-0'/>
      <address type='drive' controller='0' bus='0' target='0' unit='0'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu'/>
      <target dev='hdb' bus='ide'/>
      <readonly/>
      <alias name='ide0-0-1'/>
      <address type='drive' controller='0' bus='0' target='0' unit='1'/>
    </disk>
    <controller type='usb' index='0' model='ich9-ehci1'>
      <alias name='usb'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x04' function='0x7'/>
    </controller>
    <controller type='usb' index='0' model='ich9-uhci1'>
      <alias name='usb'/>
      <master startport='0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x04' function='0x0' multifunction='on'/>
    </controller>
    <controller type='usb' index='0' model='ich9-uhci2'>
      <alias name='usb'/>
      <master startport='2'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x04' function='0x1'/>
    </controller>
    <controller type='usb' index='0' model='ich9-uhci3'>
      <alias name='usb'/>
      <master startport='4'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x04' function='0x2'/>
    </controller>
    <controller type='pci' index='0' model='pci-root'>
      <alias name='pci.0'/>
    </controller>
    <controller type='ide' index='0'>
      <alias name='ide'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x1'/>
    </controller>
    <interface type='network'>
      <source network='default'/>
      <!-- e1000 is not good enough for esxi 7 -->
      <model type='e1000e'/>
      <alias name='net0'/>
    </interface>
    <serial type='pty'>
      <source path='/dev/pts/9'/>
      <target type='isa-serial' port='0'>
        <model name='isa-serial'/>
      </target>
      <alias name='serial0'/>
    </serial>
    <console type='pty' tty='/dev/pts/9'>
      <source path='/dev/pts/9'/>
      <target type='serial' port='0'/>
      <alias name='serial0'/>
    </console>
    <input type='tablet' bus='usb'>
      <alias name='input0'/>
      <address type='usb' bus='0' port='1'/>
    </input>
    <input type='mouse' bus='ps2'>
      <alias name='input1'/>
    </input>
    <input type='keyboard' bus='ps2'>
      <alias name='input2'/>
    </input>
    <graphics type='vnc' port='5900' autoport='yes' listen='127.0.0.1'>
      <listen type='address' address='127.0.0.1'/>
    </graphics>
    <audio id='1' type='none'/>
    <video>
      <model type='qxl' ram='65536' vram='65536' vgamem='16384' heads='1' primary='yes'/>
      <alias name='video0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0'/>
    </video>
    <memballoon model='virtio'>
      <alias name='balloon0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>
    </memballoon>
  </devices>
</domain>
EOF

virsh define /tmp/esxi
```

#### govc

`govc` is "vSphere" CLI, written in golang.

``` shell
$ printenv | grep ^GOVC
GOVC_PASSWORD=password
GOVC_URL=https://example.com
GOVC_USERNAME=user
GOVC_INSECURE=1

$ govc about
FullName:     VMware vCenter Server 8.0.3 build-24022515
Name:         VMware vCenter Server
Vendor:       VMware, Inc.
Version:      8.0.3
Build:        24022515
OS type:      linux-x64
API type:     VirtualCenter
API version:  8.0.3.0
Product ID:   vpx
UUID:         fe57421e-0e49-4b8e-932e-a05a94ee260e

$ govc ls /Datacenter/host/
/Datacenter/host/192.168.100.3

$ govc host.info /Datacenter/host/192.168.100.3
Name:              192.168.100.3
  Path:            /Datacenter/host/192.168.100.3/192.168.100.3
  Manufacturer:    Red Hat
  Logical CPUs:    8 CPUs @ 2200MHz
  Processor type:  Intel(R) Xeon(R) Silver 4114 CPU @ 2.20GHz
  CPU usage:       123 MHz (0.7%)
  Memory:          8168MB
  Memory usage:    2655 MB (32.5%)
  Boot time:       2024-09-02 09:15:14.069137 +0000 UTC
  State:           connected

$ govc vm.info jirib-test01
Name:           jirib-test01
  Path:         /ha-datacenter/vm/jirib-test01
  UUID:         564d5d7a-57dc-7a82-55f6-563e0421f161
  Guest name:   SUSE Linux Enterprise 15 (64-bit)
  Memory:       2048MB
  CPU:          2 vCPU(s)
  Power state:  poweredOn
  Boot time:    2024-08-22 13:24:40 +0000 UTC
  IP address:
  Host:         example.com
```

``` shell
$ govc vm.info -e external=true  /Datacenter/vm/jirib-test01 | grep -m1 -Po 'guestinfo.userdata:\s*\K(.*)' | base64 -d | zcat -
#cloud-config

users:
- default
- name: jiri
  primary_group: jiri
  sudo: ALL=(ALL) NOPASSWD:ALL
  groups: sudo, wheel
  lock_passwd: true
  ssh_authorized_keys:
  - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE1x+93H1K9QT62tvFbO3M8Ze5JvjtDB4QeslJJx60xi jiri
```


#### tools & Guest OS Customization

VMware Tools are _open-vm-tools_ now.

``` shell
$ rpm -q open-vm-tools
open-vm-tools-12.4.0-150600.1.3.x86_64
```

``` shell
$ grep -Pv '^\s*(#|$)' /etc/vmware-tools/tools.conf
[powerops]
[vmsvc]
[vmtools]
[vmtray]
[desktopevents]
[logging]
log=true
deployPkg.level = debug
vmtoolsd.level = debug
[guestinfo]
[unity]
```

VMware Tools might do
vSphere [Guest OS Customization](https://knowledge.broadcom.com/external/article/311864/how-does-vsphere-guest-os-customization.html)
(GOSC).

GOSC via VMware Tools might conflict with _cloud-init_; in case of
GOSC, _cloud-init_ should provide only _user data_. And if
_cloud-init_ takes too long, VMware Tools can have increased timeout:

``` shell
$ grep cloud /etc/vmware-tools/tools.conf.example
# This "wait-cloudinit-timeout" option controls how long does guest
# customization wait for cloud-init execution done when it detects cloud-init
# Guest customization will continue executing as soon as it detects cloud-init
# If cloud-init is still running beyond this option's value in seconds, guest
# customization will continue executing regardless cloud-init execution status.
#wait-cloudinit-timeout=30

$ vmware-toolbox-cmd config set deployPkg wait-cloudinit-timeout 60
$ vmware-toolbox-cmd config get deployPkg wait-cloudinit-timeout
[deployPkg] wait-cloudinit-timeout = 60
$ grep '^wait-cloudinit-timeout' /etc/vmware-tools/tools.conf
wait-cloudinit-timeout=60
```

Interaction with _cloud-init_ requires version >= 18.4, ideally >=
23.1 (would use 'Datasource VMware').

``` shell
$ rpm -q cloud-init
cloud-init-23.3-150100.8.79.2.x86_64
```

_cloud-init_ is able to use various datasources, eg. OVF of VMware;
see how it behaves when no VM _guestinfo_ is set:

``` shell
$ vmtoolsd --cmd "info-get guestinfo.userdata"
No value found

$ DEBUG_LEVEL=1 DI_LOG=stderr /usr/lib/cloud-init/ds-identify --force
[up 350482.07s] ds-identify --force
policy loaded: mode=search report=false found=all maybe=all notfound=disabled
no datasource_list found, using default: MAAS ConfigDrive NoCloud AltCloud Azure Bigstep CloudSigma CloudStack DigitalOcean Vultr AliYun Ec2 GCE OpenNebula OpenStack OVF SmartOS Scaleway Hetzner IBMCloud Oracle Exoscale RbxCloud UpCloud VMware LXD NWCS Akamai
DMI_PRODUCT_NAME=VMware20,1
DMI_SYS_VENDOR=VMware, Inc.
DMI_PRODUCT_SERIAL=VMware-42 03 d4 64 38 b9 fa d1-5c 91 80 20 ca 47 ca a5
DMI_PRODUCT_UUID=64d40342-b938-d1fa-5c91-8020ca47caa5
PID_1_PRODUCT_NAME=unavailable
DMI_CHASSIS_ASSET_TAG=No Asset Tag
DMI_BOARD_NAME=440BX Desktop Reference Platform
FS_LABELS=BOOTFS,EFIFS,EFIFS,EFI,EFI,ROOT
ISO9660_DEVS=
KERNEL_CMDLINE=BOOT_IMAGE=/boot/vmlinuz-6.4.0-150600.21-default root=UUID=5832c91b-2e72-477f-bd2f-99382788517a rw systemd.show_status=1 console=ttyS0,115200 console=tty0 quiet
VIRT=vmware
UNAME_KERNEL_NAME=Linux
UNAME_KERNEL_RELEASE=6.4.0-150600.21-default
UNAME_KERNEL_VERSION=#1 SMP PREEMPT_DYNAMIC Thu May 16 11:09:22 UTC 2024 (36c1e09)
UNAME_MACHINE=x86_64
UNAME_NODENAME=jbelka-test2
UNAME_OPERATING_SYSTEM=GNU/Linux
DSNAME=
DSLIST=MAAS ConfigDrive NoCloud AltCloud Azure Bigstep CloudSigma CloudStack DigitalOcean Vultr AliYun Ec2 GCE OpenNebula OpenStack OVF SmartOS Scaleway Hetzner IBMCloud Oracle Exoscale RbxCloud UpCloud VMware LXD NWCS Akamai
MODE=search
ON_FOUND=all
ON_MAYBE=all
ON_NOTFOUND=disabled
pid=11335 ppid=10717
is_container=false
is_ds_enabled(IBMCloud) = true.
ec2 platform is 'Unknown'.
is_ds_enabled(IBMCloud) = true.
Running on vmware but rpctool query returned 1: No value found
No ds found [mode=search, notfound=disabled]. Disabled cloud-init [1]
[up 350482.42s] returning 1
```

Now with _cloud-init_ user data:

``` shell
$ cat > userdata.yaml <<EOF
#cloud-config

users:
- default
- name: jiri
  primary_group: jiri
  sudo: ALL=(ALL) NOPASSWD:ALL
  groups: sudo, wheel
  lock_passwd: true
  ssh_authorized_keys:
  - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE1x+93H1K9QT62tvFbO3M8Ze5JvjtDB4QeslJJx60xi jiri
EOF

$ vmtoolsd --cmd "info-set guestinfo.userdata.encoding gzip+base64"
$ vmtoolsd --cmd "info-set guestinfo.userdata $(gzip -c9 < userdata.yaml | { base64 -w0 2>/dev/null || base64; })"

$ vmtoolsd --cmd "info-get guestinfo.userdata" | base64 -d | zcat -
#cloud-config

users:
- default
- name: jiri
  primary_group: jiri
  sudo: ALL=(ALL) NOPASSWD:ALL
  groups: sudo, wheel
  lock_passwd: true
  ssh_authorized_keys:
  - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE1x+93H1K9QT62tvFbO3M8Ze5JvjtDB4QeslJJx60xi jiri


$  DEBUG_LEVEL=1 DI_LOG=stderr /usr/lib/cloud-init/ds-identify --force
[up 350912.78s] ds-identify --force
policy loaded: mode=search report=false found=all maybe=all notfound=disabled
no datasource_list found, using default: MAAS ConfigDrive NoCloud AltCloud Azure Bigstep CloudSigma CloudStack DigitalOcean Vultr AliYun Ec2 GCE OpenNebula OpenStack OVF SmartOS Scaleway Hetzner IBMCloud Oracle Exoscale RbxCloud UpCloud VMware LXD NWCS Akamai
DMI_PRODUCT_NAME=VMware20,1
DMI_SYS_VENDOR=VMware, Inc.
DMI_PRODUCT_SERIAL=VMware-42 03 d4 64 38 b9 fa d1-5c 91 80 20 ca 47 ca a5
DMI_PRODUCT_UUID=64d40342-b938-d1fa-5c91-8020ca47caa5
PID_1_PRODUCT_NAME=unavailable
DMI_CHASSIS_ASSET_TAG=No Asset Tag
DMI_BOARD_NAME=440BX Desktop Reference Platform
FS_LABELS=BOOTFS,EFIFS,EFIFS,EFI,EFI,ROOT
ISO9660_DEVS=
KERNEL_CMDLINE=BOOT_IMAGE=/boot/vmlinuz-6.4.0-150600.21-default root=UUID=5832c91b-2e72-477f-bd2f-99382788517a rw systemd.show_status=1 console=ttyS0,115200 console=tty0 quiet
VIRT=vmware
UNAME_KERNEL_NAME=Linux
UNAME_KERNEL_RELEASE=6.4.0-150600.21-default
UNAME_KERNEL_VERSION=#1 SMP PREEMPT_DYNAMIC Thu May 16 11:09:22 UTC 2024 (36c1e09)
UNAME_MACHINE=x86_64
UNAME_NODENAME=jbelka-test2
UNAME_OPERATING_SYSTEM=GNU/Linux
DSNAME=
DSLIST=MAAS ConfigDrive NoCloud AltCloud Azure Bigstep CloudSigma CloudStack DigitalOcean Vultr AliYun Ec2 GCE OpenNebula OpenStack OVF SmartOS Scaleway Hetzner IBMCloud Oracle Exoscale RbxCloud UpCloud VMware LXD NWCS Akamai
MODE=search
ON_FOUND=all
ON_MAYBE=all
ON_NOTFOUND=disabled
pid=11381 ppid=10717
is_container=false
is_ds_enabled(IBMCloud) = true.
ec2 platform is 'Unknown'.
is_ds_enabled(IBMCloud) = true.
Running on vmware but rpctool query returned 1: No value found
check for 'VMware' returned found
Found single datasource: VMware
[up 350913.15s] returning 0
```

Voila! 'VMware' datasource found!

GOSC works based on 'VM Customization Specifications' policy/profile; the policy might be something like this:

``` xml
<ConfigRoot>
  <_type>vim.CustomizationSpecItem</_type>
  <info>
    <_type>vim.CustomizationSpecInfo</_type>
    <changeVersion>1725551416</changeVersion>
    <description>jbelka test</description>
    <lastUpdateTime>2024-09-05T15:50:16Z</lastUpdateTime>
    <name>jbelka-test</name>
    <type>Linux</type>
  </info>
  <spec>
    <_type>vim.vm.customization.Specification</_type>
    <globalIPSettings>
      <_type>vim.vm.customization.GlobalIPSettings</_type>
      <dnsServerList>
        <_length>1</_length>
        <_type>string[]</_type>
        <e id="0">1.1.1.1</e>
      </dnsServerList>
      <dnsSuffixList>
        <_length>1</_length>
        <_type>string[]</_type>
        <e id="0">example.com</e>
      </dnsSuffixList>
    </globalIPSettings>
    <identity>
      <_type>vim.vm.customization.LinuxPrep</_type>
      <domain>example.com</domain>
      <hostName>
        <_type>vim.vm.customization.UnknownNameGenerator</_type>
      </hostName>
      <hwClockUTC>true</hwClockUTC>
      <scriptText/>
      <timeZone>Europe/Prague</timeZone>
    </identity>
    <nicSettingMap>
      <_length>1</_length>
      <_type>vim.vm.customization.AdapterMapping[]</_type>
      <e id="0">
        <_type>vim.vm.customization.AdapterMapping</_type>
        <adapter>
          <_type>vim.vm.customization.IPSettings</_type>
          <ip>
            <_type>vim.vm.customization.UnknownIpGenerator</_type>
          </ip>
          <primaryWINS/>
          <secondaryWINS/>
        </adapter>
      </e>
    </nicSettingMap>
    <options>
      <_type>vim.vm.customization.LinuxOptions</_type>
    </options>
  </spec>
</ConfigRoot>
```

Then, when creating new VM from template, in 'Select clone options'
part of the 'New VM' wizard, there's 'Customize the operating system'
which would ask in 'User settings' dialog customization specification,
eg. 'Computer Name', IPv4 address' etc...

The final GOSC data with _cloud-init_ user data might be the following:

``` shell
$ govc vm.info -e external=true  /Datacenter/vm/jirib-test01 | grep -P '(deployPkg|guestinfo.userdata)' | fold -w80
    tools.deployPkg.fileName:      imcf-KCr7iB
    guestinfo.userdata:            H4sIAHJE4GYCAz2OzYrCQBCE73mKBi8ra2BjVtEBD9Eom
nWjoiB4CWOmNaOjE+ZHY57e0YXtQ9P9VVFUIxfSMj+X1wM/ep7VqDTxfGB4oFYYd13pBQmcuOIeQKn4h
apHdlTSlv9UWyYJRPP54MOtJqSLZbReb2PiPie/zZq8bS24F4jCUSHzc1ZSre+MgFEWX0G6yKg1hVS8R
pad8eHKAPgQuRmFaU1HgdjFsyDdjDsvNhsH1Wc/nAY//dWm2za3yX4R/vZ22EluJxMPv1eoRZJU3a+K/
7V9AqeO4QnxAAAA
    guestinfo.userdata.encoding:   gzip+base64
```

`tools.deployPkg.filename` is, in fact, a file on the datastore, in
the same directory where the VM data are located:

``` shell
$ govc datastore.ls jirib-test01/
jirib-test01.vmsd
jirib-test01-00a5fe75.hlog
imcf-KCr7iB
jirib-test01.vmx
jirib-test01.vmdk
jirib-test01-flat.vmdk

$ govc datastore.download jirib-test01/imcf-KCr7iB /tmp/imcf-KCr7iB
[10-09-24 10:31:56] Downloading... OK

$ 7z l /tmp/imcf-KCr7iB | sed -n '/Listing/,$p' | head -n 12
Listing archive: /tmp/imcf-KCr7iB

--
Path = /tmp/imcf-KCr7iB
Type = Cab
Offset = 512
Physical Size = 628197
Method = MSZip
Blocks = 1
Volumes = 1
Volume Index = 0
ID = 0

$ 7z e -so /tmp/imcf-KCr7iB cust.cfg
[NETWORK]
NETWORKING = yes
BOOTPROTO = dhcp
HOSTNAME = jirib-test01
DOMAINNAME = example.com

[NIC-CONFIG]
NICS = NIC1

[NIC1]
MACADDR = 00:50:56:83:ab:39
PRIMARY = yes
ONBOOT = yes
IPv4_MODE = BACKWARDS_COMPATIBLE
BOOTPROTO = static
IPADDR = 192.168.100.201
NETMASK = 255.255.255.0
GATEWAY = 192.168.100.1


[DNS]
DNSFROMDHCP=no
SUFFIX|1 = example.com
NAMESERVER|1 = 1.1.1.1

[DATETIME]
TIMEZONE = Europe/Prague
UTC = yes

[CUSTOM-SOURCE]
CUSTOMIZATION_SOURCE=vcenter-clone
```

...and `toolsDeployPkg.log` extracts are the following:

``` shell
$ grep -i command /var/log/vmware-imc/toolsDeployPkg.log
[2024-09-10T14:36:14.575Z] [    info] Original deployment command: '/usr/bin/perl -I/tmp/.vmware/linux/deploy/scripts /tmp/.vmware/linux/deploy/scripts/Customize.pl /tmp/.vmware/linux/deploy/cust.cfg'.
[2024-09-10T14:36:14.575Z] [    info] Actual deployment command: '/usr/bin/perl -I/var/run/.vmware-imgcust-dh0Ta7i/scripts /var/run/.vmware-imgcust-dh0Ta7i/scripts/Customize.pl /var/run/.vmware-imgcust-dh0Ta7i/cust.cfg'.
[2024-09-10T14:36:14.594Z] [   debug] Command to exec : '/usr/bin/cloud-init'.
[2024-09-10T14:36:16.198Z] [    info] Customization command output:
[2024-09-10T14:36:16.199Z] [   debug] Command to exec : '/usr/bin/perl'.
[2024-09-10T14:36:25.136Z] [    info] Customization command output:
2024-09-10T14:36:16 DEBUG: Command: 'cat /etc/issue'
2024-09-10T14:36:16 DEBUG: Command: 'cat /etc/issue'
2024-09-10T14:36:16 DEBUG: Command: 'perl --version'
2024-09-10T14:36:16 DEBUG: Command: 'hostname 2>/dev/null'
2024-09-10T14:36:16 DEBUG: TimedCommand: 'hostname -f 2>/dev/null' with timeout of 5 sec
2024-09-10T14:36:16 DEBUG: Command: '/bin/cat /etc/machine-id'
2024-09-10T14:36:16 DEBUG: Command: '/bin/rm -f /etc/machine-id'
2024-09-10T14:36:16 DEBUG: Command: 'dbus-uuidgen --ensure=/etc/machine-id'
2024-09-10T14:36:16 DEBUG: Command: '/bin/cat /etc/machine-id'
2024-09-10T14:36:16 DEBUG: Command: 'hostname jirib-test01'
2024-09-10T14:36:16 DEBUG: Command: 'chmod 644 /etc/HOSTNAME'
2024-09-10T14:36:16 DEBUG: Command: 'hostname jirib-test01'
2024-09-10T14:36:24 DEBUG: Command: 'modprobe pcnet32 2> /dev/null'
2024-09-10T14:36:24 DEBUG: Command: '/sbin/ifconfig eth0 2> /dev/null'
2024-09-10T14:36:24 DEBUG: Command: 'whereis ip'
2024-09-10T14:36:24 DEBUG: Command: '/usr/sbin/ip addr show 2>&1'
2024-09-10T14:36:24 DEBUG: Command: 'whereis ip'
2024-09-10T14:36:24 DEBUG: Command: '/usr/sbin/ip addr show 2>&1'
2024-09-10T14:36:24 DEBUG: Command: 'chmod 644 /etc/sysconfig/network/ifcfg-eth0'
2024-09-10T14:36:24 DEBUG: Command: 'chmod 644 /etc/hosts'
2024-09-10T14:36:24 DEBUG: Command: 'chmod 644 /etc/nsswitch.conf'
2024-09-10T14:36:24 DEBUG: Command: 'readlink -f "/etc/resolv.conf"'
2024-09-10T14:36:24 DEBUG: Command: 'chmod 644 /etc/sysconfig/network/config'
2024-09-10T14:36:24 DEBUG: Command: 'chmod 644 /etc/sysconfig/network/config'
2024-09-10T14:36:24 DEBUG: Command: 'chmod 644 /etc/sysconfig/network/config'
2024-09-10T14:36:24 DEBUG: Command: 'netconfig update -f'
2024-09-10T14:36:24 DEBUG: Command: 'chmod 644 /etc/sysconfig/network/dhcp'
2024-09-10T14:36:24 DEBUG: Command: 'ln -sf /usr/share/zoneinfo/Europe/Prague /etc/localtime'
2024-09-10T14:36:24 DEBUG: Command: 'chmod 644 /etc/sysconfig/clock'
2024-09-10T14:36:24 DEBUG: Command: 'whereis timedatectl'
2024-09-10T14:36:24 DEBUG: Command: '/usr/bin/timedatectl set-local-rtc 0 2>/tmp/guest.customization.stderr'
[2024-09-10T14:36:31.150Z] [   debug] Command to exec : '/bin/rm'.
[2024-09-10T14:36:31.254Z] [    info] Customization command output:
[2024-09-10T14:36:31.254Z] [   debug] Command to exec : '/usr/bin/cloud-init'.
[2024-09-10T14:36:32.157Z] [    info] Customization command output:
[2024-09-10T14:36:37.193Z] [   debug] Command to exec : '/usr/bin/cloud-init'.
[2024-09-10T14:36:38.321Z] [    info] Customization command output:
[2024-09-10T14:36:46.030Z] [   debug] Command to exec : '/usr/bin/cloud-init'.
[2024-09-10T14:36:47.768Z] [    info] Customization command output:
[2024-09-10T14:36:58.976Z] [   debug] Command to exec : '/usr/bin/cloud-init'.
[2024-09-10T14:37:00.706Z] [    info] Customization command output:
[2024-09-10T14:37:00.707Z] [   debug] Command to exec : '/bin/readlink'.
[2024-09-10T14:37:00.808Z] [    info] Customization command output:
[2024-09-10T14:37:00.808Z] [   debug] Command to exec : '/sbin/telinit'.
[2024-09-10T14:37:00.909Z] [    info] Customization command output:
[2024-09-10T14:37:01.909Z] [   debug] Command to exec : '/sbin/telinit'.
[2024-09-10T14:37:02.636Z] [    info] Customization command output:
[2024-09-10T14:37:02.636Z] [   error] Customization command failed with stderr: 'Failed to set wall message, ignoring: Refusing activation, D-Bus is shutting down.
```

KB articles & other sources of information:
- https://knowledge.broadcom.com/external/article/311864/how-does-vsphere-guest-os-customization.html
- https://knowledge.broadcom.com/external/article?legacyId=59557
- https://cloudinit.readthedocs.io/en/latest/reference/datasources/vmware.html


#### VCSA

JSON answer aka template file, only needed when deploying via the
installer to ESXi/vSphere:

``` json
{
  "__version": "2.13.0",
  "new_vcsa": {
    "esxi": {
      "hostname": "<ip>",
      "username": "root",
      "password": "********,
      "deployment_network": "VM Network",
      "datastore": "vcsa"
    },
    "appliance": {
      "thin_disk_mode": true,
      "deployment_option": "tiny",
      "name": "Embedded-vCenter-Server-Appliance"
    },
    "network": {
      "ip_family": "ipv4",
      "mode": "static",
      "system_name": "vcsa.example.com",
      "ip": "<ip>",
      "prefix": "<prefix>",
      "gateway": "<default_gw>",
      "dns_servers": [
        "<dns_ip>"
      ]
    },
    "os": {
      "password": "********,
      "ntp_servers": "<ip_or_host>",
      "ssh_enable": true
    },
    "sso": {
      "password": "********,
      "domain_name": "vsphere.local"
    }
  },
  "ceip": {
    "settings": {
      "ceip_enabled": false
    }
  }
}
```

VCSA ISO has OVA file:

``` shell
$ bsdtar xOf VMware-VCSA-all-8.*iso 'vcsa/VMware-vCenter-Server-Appliance-8.*.ova' | bsdtar tf -
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10.ovf
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10.mf
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10.cert
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10-file1.json
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10-file2.rpm
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10-disk1.vmdk
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10-disk2.vmdk
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10-disk3.vmdk
```

According to a blog, the appliance needs couple of additional disks
attached (they need to be attached if "extracting" the appliance
_outside_ of ESXi/vSphere (in "VMware" environment, the appliance
would create the disk itself during deployment via the installer):

``` shell
$ bsdtar xOf VMware-VCSA-all-8.*iso 'vcsa/VMware-vCenter-Server-Appliance-8.*.ova' | \
    bsdtar xOf - '*.json' | \
    jq -r '.tiny | to_entries[] | select(.key | startswith("disk")) | (.key | split("-"; null)[1]), .value' | \
    xargs -n2 | nl
     1  root 48GB
     2  swap 25GB
     3  core 25GB
     4  log 10GB
     5  db 10GB
     6  dblog 15GB
     7  seat 10GB
     8  netdump 1GB
     9  autodeploy 10GB
    10  imagebuilder 10GB
    11  updatemgr 100GB
    12  archive 50GB
    13  vtsdb 10GB
    14  vtsdblog 5GB
    15  lifecycle 100GB
    16  lvm_snapshot 150GB
```

Deployment from VCSA ISO:

``` shell
$ lin64/vcsa-deploy install --accept-eula --no-esx-ssl-verify --no-ssl-certificate-verification embedded_vCSA_on_ESXi.json
```

Importing VCSA into libvirt/KVM - I can't explain why but totally
there should be _17_ disks, even though there are 16 disks in the json
file !!! The following therefore works for me:

``` shell
# creating additional vcenter disks
$ bsdtar xOf /tmp/data/iso/VMware-VCSA-all-8*.iso 'vcsa/VMware-vCenter-Server-Appliance-8.*.ova' | \
    bsdtar -xOf - '*.json' | \
    jq -r '.tiny | to_entries[] | select(.key | startswith("disk")) | (.key | split("-"; null)[1]), .value' | \
    xargs -n2 | nl | \
    sed -n '3,$p' | while read number name size ; do \
        qemu-img create -f qcow2 vcenter-disk${number}.qcow2 ${size//GB/G} ; done

$ ls -1 vcenter-disk*.qcow2 | sort -V
vcenter-disk4.qcow2
vcenter-disk5.qcow2
vcenter-disk6.qcow2
vcenter-disk7.qcow2
vcenter-disk8.qcow2
vcenter-disk9.qcow2
vcenter-disk10.qcow2
vcenter-disk11.qcow2
vcenter-disk12.qcow2
vcenter-disk13.qcow2
vcenter-disk14.qcow2
vcenter-disk15.qcow2
vcenter-disk16.qcow2

# extracting vmdk from the ova
$ bsdtar xOf /tmp/data/iso/VMware-VCSA-all-8*.iso 'vcsa/VMware-vCenter-Server-Appliance-8.*.ova' | \
    bsdtar -xf - 'VMware-vCenter-Server-Appliance-8*.vmdk'

$ ls -1 *.vmdk
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10-disk1.vmdk
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10-disk2.vmdk
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10-disk3.vmdk

# converting vmdk to qcow2
$ (i=1; while read line; do \
    qemu-img convert -f vmdk -O qcow2 $line vcenter-disk${i}.qcow2; ((i++)); \
    done) < <(ls -1 *.vmdk)

$ ls -1 vcenter-disk[1-3].qcow2
vcenter-disk1.qcow2
vcenter-disk2.qcow2
vcenter-disk3.qcow2

$ while read name size; do \
    qemu-img resize vcenter-${name}.qcow2 $((size * 1024 * 1024)) ; \
    done << EOF
disk1  49728
disk2  7040
disk3  25600
disk4  25600
disk5  10240
disk6  10240
disk7  15360
disk8  10240
disk9  1024
disk10  10240
disk11  10240
disk12  102400
disk13  51200
disk14  10240
disk15  5120
disk16  102400
disk17  153600
EOF

# 'tiny' profile CPU and memory settings
# inside vcenter appliance there's `/usr/sbin/verify_disk_size.py` which does some internal
# check and based on CPU and memory it requires a specific storage configuration

$ bsdtar xOf /tmp/data/iso/VMware-VCSA-all-8*.iso 'vcsa/VMware-vCenter-Server-Appliance-8.*.ova' | \
    bsdtar -xOf - '*.json' | \
    jq '.tiny | to_entries[] | select((.key == "cpu") or .key == "memory") | (.key, .value)' | xargs -n2
cpu 2
memory 14336

$ virt-install \
    --name vcenter \
    --memory 14336 \
    --vcpus 2 \
    --cpu host-passthrough,check=none,migratable=on \
    $(printf -- ' --disk /var/lib/libvirt/images/vsphere/vcenter-disk%d.qcow2,bus=sata' $(seq 1 17)) \
    --os-variant linux2022 \
    --network model=e1000e,network=vsphere \
    --wait 0 \
    --import
```

Then, open the VM console, change root password (you can also enable shell and SSH); login via HTTPS on 5480 port,
and follow the wizard.

vCenter appliance console UI is idiotic, however networking (do it
before configuring vCenter via web UI!) can be done via
`/opt/vmware/share/vami/vami_config_net`.
