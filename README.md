# My cheatsheet

## ACL

- *mask* is maximum permission for users (other than the owner) and groups!
- `chmod` incluences mask of ACL file/dir!
- default ACL of a directory for inheritance

## kernel

``` shell
echo "blacklist pcspkr" > /etc/modprobe.d/bell.conf # blacklist a module
rmmod pcspkr
```

``` shell
grep -H '' /sys/module/iwlwifi/parameters/* # a module parameters
/sys/module/iwlwifi/parameters/11n_disable:0
/sys/module/iwlwifi/parameters/amsdu_size:0
/sys/module/iwlwifi/parameters/bt_coex_active:Y
/sys/module/iwlwifi/parameters/debug:0
/sys/module/iwlwifi/parameters/disable_11ac:N
/sys/module/iwlwifi/parameters/disable_11ax:N
/sys/module/iwlwifi/parameters/enable_ini:Y
/sys/module/iwlwifi/parameters/fw_restart:Y
/sys/module/iwlwifi/parameters/led_mode:0
/sys/module/iwlwifi/parameters/nvm_file:(null)
/sys/module/iwlwifi/parameters/power_level:0
/sys/module/iwlwifi/parameters/power_save:N
/sys/module/iwlwifi/parameters/remove_when_gone:N
/sys/module/iwlwifi/parameters/swcrypto:0
/sys/module/iwlwifi/parameters/uapsd_disable:3

systool -vm iwlwifi | awk '/^\s*Parameters:/{p=1}/^ *$/{p=0}p' # a module params
  Parameters:
    11n_disable         = "0"
    amsdu_size          = "0"
    bt_coex_active      = "Y"
    debug               = "0"
    disable_11ac        = "N"
    disable_11ax        = "N"
    enable_ini          = "Y"
    fw_restart          = "Y"
    led_mode            = "0"
    nvm_file            = "(null)"
    power_level         = "0"
    power_save          = "N"
    remove_when_gone    = "N"
    swcrypto            = "0"
    uapsd_disable       = "3"
```

### dracut

``` shell
lsinitrd [<initrd_file>] # list initrd content
lsinitrd -f <file> [<initrd_file>] # display content of a file in initrd
```

``` shell
man dracut.conf
```

`omit_dracutmodules+=" <dracut module> "` to omit a module, see
`/usr/lib/dracut/modules.d`.

### /proc

https://www.kernel.org/doc/html/latest/admin-guide/sysrq.html


## virtualization

### qemu

``` shell
qemu-nbd --connect=/dev/nbd0 <qemu_image> # connect eg. a qcow2 image
qemu-nbd -d /dev/nbd0
```

## rpm

``` shell
rpm -K --nosignature <rpm_file>
<rpm_file>: digests OK
rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig} %{SIGGPG:pgpsig}\n' -p <rpm_file>
key=$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig} %{SIGGPG:pgpsig}\n' -p <rpm_file> \
    | awk '{ print $(NF-1) }' | rev | cut -c1-8 | rev)
rpm -qa gpg-pubkey* | grep $key
```

## storage

*GPT* - GRUB booting from GPT requires *BIOS boot partition* (ef02) on
BIOS systems or *EFI system partition* (ef00) on EFI systems.

``` shell
cat /sys/block/<dev>/queue/hw_sector_size
cat /sys/block/<dev>/{queue/{scheduler,add_random,rq_affinity},device/timeout} # some tunning values
```
### udev

``` shell
udevadm info -q property -n <dev> # info about a device
```

### iscsi

- *initiator*, an originating end of SCSI connection (eg. iSCSI client)
- *iqn*, iSCSI qualified name
- *target*, a receiving end of SCSI connection (eg. iSCSI server)
- *portal*, (network) portal, combination of SCSI endpoint with IP and
  TCP port (on a target)
- *tpg*, target port group, combination of IP and TCP port of a target
- *CHAP*, protocol used to negotiate authentication (does not send
  plain-text secret!)

#### initiator

``` shell
lsmod | grep iscsi
```

##### discovery

``` shell
# libiscsi-utils
iscsi-ls iscsi://<ip>[:port]             # discover targets
iscsi-ls --show-luns iscsi://<ip>[:port]
```

``` shell
# open-iscsi
iscsiadm -m discovery -p <ip>[:port] -t [sendtargets|st] # discovery

```

##### node

operations related to node (initiator)

``` shell
iscsiadm -m node -T <target> [-p <ip>[:port]] -o new # add new record to node db,
                                                     # ie. if not already known by discovery
iscsiadm -m node -l [-T <target>]                    # login to all or specific node entry
```

``` shell
iscsiadm -m node # node records
> <ip:port>,<tpg_number> <iqn>

iscsiadm -m node -T <target> # details about a node record
iscsiadm -m node -T <target> -n node.startup -v automatic -o update # auto-enable iscsi lun
```

``` shell
iscsiadm -m node -u [-T <target>] # logout from all or specific node entry
iscsiadm -m node -T <target> -o delete # remote an entry from node db
```

##### session

``` shell
iscsiadm -m session [-P 3] # list initiator session
udevadm info -q property -n /dev/<scsi_lun>
```

#### target



### multipath

``` shell
multipath -ll
3600d023100049aaa714c80f5169c0158 dm-0 IFT,DS 1000 Series
size=1000G features='2 queue_if_no_path retain_attached_hw_handler' hwhandler='1 alua' wp=rw
`-+- policy='service-time 0' prio=50 status=active
  |- 1:0:0:0 sda 8:0  active ready running
  `- 1:0:3:0 sdb 8:16 active ready running

```

explanation for above lines:

- `3600d023100049aaa714c80f5169c0158 dm-0 IFT,DS 1000 Series`
  `wwwid sysfs-name vendor,product`
- `size=1000G features='2 queue_if_no_path retain_attached_hw_handler' hwhandler='1 alua' wp=rw`
  `size=<value> features='<number> <values comma separated>' hwhandler='0|1 <value> wp=<value of write permissions if know>`

- *hardware handler* - is a kernel module that performs
  hardware-specific actions when switching path groups and dealing
  with I/O errors; `1|0 driver`
  *alua* - defines a standard set of SCSI commands for discovering path priorities to LUNs on SANs
  ``` shell
  udevadm info -q property -n <dev> | grep TPG
  sg_rtpg -vvd <dev> 2>/dev/null | grep 'asymmetric access state'
  ```

https://www.learnitguide.net/2016/06/understand-multipath-command-output.html

multipath issue in logs

```
May 24 18:22:24 t14s kernel: sd 0:0:0:1: alua: port group 00 state A non-preferred supports TOlUSNA
May 24 18:25:41 t14s kernel:  connection7:0: ping timeout of 5 secs expired, recv timeout 5, last rx 4495125049, last ping 4495126336, now 4495127616
May 24 18:25:41 t14s kernel:  connection7:0: detected conn error (1022)
May 24 18:25:41 t14s kernel: sd 1:0:0:1: [sdb] tag#4 FAILED Result: hostbyte=DID_TRANSPORT_DISRUPTED driverbyte=DRIVER_OK cmd_age=7s
May 24 18:25:41 t14s kernel: sd 1:0:0:1: [sdb] tag#4 CDB: Test Unit Ready 00 00 00 00 00 00
...
May 24 18:25:46 t14s multipathd[21267]: 36001405fbcc04a11155470eac0f2ff53: sdb - tur checker reports path is down
May 24 18:25:46 t14s multipathd[21267]: checker failed path 8:16 in map 36001405fbcc04a11155470eac0f2ff53
May 24 18:25:46 t14s multipathd[21267]: 36001405fbcc04a11155470eac0f2ff53: remaining active paths: 1
May 24 18:25:46 t14s kernel:  session7: session recovery timed out after 5 secs
May 24 18:25:46 t14s kernel: sd 1:0:0:1: rejecting I/O to offline device
May 24 18:25:46 t14s kernel: device-mapper: multipath: 254:9: Failing path 8:16.

```

### health

`smartctl -a <device>`

### lvm

``` shell
pvs -o +pv_used                               # show spage used in PVs
pvmove /dev/<pv>                              # moving data from PV to other PV
pvmove -n </dev/<vg>/<lv> /dev/<pv> /dev/<pv> # moving extents of to other PV
vgreduce <vg> <unused_pv>                     # removing a PV from VG
pvremove <unused_pv>
pvs -o help # list of options
```

## filesystems

### btrfs

``` shell
btrfs subvolume list -p <path> # list subvolumes
btrfs subvolume delete -i <subvol_id> <path> # remove subvolume

btrfs device usage <path>    # underlying block device and usage info

btrfs filesystem show <path> # usage info
btrfs filesystem balance start

btrfs-convert [-l <label>] <block_device> # convert eg. ext4 into btrfs
btrfs-convert -r <block_device>           # rollback, files in btrfs will be lost!

systemctl list-units -t timer --no-legend btrfs\* # list btrfs maintenance units
egrep -v '^(\s*#|$)' /etc/sysconfig/btrfsmaintenance # SUSE btrfs maintenance conf
```

``` shell
mount -o subvol=[<subvol_name> | <subvol_id>] <storage_dev> /<path>
```

#### disable copy-on-write (cow)

> A subvolume may contain files that constantly change, such as
> virtualized disk images, database files, or log files. If so,
> consider disabling the copy-on-write feature for this volume, to
> avoid duplication of disk blocks.

``` shell
grep '\bbtrfs\b.*nodatacow' /etc/fstab # check if cow disabled in /etc/fstab
lsattr -d /var                         # check if cow disabled via attributes
```

### nfs

On SUSE `/usr/sbin/rpc.nfsd` reads `/etc/nfs.conf` which loads
`/etc/sysconfig/nfs`.

``` shell
# usually nfsv3 commands
rpcbind -p   # list registered services in rpcbind
showmount -e # list remote exports
```

``` shell
exportfs -s # see exports
```

Firewalling NFS needs special handling (mostly because many daemons/ports for NFSv3).

``` shell
# SUSE
egrep -v '^(\s*#| *$)' /etc/sysconfig/nfs | egrep '_(TCP|UDP)*PORT'
MOUNTD_PORT="20048"
STATD_PORT="33081"
LOCKD_TCPPORT="38287"
LOCKD_UDPPORT="36508"
```

#### nfsv4

- *NFSv4* does NOT require `rpcbind`, no longer requirement of separate
  TCP callback connection (ie. server does not need to contact the
  client directly by itself); mounting and locking protocols are part
  of NFSv4
- in-kernel *nfsd* listening on 2049/{tcp,udp}

info about NFSv4-only setup https://www.suse.com/support/kb/doc/?id=000019530

#### nfsv3

- *NFSv3* does require `rpcbind` (previously `portmapper`) and has
  couple of separate processes (rpc.mountd, prpc.statd), in-kernel
  *lockd* thread (nlockmgr) which require special firewall handling
- *autofs* requires NFSv3 daemons for operation

`rpc.mountd` registers every successful mount request of clients into
`/var/lib/nfs/rmtab`. If a client doesn't unmount a NFS filesystem
before shutting down, there would be salve inforation in `rmtab`.

when a NFS server shuts down/reboots, `rpc.mountd` consults `rmtab`
and notifies clients that the server is to be
shutdown/rebooted. out-of-date `rmtab` does not cause shutdown to
hang.


#### troubleshooting

``` shell
grep -RH '' /proc/fs/nfsd/ 2>/dev/null
```

#### snapper

automatically triggered btrfs snapshots

``` shell
snapper list
```

## systemd

### commands

``` shell
systemctl get-default # default target, similar to runlevel
systemctl set-default <target> # set default target
systemctl --failed # as --state=failed
systemctl list-units --type=service --state=running
systemctl daemon-reload # after configuration change
systemctl mask <unit> # prevents unit start, even manually or as dep
systemctl cat <unit> # shows unit files content as they are on the disk
systemctl status <unit>

systemctl --no-legend list-unit-files | \
    awk '$2 == "enabled" { print $1 }' | sort # list enabled units
```

### unit files location

* `/usr/local/lib/systemd/system` for system units installed by the
  administrator, outside of the distribution package manager
* `/etc/systemd/system` system units *created* by the administrator

### override units via drop-in files

`/etc/systemd/system/<unit>.d/override.conf` or via `systemctl edit <unit>`

For unit types **different** than *oneshot* `ExecStart` must be cleared.

``` shell
systemctl show -p Type sshd
Type=notify

cat > /etc/systemd/system/sshd.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=/usr/sbin/sshd -p 2222 -p 22 -D $SSHD_OPTS
EOF

systemctl daemon-reload
systemctl restart sshd
```

### rescue, repair

* single-user like mode

`systemd.unit=rescue.target` as kernel boot param

* emergency

`systemd.unit=emergency.target` as kernel boot param

Other tips:

* `systemd.mask=swap.target`         # on SUSE
* `system.device_wants_unit=off`     # on SUSE
* `system.mask=dev-system-swap.swap` # on SUSE
* `systemctl list-units --type=swap`
* `systemd-escape -p --suffix=swap /dev/system/swap # returns 'dev-system-swap.swap'

## journald

``` shell
journalctl -k # kernel messages
journalctl -u sshd
journalctl _SYSTEMD_UNIT=sshd
journalctl /usr/lib/postfix/bin/cleanup # specific binary
journalctl --list-boots #
journalctl -b # messages since current boot

journalctl --since now -f # `tail -f` journald alternative
journalctl --since <start_time> --until <end_time> # xxxx-xx-xx yy:yy:yy

journalctl _SYSTEMD_UNIT=sshd + _UID=1000

journalctl -o verbose -u sshd # details about message
```

## mdraid

``` shell
readlink -f /dev/md/* # all mdraid device names
mdadm -D /dev/<mddev> # details
cat /proc/mdstat      # basic details
mdadm --examine <physical_device>

echo check > /sys/block/<mddev>/md/sync_action # trigger resync

mdadm /dev/<mddev> --fail <realdev> # make realdev failed to be removed later
mdadm /dev/<mddev> --remove <realdev> # remove realdev from mdraid

mdadm --stop /dev/<mddev>                 # stop array
mdadm --zero-superblock <physical_device> # remove metadata
```

``` shell
# creating a mirror with only one disk (eg. for a migration)
mdadm --create /dev/mv/<name> --level=mirror --raid-devices=2 <realdev> missing # name will be symlink
echo 'CREATE names=yes' > /etc/mdadm.conf # careful!
madadm --detail --scan >> /etc/mdadm.conf

mdadm /dev/md/<name> --add <real_dev> # add disk to array
watch -n 1 cat /proc/mdstat # watch recovery
```

``` shell
mdadm --monitor -d 1800 -m root@localhost --scan -c /etc/mdadm.conf # manually starting monitor
```

but on various distros *udev* would call `mdmonitor.service` when
putting an array online

``` shell
grep -Rh mdmonitor.service /usr/lib/udev/rules.d # udev starting monitoring of array
ENV{MD_LEVEL}=="raid[1-9]*", ENV{SYSTEMD_WANTS}+="mdmonitor.service"
```

*MDADM_MAIL* variable in `/etc/sysconfig/mdadm` and activation of
`mdmonitor.service` unit to get mail notifications (on SLES).

## SUSE

### support

- latest *SP* (service pack), 6 monts to update to latest SP after it
  has been released
- latest updates in older SP if *LTTS* (long term technical support),
  LTTS adds 3 years period of support of an old SP end of general
  support date
- *Extended Service Pack Support* (ESPOS), LTTS-kind 3.5 yr support
  bounded to a specific product release (eg. SLES for SAP 12 SP5
- *LV1*, problem determination, troubleshooting based on documentation
- *LV2*, problem isolation, analysis, reproduction
- *LV3*, problem resolution, engineering engagement, resolution of
  defects reported by LV2
- *PTF*, Program Temporary Fixes

### installation

*linuxrc* is *init* instead of *systemd*

### registration

``` shell
SUSEConnect -r <activation_key> -e <email>
```

### packages via zypper

#### repos

``` shell
zypper lr # list repos
zypper lr -d <repo> # details about a repo
zypper mr -e <repo>
zypper mr -e --all # enable all repos
```

#### patterns

``` shell
zypper pt
zypper in -t pattern <pattern_name>

```

``` shell
zypper search --provides --type package -x view
```

#### packages

``` shell
zypper rm -u <package> # removes package and all deps
zypper se --provides -x /usr/bin/gnat # search package owning path
```

#### patches

``` shell
zypper lp
zypper pchk
```

### networking

``` shell
echo 'default <ip> - -' > /etc/sysconfig/network/routes
cat > /etc/sysconfig/network/ifcfg-eth0 <<EOF
IPADDR='<ip/mask>'
BOOTPROTO='static'
STARTMODE='auto'
EOF
```

## firewall

### iptables

#### iptables replace rule

```
# iptables --line-numbers -nL FORWARD 33
33   ACCEPT     all  --  10.64.0.0/10         10.64.0.252
# iptables -R FORWARD 33 -s 10.64.0/15 -d 10.64.0.252 -j ACCEPT
```

### firewalld

``` shell
firewall-cmd --state
firewall-cmd --get-active-zones
firewall-cmd --get-default-zone
```

``` shell
firewall-cmd --reload # reload from permanent configuration

```

## backup

### borg

``` shell
borg -V        # on remote machine
mkdir ~/backup # on remote machine
```
``` shell
borg -V

BORG_REPO="ssh://backup.home.arpa/./backup"
BORG_RSH="ssh -o BatchMode=yes -o Compression=no"
BORG_RSH+=" -o Ciphers=aes128-ctr -o MACs=umac-64-etm@openssh.com" # better use ssh_config
export BORG_REPO BORG_RSH

borg init
borg info

cat > ${HOME}/.config/borg/home_patternfile <<EOF
exclude_dir
EOF

borg create -stats \
    --list \
    --info \
    --progress \
    --show-rc \
    --patterns-from ${HOME}/.config/borg/home_patternfile \
    --exclude-caches \
    "::home-{now:%Y%m%d%H%M%SZ}" \
    /home

borg list --last 1
borg info ::$(borg list --last 1 | awk '{ print $1 }')
```

``` shell
borg list ::$(borg list --last 1 | awk '{ print $1 }') <path>
borg extract --strip-components <digit> ::$(borg list --last 1 | awk '{ print $1 }') <path>
```

## development

### git

#### SSH

If one uses different SSH keys for various projects (which are hosted
on same remote host and use same remote username,
ie. `$HOME/.ssh/config` setting won't work), one could use
`GIT_SSH_COMMAND` environment variable.

This is especially useful for initial `git clone`.

``` shell
GIT_SSH_COMMAND="ssh -i <keyfile>" git clone <user>@<server>:project/repo.github
grep ssh .git/confg                           # no SSH settings configured
git config core.sshCommand "ssh -i <keyfile>" # set SSH settings per repo
```

#### submodules

``` shell
git clone <repo_url>
# after initial cloning, repo does not have submodules
grep path .gitmodules ; [[ -z $(ls -A <submodule_path) ]] && \
    echo empty || echo exists
        path = <submodule_path>
empty
git submodule init
git submodule update
[[ -z $(ls -A <submodule_path>) ]] && echo empty || echo exists
exists
```

## graphics

### ghostscript

``` shell
ps2pdf -dPDFSETTINGS=/ebook <orig_pdf> <new_pdf> # shrink size of a pdf
```
z
### ImageMagick

convert a specific page of a PDF into eg. PNG

``` shell
convert 'file.pdf[0]' \
    -density 600 \
    -background white \
    -alpha remove \
    -resize 100% \
    -compress zip +adjoin
    /tmp/file.png
```

ImageMagick policy blocking action with PDF files.

``` shell
convert: attempt to perform an operation not allowed by the security policy `PDF' @ error/constitute.c/IsCoderAuthoriz
ed/422.
```

Update `polixy.xml`.

``` shell
xmllint --xpath '/policymap/policy[@pattern="PDF"]' /etc/ImageMagick-7/policy.xml
<policy xmlns="" domain="coder" rights="read | write" pattern="PDF"/>
```

## clusters

### pacemaker/corosync

#### terminology

- *RTO* - recovery time objective, target time to recover normal
  activities after a failure
- *RPO* - recovery point objective, amount of data that can be lost
- *node* - member of a cluster
- *ccm* - consensus cluster membership, determination of cluster members
  and sharing this information
- *quorum* - majority (eg. 50% + 1) defines a cluster partition has
  quorum (is "quorate")
- *epoch* - version of cluste metadata
- *split brain* - competing cluster "groups" that do not know about each
  other
- *fencing* - prevention of access to shared resource, eg. via STONITH

- *resources*, anything managed by cluster (eg. IP, service,
  filesystems...), defined in CIB, use RA scripts, active/passive or
  active/active

- *primitive resource* - single instance on one node
- *group resource* - group of one or more privitive resources as a
  single entity, managed as whole, order is important!
- *clone resource* - resources running simultaneously on multiple nodes at the same time
  - *anonymous clone* - exactly the same primitive runs on each node
  - *globally unique clone* - distinct primitives run on each node, unique identity (eg. unique IP)
- *multi-state resource* - special clone resource, active or passive,
  promote/demote for active/passive


#### architecture

- *corosync* - messaging and membership layer (can replicate data across cluster?)
- *pacemaker* - cluster resource manager, CRM, part of resource allocation layer, `crmd` is main process
- *CIB* - cluster information base, configuration, current status,
  pacemaker, part of resource allocation layer; shared copy of state, versioned
- *DC* - designated coordinator, member managing the master copy of
  the *CIB*, so-called master node, communicate changes of the CIB
  copy to other nodes via CRM
- *PE* - policy engine, running on DC, the brain of the cluster,
  monitors CIB and calculates changes required to align with desired
  state, informs CRM
- *LRM* - local resource manager, instructed from CRM what to do
- *RA* - resource agent, logic to start/stop/monitor a resource,
  called from LRM and return values are passed to the CRM, ideally
  OCF, LSB, systemd service units or STONITH
- *OCF* - open cluster framework, standardized resource agents
- *STONITH* - "shoot the other node in the head", fencing resource
  agent, eg. via IPMI…
- *DLM* - distributed lock manager, cluster wide locking (`ocf:pacemaker:controld`)
- *CLVM* - cluster logical volume manager, `lvmlockd`, protects LVM
  metadata on shared storage

#### management

by default *root* and *haclient* group members can manage cluster

``` shell
crm_mon # general overview, part of pacemaker
crm_mon [-n | --group-by-node ]
crm_mon -nforA # incl. fail, counts, operations...
cibadmin [-Q | --query] # expert xml administration, part of pacemaker
```

``` shell
crm
crm status # similar to *crm_mon*, part of crmsh

crm resource # interactive shell for resources
crm configure [edit] # configuration edit via editor
                     # do not forget commit changes!
crm move     # careful, creates constraints
crm resource constraints <resource> # show resource constraints
```

``` shell
crm cluster property maintenance-mode=true # global cluster property, no modulesonitoring
```

``` shell
corosync-cfgtool -R # tell all nodes to reload corosync config
```

and web-based hawk (suse) *7630/tcp*

##### order constraints

```
crm configure edit

< order <id> Mandatory: <resource>:<status> <resource>:<action>

# an example

crm configure edit

< order o-mariadb_before_webserver Mandatory: g-mariadb:start g-webserver:start
```

##### location constraints

```
crm configure edit

< location <id> <resource> <infinity>: [<node> | <resource>:<state>]

# an example

crm configure edit

< location l-mariadb_pref_node1 g-mariadb 100: node1

# an example of never collocate

crm configure edit

< location l-mariadb_never_with_webserver -inf: g-mariadb:Started g-webserver:Started
```

##### acls

- same users and userids on all nodes
- users must be in *haclient* user group
- users need to have rights to run `/usr/bin/crm`

##### troubleshooting

logs must be gathered from all nodes

``` shell
hb_report -f <start_time> <filename> # tarball with information,
                                     # run on each node separately!
hb_report -f $(date --rfc-3339=date) # ./YYYY-MM-DD.tar.bz2
```

``` shell
crm cluster health | tee output
```

resource action failure increases *failcount* on a node

``` shell
crm resource failcount <resource> show <node>

crm resource failcount <resource> delete <node> # reset
crm resource cleanup <resource> <node>          # same stuff
```

``` shell
crm_simulate -x <pe_file> -S # what was going on during life of cluster
```

simulating a cluster network failure via iptables:
https://www.suse.com/support/kb/doc/?id=000018699

##### backup

``` shell
crm configure show > <backup_file> # remove node specific stuff

# something like this
crm configure show | \
  perl -pe 's/\\\n/ /' | \
  perl -ne 'print unless m/^property cib-bootstrap-options:/' | \
  perl -pe 's/ {2,}/ \\\n    /g'

cibadmin -E --force # remove cluster configuration
crm configure < <backup_file>
```

#### resource agents

``` shell
crm ra classes # list RA classes
```

hack to print ocf-based RA required paramenters and other stuff

```
/usr/lib/ocf/resource.d/linbit/drbd meta-data | \
  xmllint --xpath '//*/parameter[@required="1"]' -
<parameter name="drbd_resource" unique="1" required="1">
<longdesc lang="en">
The name of the drbd resource from the drbd.conf file.
</longdesc>
<shortdesc lang="en">drbd resource name</shortdesc>
<content type="string"/>
</parameter>

/usr/lib/ocf/resource.d/linbit/drbd meta-data | \
  xmllint --xpath '//*/actions/action[@name="monitor"]' -
<action name="monitor" timeout="20" interval="20" role="Slave"/>
<action name="monitor" timeout="20" interval="10" role="Master"/>
```

``` shell
crm resource [trace | untrace] <resource>
```

tracing logs in `/var/lib/heartbeat/trace_ra` (SUSE), filenames as
`<resource>.<action>.<date>`.

#### fencing

``` shell
crm node fence <node>
```

``` shell
stonith_admin -L
```

##### sbd

*SBD* - storage based death aka STONITH block device

*SBD_STARTMODE=clean* in `/etc/sysconfig/sdb` (SUSE) to prevent
starting cluster if non-clean state exists on SBD

``` shell
sbd -d <block_dev> message <node> test # testing communication
sbd -d <block_dev> list                # query

> <ide> <node> <message> <source of message>

sbd -d <block_dev> message <node> clear # clear sbd state for a node, restart pacemaker!
```

### csync2

file syncronization, `/etc/csync2/csync2.cfg`, *30865/tcp*, key-based authentication

``` shell
systemctl cat csync2.socket # at suse
[Socket]
ListenStream=30865
Accept=yes

[Install]
WantedBy=sockets.target
```

``` shell
csync2 -xv
```

### drbd

*distributed block device*, ie. replicated local block device over
network, by default *7789/tcp* and above (till *7799/tcp*) is used.

configs `/etc/drbd.{conf,d/}`

``` shell
drbdadm [create | up | status] <resource>
drbdadm new-current-uuid --clear-bitmap <resource>/0
```

#### drbd in cluster

RA is in *drbd-utils* package on SUSE

```
primitive p-drbd_<resource> ocf:linbit:drbd \
  params drbd_resource=<drbd_resource> \
  op monitor interval=15 role=Master \
  op monitor interval=30 role=Slave

ms ms-drbd_<resource> \
  meta master-max=1 \
    master-node-max=1 \
    clone-max=2 \
    clone-node-max=1 \
    notify=true
```

…but that is, of course, just the basic of whole cluster setup.

## GRUB

`/etc/default/grub_installdevice` is used in various distros (SLES) by
tools to install GRUB on boot disk.

``` shell
grub2-install -v <boot_device>
```

### commands

``` shell
set # list all set variables
lsmod
insmod <module>

```

## coreboot

https://doc.coreboot.org/tutorial/part1.html

``` shell
git clone <repo>
make help_toolchain
make crossgcc-<arch> # wait for looong time
make -C payloads/coreinfo olddefconfig
make -C payloads/coreinfo
make menuconfig    # increase ROM size if needed
make savedefconfig
make
```

## gtk

### file-chrooser

``` shell
dconf write /org/gtk/settings/file-chooser/sort-directories-first true # dirs first
cat  ~/.config/gtk-3.0/bookmarks # output: file://<absolute_path> <label>
```

## networking

### http(s) proxy

``` shell
pip install --user proxy.py
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
proxy --hostname 127.0.0.1 --port 8080 --key-file key.pem --cert-file cert.pem --log-level DEBUG
```

``` shell
curl --proxy-insecure --proxy https://127.0.0.1:8080 http://api.ipify.org
*   Trying 127.0.0.1:8080...
* Connected to 127.0.0.1 (127.0.0.1) port 8080 (#0)
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* Proxy certificate:
*  subject: C=AU; ST=Some-State; O=Internet Widgits Pty Ltd
*  start date: May 25 10:00:18 2021 GMT
*  expire date: May 25 10:00:18 2022 GMT
*  issuer: C=AU; ST=Some-State; O=Internet Widgits Pty Ltd
*  SSL certificate verify result: self signed certificate (18), continuing anyway.
> GET http://api.ipify.org/ HTTP/1.1
...
```

## desktop

### pulseaudio

``` shell
pactl list sinks | egrep '(^(Sink)|\s+(State|Name|Description|Driver):)'
Sink #0
        State: RUNNING
        Name: alsa_output.usb-Lenovo_ThinkPad_USB-C_Dock_Gen2_USB_Audio_000000000000-00.analog-stereo
        Description: ThinkPad USB-C Dock Gen2 USB Audio Analog Stereo
        Driver: module-alsa-card.c
Sink #1
        State: SUSPENDED
        Name: alsa_output.usb-Logitech_Logitech_Wireless_Headset_4473D65FB53E-00.analog-stereo
        Description: H600 [Wireless Headset] Analog Stereo
        Driver: module-alsa-card.c
Sink #2
        State: SUSPENDED
        Name: alsa_output.pci-0000_06_00.6.HiFi__hw_Generic_1__sink
        Description: Family 17h (Models 10h-1fh) HD Audio Controller Speaker + Headphones
        Driver: module-alsa-card.c
```

### systemd stuff

``` shell
mkdir /etc/systemd/logind.conf.d
echo 'HandleLidSwitch=ignore' >> \
  /etc/systemd/logind.conf.d/lid.conf
systemctl restart systemd-logind # does not work on SUSE
```

### default apps

``` shell
xdg-mime query filetype <file>     # returns mime type
xdg-mime query default <mime_type> # returns desktop file
```

## printing

### cups

``` shell
lpstat -p -d              # list printers and default one
lpoptions -d <printer>    # set default printer
lpoptions -l -p <printer> # list printer options

lpstat -l -e | grep <printer> # show connection to a printer

lp [-d <printer>] <file>   # print a file
lpr [-P <printer>] <file>  # print a file

grep 'Printer' /sys/bus/usb/devices/*/* 2>/dev/null # list usb printers
udevadm info -p <sysfs_path>                        # show properties of usb device
grep -rH '' /sys/bus/usb/devices/*/ieee1284_id 2>/dev/null # IEEE 1284 info
```
See http://www.undocprint.org/formats/communication_protocols/ieee_1284
See https://www.cups.org/doc/options.html
