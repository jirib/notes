# My cheatsheet

## acl

- *mask* is maximum permission for users (other than the owner) and groups!
- `chmod` incluences mask of ACL file/dir!
- default ACL of a directory for inheritance


## authentication

### 389ds

``` shell
dsidm localhost client_config sssd.conf | \
  sed '1d' | \
  egrep -v '^(\s*[;#]| *$)' | \
  sed 's!//.*!//<fqdn>:636!'                 # get 389ds configuration for sssd
[domain/ldap]
cache_credentials = True
id_provider = ldap
auth_provider = ldap
access_provider = ldap
chpass_provider = ldap
ldap_schema = rfc2307
ldap_search_base = dc=example,dc=com
ldap_uri = ldapi://<fqdn>:636
ldap_tls_reqcert = demand
ldap_tls_cacertdir = /etc/openldap/certs
enumerate = false
access_provider = ldap
ldap_user_member_of = memberof
ldap_user_gecos = cn
ldap_user_uuid = nsUniqueId
ldap_group_uuid = nsUniqueId
ldap_account_expire_policy = rhds
ldap_access_order = filter, expire
ldap_user_ssh_public_key = nsSshPublicKey
ignore_group_members = False
[sssd]
services = nss, pam, ssh, sudo
config_file_version = 2
domains = ldap
[nss]
homedir_substring = /home
```

### nscd, nss-pam-ldapd, pam_ldap

#### rhel7

``` shell
yum install nscd nss-pam-ldapd pam_ldap
authconfig --savebackup=<backup_dir> \
  --enableldap \
  --enableldapauth \
  --ldapserver=ldap://<ldap_server> \
  --ldapbasedn="ou=people,dc=example,dc=com" \
  --enableldaptls \
  --enablemkhomedir \
  --enablecache \
  --disablesssd \
  --updateall
```

``` shell
# /etc/nslcd.conf
uid nslcd
gid ldap
uri ldap://<ldap_server>
base ou=people,dc=example,dc=com
ssl start_tls
tls_cacertdir /etc/openldap/cacerts

# /etc/nsswitch.conf
passwd: files ldap
shadow: files ldap
group: files ldap
hosts: files dns myhostname
bootparams: nisplus [NOTFOUND=return] files
ethers: files
netmasks: files
networks: files
protocols: files
rpc: files
services: files
netgroup: files ldap
publickey: nisplus
automount: files ldap
aliases: files nisplus

# /etc/openldap/ldap.conf
TLS_CACERTDIR /etc/openldap/cacerts
SASL_NOCANON on
URI ldap://<ldap_server>
BASE ou=people,dc=example,dc=com

# /etc/pam.d/password-auth-ac
auth required pam_env.so
auth required pam_faildelay.so delay=2000000
auth sufficient pam_unix.so nullok try_first_pass
auth requisite pam_succeed_if.so uid >= 1000 quiet_success
auth sufficient pam_ldap.so use_first_pass
auth required pam_deny.so
account required pam_unix.so broken_shadow
account sufficient pam_localuser.so
account sufficient pam_succeed_if.so uid < 1000 quiet
account [default=bad success=ok user_unknown=ignore] pam_ldap.so
account required pam_permit.so
password requisite pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password sufficient pam_unix.so sha512 shadow nullok try_first_pass use_authtok
password sufficient pam_ldap.so use_authtok
password required pam_deny.so
session optional pam_keyinit.so revoke
session required pam_limits.so
-session optional pam_systemd.so
session optional pam_mkhomedir.so umask=0077
session [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session required pam_unix.so
session optional pam_ldap.so

# /etc/pam.d/system-auth-ac
auth required pam_env.so
auth required pam_faildelay.so delay=2000000
auth sufficient pam_unix.so nullok try_first_pass
auth requisite pam_succeed_if.so uid >= 1000 quiet_success
auth sufficient pam_ldap.so use_first_pass
auth required pam_deny.so
account required pam_unix.so broken_shadow
account sufficient pam_localuser.so
account sufficient pam_succeed_if.so uid < 1000 quiet
account [default=bad success=ok user_unknown=ignore] pam_ldap.so
account required pam_permit.so
password requisite pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password sufficient pam_unix.so sha512 shadow nullok try_first_pass use_authtok
password sufficient pam_ldap.so use_authtok
password required pam_deny.so
session optional pam_keyinit.so revoke
session required pam_limits.so
-session optional pam_systemd.so
session optional pam_mkhomedir.so umask=0077
session [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session required pam_unix.so
session optional pam_ldap.so
```

``` shell
systemctl --no-legend list-unit-files | awk '$2 == "enabled" && /(nscd|nslcd)/ { print $1 }'
nscd.service
nslcd.service
nscd.socket
```

failing *nslcd* because of TLS issue

``` shell
localhost:slcd: [8b4567] no available LDAP server found, sleeping 1 seconds
nslcd: [7b23c6] DEBUG: ldap_initialize(ldaps://<ldap_server>)
nslcd: [7b23c6] DEBUG: ldap_set_rebind_proc()
nslcd: [7b23c6] DEBUG: ldap_set_option(LDAP_OPT_PROTOCOL_VERSION,3)
nslcd: [7b23c6] DEBUG: ldap_set_option(LDAP_OPT_DEREF,0)
nslcd: [7b23c6] DEBUG: ldap_set_option(LDAP_OPT_TIMELIMIT,0)
nslcd: [7b23c6] DEBUG: ldap_set_option(LDAP_OPT_TIMEOUT,0)
nslcd: [7b23c6] DEBUG: ldap_set_option(LDAP_OPT_NETWORK_TIMEOUT,0)
nslcd: [7b23c6] DEBUG: ldap_set_option(LDAP_OPT_REFERRALS,LDAP_OPT_ON)
nslcd: [7b23c6] DEBUG: ldap_set_option(LDAP_OPT_RESTART,LDAP_OPT_ON)
nslcd: [7b23c6] DEBUG: ldap_set_option(LDAP_OPT_X_TLS,LDAP_OPT_X_TLS_HARD)
nslcd: [7b23c6] DEBUG: ldap_simple_bind_s("uid=<user>,ou=people,dc=example,dc=com","***") (uri="ldaps://<ldap_server>")
nslcd: [7b23c6] failed to bind to LDAP server ldaps://<ldap_server>: Can't contact LDAP server: error:14090086:SSL routines:ssl3_get_server_certificate:certificate verify failed (unable to get local issuer certificate)
nslcd: [7b23c6] DEBUG: ldap_unbind()
```

### sssd

*sssd* validates CN in TLS cert!

``` shell
journalctl -u sssd -p err --since='2021-06-10 15:49:37' --no-pager
-- Logs begin at Thu 2021-06-10 13:35:58 CEST, end at Thu 2021-06-10 15:50:56 CEST. --
Jun 10 15:49:37 localhost.localdomain sssd[be[ldap]][17206]: Could not start TLS encryption. TLS: hostname does not match CN in peer certificate
Jun 10 15:50:50 localhost.localdomain sssd[be[ldap]][17206]: Could not start TLS encryption. TLS: hostname does not match CN in peer certificate
Jun 10 15:50:52 localhost.localdomain sssd[be[ldap]][17206]: Could not start TLS encryption. TLS: hostname does not match CN in peer certificate
Jun 10 15:50:56 localhost.localdomain sssd[be[ldap]][17206]: Could not start TLS encryption. TLS: hostname does not match CN in peer certificate
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

## boot loaders

### GRUB

`/etc/default/grub_installdevice` is used in various distros (SLES) by
tools to install GRUB on boot disk.

``` shell
grub2-install -v <boot_device>
```

#### commands

``` shell
set # list all set variables
lsmod
insmod <module>

```
#### troubleshooting

various indications of *GRUB 2* issue

- `grub>` - prompt, *GRUB 2* loaded modules but was unable to find the
  its configuration file (`grub.cfg`)
- `grub rescue>` - prompt, *GRUB 2* failed to find the GRUB directory
  or its content is missing or corrupted; the directory contains the
  menu, modules and stored environmental data (or failed to load the
  normal module)
- `GRUB` - a single word at the top left of the screen, with no prompt
  and no cursor. *GRUB 2* failed to find even the most basic
  information, usually contained in the MBR or boot sector.


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

#### setup

See a [two node cluster example](two_node_cluster.md).

#### scenarios

See a [two_node_cluster_example scenarios](two_node_cluster.md#scenarios).

#### management

- by default *root* and *haclient* group members can manage cluster
- some `crm` actions require SSH working between nodes, either
  passwordless root or via a user configured with `crm options user
  <user>` (then it requires passwordless `sudoers` rule)

##### corosync

- *multicast*, when used check that switch is configured correctly
  (see [IGMP snooping](https://en.wikipedia.org/wiki/IGMP_snooping) -
  forwarding only to *valid* ports instead of broadcasting)
  ```
  # for virtual bridge (not openvswitch!)
  grep -H '' /sys/class/net/<bridge_name>/bridge/multicast_snooping
  /sys/class/net/docker0/bridge/multicast_snooping:1

  # for openvswitch
  ovs-vsctl list bridge | grep mcast_snooping_enable
  ```
- *unicast*, usually better

``` shell
corosync-cmapctl nodelist.node                    # list corosync nodes
corosync-cmapctl runtime.totem.pg.mrp.srp.members # list members and state
corosync-cmapctl runtime.votequorum               # runtime info about quorum

corosync-quorumtool -l          # list nodes
corosync-quorumtool -s          # show quorum status of corosync ring
corosync-quorumtool -e <number> # change number of extected votes

corosync-cfgtool -R # tell all nodes to reload corosync config
```

##### pacemaker

important cluster settings

-
``` shell
systemctl start pacemaker # on all nodes
corosync-cpgtool          # see if pacemaker is known to corosync,
                          # these are symlinks to pacemaker daemons,
                          # see `ls -l /usr/lib/pacemaker/'
```

###### pacemaker cli

``` shell
crmadmin -N # show member nodes
crmadmin -D # show designated coordinator (DC)

crm_mon -1 # show cluster status

# pacemaker cli tools
```

``` shell
cibadmin -Q -o nodes      # list nodes in pacemaker
cibadmin -Q -o crm_config # list cluster options configuration in pacemaker
crm_verify -LV            # check configuration used by cluster, verbose
                          # can show important info
```

general cluster mgmt

``` shell
crm_mon                                                 # general overview, part of pacemaker
crm_mon [-n | --group-by-node ]
crm_mon -nforA                                          # incl. fail, counts, operations...
cibadmin [-Q | --query]                                 # expert xml administration, part of pacemaker
crm_attribute --type <scope> --name <attribute> --query # another query solution
```

###### crm (crmsh)

``` shell
crm
crm help <topic>    # generic syntax for help
crm status          # similar to *crm_mon*, part of crmsh
crm resource status # show status of resources

crm resource # interactive shell for resources
crm configure [edit] # configuration edit via editor
                     # do not forget commit changes!
crm move     # careful, creates constraints
crm resource constraints <resource> # show resource constraints
```

#### maintenances

- *maintenance mode* - global cluster property, no resource
  monitoring, no action on resource state change
- *node maintenance* - monitoring operations will cease for the node,
  no action on node state change
- *resource maintenace* - no monitoring of a resource, useful for
  changes in resource without cluster interference
- *is-managed* mode - like resource maintenace mode except cluster
  still monitors resource, reports any failures but does not do any
  action
- *standby* node mode - a node cannot run resources but still
  participates in quorum decisions

``` shell
crm configure property maintenance-mode=<true|false> # global maintenance

crm node maintenance <node> # node maintenance start
crm node ready <node>       # node maintenance stop

crm resource meta <resource> set maintenace true  # resource maintenance start
crm resource meta <resource> set maintenace false # resource maintenance stop

crm resource maintenance <on|off> # (un)sets meta maintenance attribute
crm resource <manage|unmanage> <resource> # set/unsets is-managed mode, ie. *unmanaged*

crm node standby <node> # put node into standby mode (moving away resources)
crm node online <node> # put node online to allow hosting resources
```

##### update service resource example

``` shell
crm resource ban <service_resource> <node> # prevent resource from running on the node
                                           # where service resouce is going to be updated,
                                           # moves resource out of node
...
crm resource clear <service_resource>      # ...
...
```

##### reboot node scenario

node in *standby mode*

``` shell
crm -w node standby # on the node to be rebooted
crm status          # search for 'Node <node>: standby'
crm cluster stop    # stopping cluster services
reboot

crm cluster status  # check cluster services have started
crm cluster start
crm cluster status
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

``` shell
# pacemaker 1.x
grep -P \
  '^(\d{4}-\d{2}-\d{2}T|\S{3} \d{2} )\d{2}:\d{2}:\d{2} .* (corosync|attrd|crmd|cib|lrmd|pengine|stonith|controld|systemd)' \
  messages # grep log file for cluster messages
```

``` shell
# pacemaker 2.x
grep -P \
  '^<YYYY>-<MM>-<DD>T<HH>:\d+:.* (corosync|pacemaker-(attrd|based|controld|execd|schedulerd|fenced)|stonith|systemd)' \
  messages # grep log file for cluster messages
```

##### backup and restore

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
crm ra list ocf # list ocf RA class resources
crm ra list ocf <providers> # list ocf:<provider> RAs
crm ra info [<class>:[<provider>:]]<type> # show RA info and options
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
stonith_admin -L # list registered fencing devices
stonith_admin -I # list available fencing devices
```

stonith device helpers are either programs available as
`/usr/sbin/fence_<device>`, scripts in
`/usr/lib64/stonith/plugins/external/` or libs in
`/usr/lib64/stonith/plugins/stonith2`.

``` shell
stonith_admin -M -a <fence_device_agent> # show docs
```

``` shell
# testing fence_virsh for libvirt VMs

fence_virsh -x -a <libvirt_host> -l <username> \
  -k <ssh_private_key> -o status -v -n <vm/domain>
```

crm node fence <node>


fence_virsh -a host -l <user> -x -k <ssh_private_key> -o <action> -v -n

``` shell
stonith_admin -L
```

##### sbd

*SBD* - storage based death aka STONITH block device

*SBD_STARTMODE=clean* in `/etc/sysconfig/sdb` (SUSE) to prevent
starting cluster if non-clean state exists on SBD

``` shell
sbd query-watchdog                                 # check if sbd finds watcdog devices
sbd -w <watchdog_device> test-watchdog             # test if reset via watchdog works,
                                                   # this RESETS node!

sbd -d /dev/<shared_lun> create                    # prepares shared lun for SBD
sbd -d /dev/<shared_lun> dump                      # info about SBD

systemctl enable sbd                               # MUST be enabled, creates dependency
                                                   # on cluster stack services
systemctl list-dependencies sbd --reverse --all    # check sbd is part of cluster stack

sbd -d /dev/<shared_lun> list                      # list nodes slots and messages

# to make following tests work, sbd has to be running (as part of corosync)
sbd -d /dev/<shared_lun>  message <node> test      # node's sbd would log the test

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

## containers

### docker

#### making all containers to use a proxy

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

#### making docker daemon to use a proxy

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

## desktop

### gtk

#### file-chrooser

``` shell
dconf write /org/gtk/settings/file-chooser/sort-directories-first true # dirs first
cat  ~/.config/gtk-3.0/bookmarks # output: file://<absolute_path> <label>
```

### monitors

``` shell
ls /sys/class/drm/*/edid | \
  xargs -i {} sh -c "echo {}; parse-edid < {}" 2>/dev/null # get info about monitors
```

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

### xdg

``` shell
xdg-mime query filetype <file>     # returns mime type
xdg-mime query default <mime_type> # returns desktop file
```

## development

### C / C++

``` shell
nm -D <shared_library> | awk '$2 == "T" { print $NF }' | sort -u # get global library symbols
objdump -T <shared_library> | \
  awk 'NR>4 && $2 == "g" && NF ~ /^[a-z]/ { print $NF }' | \
  sort -u                                                        # get global library symbols
readelf -sW <shared_library> | \
  awk '$5 == "GLOBAL" && $7 ~ /[0-9]+/ { sub(/@.*/,""); print $NF }' | \
  sort -u                                                        # get global library symbols
```

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

### perl

#### perl command line

See https://www.perl.com/pub/2004/08/09/commandline.html/.

- `-e` - definition of code to be compiled
- `-n -e` - add implicit loop for code
- `-p -e` - add implitic loop for code and also prints each iteration
  (as *continue* in *while* loop)
- `-a` - *autosplit*, input is split and saved in `@F` array
- `-F` - defines value for split the record (as used in `-a`),
  defaults to whitespace

#### regex

- `(?:pattern)` - non-capturing group

## dns

### dnsmasq

TODO: this break because on *apparmor* on SUSE

``` shell
cat > /etc/dnsmasq.<iface>.conf <<EOF
strict-order
pid-file=/run/dnsmasq/<iface>.pid
except-interface=lo
bind-dynamic
interface=<iface>
dhcp-range=<ip_start>,<ip_end>,<mask>
dhcp-no-override
dhcp-authoritative
dhcp-lease-max=253
dhcp-hostsfile=/run/dnsmasq/<iface>.hostsfile
addn-hosts=/run/dnsmasq/<iface>.addnhosts
EOF
```

### named / bind

dynamic DNS updates

``` shell
key "<key>" {
    algorithm HMAC-MD5;
    secret <secret>";
};

zone "<forward_zone>" IN {
        type master;
        allow-transfer { <dhcp_server>; };
        file "<zone_file>";
        forwarders {};
        allow-update { key "<key>"; };
};

zone "<reverse_zone>" IN {
     type master;
     allow-transfer { <dhcp_server>; };
     file "<zone_file>";
     allow-update { key "<key>"; };
     forwarders {};
};
```

## filesystems

``` shell
mount | column -t # more readable mount output
```

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

#### snapper

automatically triggered btrfs snapshots

``` shell
snapper list
```

### nfs

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

#### server

On SUSE `/usr/sbin/rpc.nfsd` reads `/etc/nfs.conf` which loads
`/etc/sysconfig/nfs`.

``` shell
exportfs -s # see exports
```

``` shell
# usually nfsv3 commands
rpcbind -p   # list registered services in rpcbind
showmount -e # list remote exports
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

#### client

``` shell
# usually nfsv3 commands
rpcbind -p <nfs_server>   # list registered services in rpcbind
showmount -e <nfs_server> # list remote exports
```

#### troubleshooting

``` shell
grep -RH '^address: ' /proc/fs/nfsd/clients/*/info # list clients
cat /var/lib/nfs/rpc_pipefs/nfsd4_cb/clnt*/info    # more brief info

grep -RH '' /proc/fs/nfsd/ 2>/dev/null
```

``` shell
rpcdebug -m <module> # status of debugging; 'nfs' (client), 'nfsd' (server)
rpcdebug -m <module> -s   # enable debugging for module
rpcdebug -m <module> -c   # disable debugging for module

grep -RH '' /proc/sys/sunrpc/nfs_debug # above commands change this value
```

- `bg / fg`, see `nfs(5)` and `systemd.mount(5)`. kernel
  **differentiates** between network problem and permnission problem,
  thus when using *bg* and networks starts working and mounting NFS
  export faces permissions issue, then there is *no more* retry
  ```
  # sle12sp5
  # first attempt to mount the NFS export with 'bg', firewall on the server blocking access
  Jun 23 12:59:47 linux-u93p mount[1770]: mount to NFS server '192.168.122.1' failed: Connection refused, retrying
  Jun 23 12:59:49 linux-u93p mount[1770]: mount to NFS server '192.168.122.1' failed: Connection refused, retrying
  ...
  # after 3 mins expired (thus > 2 mins for 'fg')
  Jun 23 13:03:53 linux-u93p kernel: NFS: nfs mount opts='hard,bg,addr=192.168.122.1,vers=3,proto=tcp,mountvers=3,mountproto=tcp,mountport=20048'
  Jun 23 13:03:53 linux-u93p kernel: NFS: parsing nfs mount option 'hard'
  Jun 23 13:03:53 linux-u93p kernel: NFS: parsing nfs mount option 'bg'
  Jun 23 13:03:53 linux-u93p kernel: NFS: ignoring mount option 'bg'
  Jun 23 13:03:53 linux-u93p kernel: NFS: parsing nfs mount option 'addr=192.168.122.1'
  Jun 23 13:03:53 linux-u93p kernel: NFS: parsing nfs mount option 'vers=3'
  Jun 23 13:03:53 linux-u93p kernel: NFS: parsing nfs mount option 'proto=tcp'
  Jun 23 13:03:53 linux-u93p kernel: NFS: parsing nfs mount option 'mountvers=3'
  Jun 23 13:03:53 linux-u93p kernel: NFS: parsing nfs mount option 'mountproto=tcp'
  Jun 23 13:03:53 linux-u93p kernel: NFS: parsing nfs mount option 'mountport=20048'
  Jun 23 13:03:53 linux-u93p kernel: NFS: MNTPATH: '/tmp'
  Jun 23 13:03:53 linux-u93p kernel: NFS: sending MNT request for 192.168.122.1:/tmp
  Jun 23 13:03:53 linux-u93p kernel: NFS: received 1 auth flavors
  Jun 23 13:03:53 linux-u93p kernel: NFS: auth flavor[0]: 1
  Jun 23 13:03:53 linux-u93p kernel: NFS: MNT request succeeded
  Jun 23 13:03:53 linux-u93p kernel: NFS: attempting to use auth flavor 1
  Jun 23 13:03:53 linux-u93p kernel: NFS: get client cookie (0xffff9650aff5bc00/0xffff9650a52c0500)
  Jun 23 13:03:53 linux-u93p systemd[1]: systemd-udevd.service: Got notification message from PID 444 (WATCHDOG=1)
  Jun 23 13:03:53 linux-u93p kernel: NFS call fsinfo
  Jun 23 13:03:53 linux-u93p kernel: NFS reply fsinfo: 0
  Jun 23 13:03:53 linux-u93p kernel: NFS call pathconf
  Jun 23 13:03:53 linux-u93p kernel: NFS reply pathconf: 0
  Jun 23 13:03:53 linux-u93p kernel: NFS call getattr
  Jun 23 13:03:53 linux-u93p kernel: NFS reply getattr: 0
  Jun 23 13:03:53 linux-u93p kernel: Server FSID: 274b5220933e3e91:0
  Jun 23 13:03:53 linux-u93p kernel: do_proc_get_root: call fsinfo
  Jun 23 13:03:53 linux-u93p kernel: do_proc_get_root: reply fsinfo: 0
  Jun 23 13:03:53 linux-u93p kernel: do_proc_get_root: reply getattr: 0
  Jun 23 13:03:53 linux-u93p kernel: NFS: nfs_fhget(0:78/256 fh_crc=0x86d0b24e ct=1)
  ...
  Jun 23 13:03:53 linux-u93p systemd[1]: libmount event [rescan: yes]
  Jun 23 13:03:53 linux-u93p systemd[1]: mnt.mount: Changed dead -> mounted
  ...
  Jun 23 13:03:53 linux-u93p systemd[1]: Received SIGCHLD from PID 1770 (mount.nfs).
  Jun 23 13:03:53 linux-u93p systemd[1]: Child 1770 (mount.nfs) died (code=exited, status=0/SUCCESS)
  Jun 23 13:03:53 linux-u93p systemd[1]: systemd-logind.service: Got notification message from PID 817 (WATCHDOG=1)
  Jun 23 13:04:10 linux-u93p kernel: NFS: revalidating (0:78/256)
  Jun 23 13:04:10 linux-u93p kernel: NFS call getattr
  Jun 23 13:04:10 linux-u93p kernel: NFS reply getattr: 0
  Jun 23 13:04:10 linux-u93p kernel: NFS: nfs_update_inode(0:78/256 fh_crc=0x86d0b24e ct=2 info=0x27e7f)
  Jun 23 13:04:10 linux-u93p kernel: NFS: (0:78/256) revalidation complete
  Jun 23 13:04:10 linux-u93p kernel: NFS: nfs_weak_revalidate: inode 256 is valid
  Jun 23 13:04:10 linux-u93p kernel: NFS call access
  Jun 23 13:04:10 linux-u93p kernel: NFS: nfs_update_inode(0:78/256 fh_crc=0x86d0b24e ct=2 info=0x27e7f)
  Jun 23 13:04:10 linux-u93p kernel: NFS reply access: 0
  Jun 23 13:04:10 linux-u93p kernel: NFS: permission(0:78/256), mask=0x24, res=0
  Jun 23 13:04:10 linux-u93p kernel: NFS: open dir(/)
  Jun 23 13:04:10 linux-u93p kernel: NFS: revalidating (0:78/256)
  Jun 23 13:04:10 linux-u93p kernel: NFS call getattr
  Jun 23 13:04:10 linux-u93p systemd[1]: systemd-journald.service: Got notification message from PID 419 (WATCHDOG=1)
  Jun 23 13:04:10 linux-u93p kernel: NFS reply getattr: 0
  Jun 23 13:04:10 linux-u93p kernel: NFS: nfs_update_inode(0:78/256 fh_crc=0x86d0b24e ct=2 info=0x27e7f)
  Jun 23 13:04:10 linux-u93p kernel: NFS: (0:78/256) revalidation complete
  Jun 23 13:04:10 linux-u93p kernel: NFS: nfs_weak_revalidate: inode 256 is valid
  Jun 23 13:04:10 linux-u93p kernel: NFS: nfs_weak_revalidate: inode 256 is valid
  Jun 23 13:04:10 linux-u93p kernel: NFS: nfs_weak_revalidate: inode 256 is valid
  Jun 23 13:04:10 linux-u93p kernel: NFS call fsstat
  Jun 23 13:04:10 linux-u93p kernel: NFS reply fsstat: 0
  ```

##### nfsstat

details about `nfsstat` can be found at this
[blog](https://web.archive.org/web/20210622120310/https://www.cyberithub.com/nfsstat-command-examples-in-linux-cheatsheet/)

| information | description |
| --- | --- |
| calls | Total Number of RPC Calls made. |
| retrans | The number of times a call had to be retransmitted due to a time-out while waiting for a reply from the server. |
| authrefrsh | The number of times the NFS client has called call_refresh() which is basically going out to the RPC server (portmap, rpcbind, etc) and validating its credentials with the server. |
| null | do nothing (debug). Check this IETF RFC Document to know more about this. |
| read | read from file. Check this IETF RFC Document to know more about this. |
| write | write to file |
| commit | commit cached data to stable storage |
| open | open a file |
| open_conf | Confirm Open |
| open_noat | Open Named Attribute Directory |
| open_dgrd | Reduce Open File Access |
| close | Close File |
| setattr | set file attributes |
| fsinfo | get static file system information |
| renew | renew a lease |
| setclntid | Negotiate Client ID |
| lock | Create Lock |
| lockt | Test For Lock |
| locku | lookup file name |
| access | check access permission |
| getattr | get file attributes |
| lookup | Lookup Filename |
| remove | Remove a File |
| rename | Rename a File or Directory |
| link | Create Link to an Object |
| symlink | Create a Symbolic Link |
| create | Create a File |
| pathconf | Retrieve POSIX Information |
| readlink | Read from Symbolic Link |
| readdir | Read from Directory |
| delegreturn | Return Delegations |
| getacl | Get Access List |
| setacl | Set Access List |
| fs_locations | Locations where this file system may be found. |
| secinfo | obtain available security |
| exchange_id | Instantiate Client ID |
| create_ses | creation new session and confirm Client ID |
| destroy_ses | destroy session |
| sequence | Supply Per-Procedure |
| reclaim_comp | Indicates Reclaim Finished. |
| layoutget | Get Layout Information |
| getdevinfo | Get Device Information |
| layoutcommit | Commit Writes Made |
| layoutreturn | Release Layout |
| getdevlist | Get All Devices |

## firewall

### iptables

##### iptables replace rule

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

## graphics

### ghostscript

``` shell
ps2pdf -dPDFSETTINGS=/ebook <orig_pdf> <new_pdf> # shrink size of a pdf
```

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

## hardware

### udev

## kerberos

- *'$'* in principal name indicates machine account

``` shell
KRB5_TRACE=/dev/stdout kinit <args> # to get debug from any gssapi/krb library
                                    # calls
```

## kernel

### configuration

- `/proc/config.gz`

### kdump

[sysrq
key](https://www.kernel.org/doc/html/latest/admin-guide/sysrq.html) in
Linux

``` shell
zgrep -P \
  '^CONFIG_(RELOCATABLE|KEXEC|CRASH_DUMP|DEBUG_INFO|MAGIC_SYSRQ|PROC_VMCORE)=' \
  /proc/config.gz # validate that kdump has configuration ready (value 'y')
```

``` shell
dmesg | grep crashkernel
```

### modules

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

### panic

an example from SLE 12 SP5, which means - IIUC - kernel panics when an
[oops](https://en.wikipedia.org/wiki/Linux_kernel_oops) or
[BUG](https://kernelnewbies.org/FAQ/BUG) is encountered **but** kernel
will loop forever since `panic` is `0`. see *panic* options in
[kernel](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/admin-guide/sysctl/kernel.rst#n706).

``` shell
grep -RH '' /proc/sys/kernel/panic*
/proc/sys/kernel/panic:0
/proc/sys/kernel/panic_on_io_nmi:0
/proc/sys/kernel/panic_on_oops:1
/proc/sys/kernel/panic_on_rcu_stall:0
/proc/sys/kernel/panic_on_unrecovered_nmi:0
/proc/sys/kernel/panic_on_warn:0
```

### procfs

what are open files limits of an existing process?

``` shell
grep '^Max open files' /proc/$(pgrep -f /usr/sbin/cupsd)/limits | column -t
> Max  open  files  4096  4096  files
systemctl show -p LimitNOFILE cups
> LimitNOFILE=4096
```

#### sysctl

`sysctl` changes kernel params at runtime, those under `/proc/sys`.

``` shell
sysctl net.ipv4.conf.all.forwarding
> net.ipv4.conf.all.forwarding = 1

grep -H '' /proc/sys/net/ipv4/conf/all/forwarding
> /proc/sys/net/ipv4/conf/all/forwarding:1
```

*rp_filter* sets validation of incoming packets (RFC 1812), see also
[ip-sysctl.txt](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)

> ``` shell
> rp_filter - INTEGER
> 	0 - No source validation.
> 	1 - Strict mode as defined in RFC3704 Strict Reverse Path
> 	    Each incoming packet is tested against the FIB and if the interface
> 	    is not the best reverse path the packet check will fail.
> 	    By default failed packets are discarded.
> 	2 - Loose mode as defined in RFC3704 Loose Reverse Path
> 	    Each incoming packet's source address is also tested against the FIB
> 	    and if the source address is not reachable via any interface
> 	    the packet check will fail.
>
> 	Current recommended practice in RFC3704 is to enable strict mode
> 	to prevent IP spoofing from DDos attacks. If using asymmetric routing
> 	or other complicated routing, then loose mode is recommended.
>
> 	The max value from conf/{all,interface}/rp_filter is used
> 	when doing source validation on the {interface}.
> ```

``` shell
grep -RH '' /proc/sys/net/ipv4/conf/{all,ppp0,eth[02]}/rp_filter # on a router
/proc/sys/net/ipv4/conf/all/rp_filter:2
/proc/sys/net/ipv4/conf/ppp0/rp_filter:0
/proc/sys/net/ipv4/conf/eth0/rp_filter:0
/proc/sys/net/ipv4/conf/eth2/rp_filter:0
```

### dracut / initramfs

``` shell
rpm -ql dracut | egrep 'systemd/dracut-.*\.(service|sh)$' | \
  grep -v shutdown                                            # dracut initramfs "hooks"
man 7 dracut.cmdline
```

useful kernel parameters

```
rd.break[=<stage>] # either stop before a dracut hook or in switch_root shell,
                   # ie. latest stage in initramfs before pivot_root is performed
rd.udev.debug      # tracing of udev actions
```

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

## networking

### bonding

*bonding* means aggregating several ethernet devices into a single device

``` shell
lsmod | grep bonding # kernel module is in drivers/net/bonding subdir
modprobe bonding     # loading module create inactive bond0 iface by default (SUSE)
```

``` shell
grep -H '' /sys/class/net/bond0/bonding/{slaves,mode,miimon,lacp_rate,ad_select} # basic query
/sys/class/net/bond0/bonding/mode:balance-rr 0
/sys/class/net/bond0/bonding/miimon:0
/sys/class/net/bond0/bonding/lacp_rate:slow 0
/sys/class/net/bond0/bonding/ad_select:stable 0
```

default *bonding* mode is *balance-rr*, see
[bonding.txt](https://www.kernel.org/doc/Documentation/networking/bonding.txt)
for details

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

## package management

## rpm

``` shell
rpm -K --nosignature <rpm_file>
> <rpm_file>: digests OK        # rpm verification

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

- *discovery/discoverydb*, query/find target
- *node*, log into a target
- *session*, get info about current session or establish new session
- *iface/host*, settings to connect to a target

``` shell
lsmod | grep scsi_transport_iscsi # should be loaded by distro tools
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
# no all targets must be started automatically, see what iscsi.service unit on
# SUSE is doing

systemctl cat iscsi | grep ^ExecStart
ExecStart=/sbin/iscsiadm -m node --loginall=automatic -W
ExecStart=/sbin/iscsiadm -m node --loginall=onboot -W
ExecStart=/sbin/iscsiadm -m fw -l -W

iscsiadm -m node -T <target> -l # login
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

##### iface

in MPIO we usually want iSCSI connection go over multiple separate
interfaces

``` shell
iscsiadm -m iface -P 1                                               # list initiator interfaces
iscsiadm -m iface -I <name> -o new                                   # add new interface named '<name>'
iscsiadm -m iface -I <name> -o update -n iface.hwaddress -v <hwaddr> # assing logical iface to hardware
                                                                     # address
iscsiadm -m iface -I <name>                                          # show logical iface details
```

#### target

usually there's a service restoring configuration for in-kernel LIO
target

``` shell
# SUSE
[[ -e /etc/sysconfig/target ]] && egrep -v '^(\s*[;#]| *$)' /etc/sysconfig/target

systemctl --no-pager show -p ExecStart -p EnvironmentFiles -p Environment target
ExecStart={ path=/usr/bin/targetctl ; argv[]=/usr/bin/targetctl restore $CONFIG_FILE ; ignore_errors=no ; start_time=[n/1] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
Environment=CONFIG_FILE=/etc/target/saveconfig.json
EnvironmentFiles=/etc/sysconfig/target (ignore_errors=yes)
```

non-interactive way of `targetcli`

``` shell
targetcli <path> <command> [<args>]
```

##### setup

``` shell
targetcli /iscsi/ create [<target_name>]                            # create target,
                                                                    # returns target name if not defined
targetcli /iscsi/<target_name>/tpg1/portals/ create [<ip>] [<port>] # create target and optionally bind to
                                                                    # specific IP and port
targetcli /iscsi/<target_name>/tpg1/luns create <backing_object> \
  [<lun_number>]                                                    # add lun to target portal group
```

##### targetcli commands examples

``` shell
targetcli /backstores/fileio create mpio01 /home/iscsi/mpio01.raw 1G

targetcli /backstores/fileio/mpio01 info
> aio: False
> dev: /home/iscsi/mpio01.raw
> name: mpio01
> plugin: fileio
> size: 1073741824
> write_back: True
> wwn: 501bb55a-79b6-499f-8c20-a3833fae05b0
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
lvmconfig # print current lvm configuration

```

``` shell
pvs -o +pv_used                               # show spage used in PVs
pvmove /dev/<pv>                              # moving data from PV to other PV
pvmove -n </dev/<vg>/<lv> /dev/<pv> /dev/<pv> # moving extents of to other PV
vgreduce <vg> <unused_pv>                     # removing a PV from VG
pvremove <unused_pv>
pvs -o help # list of options
```

#### thinpool

``` shell
lvcreate -L <size> -T -n <name> <vg> # create a thin pool

```

## systemd / journald

### systemd

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

systemctl list-dependencies <unit> --reverse --all # list unit dependency
```

#### unit files location

* `/usr/local/lib/systemd/system` for system units installed by the
  administrator, outside of the distribution package manager
* `/etc/systemd/system` system units *created* by the administrator

#### override units via drop-in files

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

#### rescue, repair

* single-user like mode

`systemd.unit=rescue.target` as kernel boot param

* emergency

`systemd.unit=emergency.target` as kernel boot param

Other tips:

* `systemd.mask=swap.target`         # on SUSE
* `system.device_wants_unit=off`     # on SUSE
* `system.mask=dev-system-swap.swap` # on SUSE
* `systemctl list-units --type=swap`
* `systemd-escape -p --suffix=swap /dev/system/swap` # returns 'dev-system-swap.swap'

#### troubleshooting

- emergency shell - systemd after `pivot_root`
- `systemd.log_level=debug systemd.log_target=console systemd.log_location=true systemd.show_status=true`
- `systemd-analyze set-log-level <level>` - change logging level
- `systemctl show -p LogLevel` - get current logging level

#### desktop stuff

``` shell
mkdir /etc/systemd/logind.conf.d
echo 'HandleLidSwitch=ignore' >> \
  /etc/systemd/logind.conf.d/lid.conf
systemctl restart systemd-logind # does not work on SUSE
```

### journald

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

## distros

### RHEL

#### sosreport

- `sos_commands/systemd/journalctl_--list-boots`
- `sos_commands/block/lsblk{,_-f_-a_-l}`
- `etc/fstab`
- `{free,proc/meminfo}`

### SUSE



#### installation

*linuxrc* is *init* instead of *systemd*

#### networking

``` shell
echo 'default <ip> - -' > /etc/sysconfig/network/routes
cat > /etc/sysconfig/network/ifcfg-eth0 <<EOF
IPADDR='<ip/mask>'
BOOTPROTO='static'
STARTMODE='auto'
EOF
```

static route on a DHCP managed iface needs also a definition for the gateway itself, see [Q: Why wicked does not set my (default) static route?](https://github.com/openSUSE/wicked/wiki/FAQ#q-why-wicked-does-not-set-my-default-static-route)

``` shell
for f in /etc/sysconfig/network/if{cfg,route}-eth0; do echo '>>>' $f ; cat $f ; done
>>> /etc/sysconfig/network/ifcfg-eth0
BOOTPROTO='dhcp'
STARTMODE='auto'
>>> /etc/sysconfig/network/ifroute-eth0
192.168.122.2 - - eth0
8.8.4.0/24 192.168.122.2 - eth0

wicked ifstatus eth0
eth0 up
link: #2, state up, mtu 1500
type: ethernet, hwaddr 52:54:00:05:62:e6
config: compat:suse:/etc/sysconfig/network/ifcfg-eth0
leases: ipv4 static granted, ipv4 dhcp granted
leases: ipv6 dhcp requesting
addr: ipv4 192.168.122.190/24 [dhcp]
route: ipv4 default via 192.168.122.1 proto dhcp
route: ipv4 8.8.4.0/24 via 192.168.122.2 proto boot
```

#### product / registration

See [TID7023490](https://www.suse.com/support/kb/doc/?id=000019341)
which states that `/etc/os-release` is not the best source of truth
about the SUSE product.

``` shell
ls -l /etc/products.d/baseproduct # check 'baseproduct' symlink
rpm -qa \*-release | grep -i sles # another helpful check
```

``` shell
SUSEConnect -r <activation_key> -e <email>
```

#### rmt

rmt is 'repository mirroring tool' from SUSE

- `/etc/rmt/ssl/rmt-ca.{crt,key}`, CA cert/key
- `/etc/rmt/ssl/rmt-server.{crt,key}`, server cert/key
- `/usr/share/rmt/public/repo` (symlink to `/var/lib/rmt/public/repo`)

``` shell
systemctl status rmt-server-sync.timer # timer

rmt-cli sync # synchronize product & repositories (meta)data

rmt-cli products list --all         # list all available products
rmt-cli products enable <id/string> # enable a product
rmt-cli products show <id/string>   # info about a product repos and attributes

rmt-cli repos list
rmt-cli repos enable/disable <id>   # enable a product repo
```

``` shell
journalctl -u rmt-server | grep Listening
> Jul 26 11:16:02 t14s rails[4995]: [4995] * Listening on http://127.0.0.1:4224

ps auxww | grep 'puma .*\[rmt\]$' # main rmt pid
> _rmt     25199  1.3  0.5 281652 87396 ?        Ssl  14:54   0:01 puma 5.3.2 (tcp://127.0.0.1:4224) [rmt]
```

#### support

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

#### supportconfig

supportconfig files could be huge thus a little tip to search for
commands output

``` shell
awk '/^#==\[ Command \]=+#$/ {getline;print NR,$0}' sysfs.txt
2 # /bin/find /sys | xargs ls -ld --time-style=long-iso
114450 # /usr/bin/systool
114622 # /usr/bin/systool -vb clockevents
117704 # /usr/bin/systool -vb clocksource
117716 # /usr/bin/systool -vb container
117721 # /usr/bin/systool -vb cpu
124718 # /usr/bin/systool -vb edac
124727 # /usr/bin/systool -vb event_source
124768 # /usr/bin/systool -vb gpio
124773 # /usr/bin/systool -vb hid
...
```

#### zypper

##### repos

``` shell
zypper lr # list repos
zypper lr -d <repo> # details about a repo
zypper mr -e <repo>
zypper mr -e --all # enable all repos
```

##### patterns

``` shell
zypper pt
zypper in -t pattern <pattern_name>

```

``` shell
zypper search --provides --type package -x view
```

##### packages

``` shell
zypper rm -u <package> # removes package and all deps
zypper se --provides -x /usr/bin/gnat # search package owning path
```

##### patches

``` shell
zypper lp
zypper pchk
```

## printing

### cups

``` shell
cupsd -t                     # test configuration
cupsctl --[no-]debug-logging # enable/disable debug logging
```

``` shell
lpstat -p -d              # list printers and default one
lpoptions -d <printer>    # set default printer
lpoptions -l -p <printer> # list printer options

lpstat -l -e | grep <printer> # show connection to a printer
```

``` shell
lpstat -o <printer>    # list jobs on printer
lprm -P <printer> <id> # kill job on printer

grep 'Printer' /sys/bus/usb/devices/*/* 2>/dev/null # list usb printers
udevadm info -p <sysfs_path>                        # show properties of usb device
grep -rH '' /sys/bus/usb/devices/*/ieee1284_id 2>/dev/null # IEEE 1284 info
```
See http://www.undocprint.org/formats/communication_protocols/ieee_1284
See https://www.cups.org/doc/options.html

``` shell
lp [-d <printer>] <file>   # print a file
lpr [-P <printer>] <file>  # print a file
```

``` shell
# limits
man cupsd.conf | egrep -A 1 'MaxJobs(PerPrinter)* number' | fmt -w80
       MaxJobs number
            Specifies the maximum number of simultaneous jobs that are allowed.
            Set to "0" to allow an unlimited number of jobs.  The default is
            "500".
--
       MaxJobsPerPrinter number
            Specifies the maximum number of simultaneous jobs that are allowed
            per printer.  The default is "0" which allows up to MaxJobs jobs
            per printer.
```
#### tips

- https://access.redhat.com/solutions/305283

### texlive

idea taken from [Void
Linux](https://github.com/void-linux/void-packages/blob/master/srcpkgs/texlive2021-bin/template),
some tips in Void Linux
[texlive](https://docs.voidlinux.org/config/texlive.html)
documentation

``` shell
zypper in cairo libpixman-1-0 libgraphite2-3 gd libpoppler110 libsigsegv2 \
  libzzip-0-13 libpng libjpeg-turbo freetype icu libharfbuzz0 wget perl ghostscript xz
cat > /etc/profile.d/texlive.sh <<EOF
#location of the TeXLive binaries
export PATH=$PATH:/opt/texlive/<version>/bin/x86_64-linux
EOF

mkdir -p /opt/texlive<version>-installer
curl -Ls https://mirror.ctan.org/systems/texlive/tlnet/install-tl-unx.tar.gz | \
  bsdtar --strip-components=1 -xvf - -C /opt/texlive<version>-installer
cat > /opt/texlive<version>-installer/local.profile <<EOF
TEXDIR ../texlive/2021
TEXMFCONFIG ~/.texlive2021/texmf-config
TEXMFHOME ~/texmf
TEXMFLOCAL ../texlive/texmf-local
TEXMFSYSCONFIG ../texlive/2021/texmf-config
TEXMFSYSVAR ../texlive/2021/texmf-var
TEXMFVAR ~/.texlive2021/texmf-var
selected_scheme scheme-small
EOF
cd /opt/textlive<version>-install && ./install-tl -profile local.profile

. /etc/profile.d/texlive.sh
tlmgr paper a4 # change global default paper size
```

putting pages from two documents side by side

``` shell
# pdfseparate is from poppler-tools

pdfseparate <pdf_file1> temp-%04d-file1.pdf
pdfseparate <pdf_file2> temp-%04d-file2.pdf
pdfjam temp-*-*.pdf --nup 2x1 --landscape --outfile <out_file>
```

## security

### apparmor

- `apparmor=0` as kernel parameter in boot to disable apparmor

``` shell
zgrep -i apparmor /proc/config.gz            # check if enabled in kernel
aa-status 2>/dev/null | head -n1             # check if enabled or not
grep -RH '' /sys/module/apparmor 2>/dev/null # check details about apparmor
systemctl is-enabled apparmor.service
systemctl is-active apparmor.service
```

``` shell
aa-unconfined | grep 'not confined' # check for unconfined processes
                                    # which listen on tcp/udp ports
```

``` shell
aa-complain <profile> # not enforcing but logging mode
                      # (similar to permissive in SELinux)
```

### auditd

- [audit system reference](https://access.redhat.com/articles/4409591)
  (description of event fields, record types), or
  [`audit.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/audit.h)
- `audit=0` as kernel boot parameter to suppress audit messages
- `audit=1`

``` shell
zgrep '^CONFIG_AUDIT=' /proc/config.gz # check support in kernel
```

``` shell
cat audit.log | \
  egrep '^type=SYSTEM_(SHUTDOWN|BOOT)' | \
  perl -pe 's/(\d+)/localtime($1)/e'       # see (un)graceful shutdowns
> type=SYSTEM_SHUTDOWN msg=audit(Wed Jun 16 03:01:36 2021.789:10227377): pid=26593 uid=0 auid=4294967295 ses=4294967295 msg=' comm="systemd-update-utmp" exe="/usr/lib/systemd/systemd-update-utmp" hostname=? addr=? terminal=? res=success'
> type=SYSTEM_BOOT msg=audit(Wed Jun 16 03:04:31 2021.348:7): pid=3962 uid=0 auid=4294967295 ses=4294967295 msg=' comm="systemd-update-utmp" exe="/usr/lib/systemd/systemd-update-utmp" hostname=? addr=? terminal=? res=success'
```

### ssh login example

#### logging in

``` shell
# record about crypto key identifier used for crypto purposes
type=CRYPTO_KEY_USER msg=audit(1623924436.018:209): pid=1802 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=destroy kind=server fp=SHA256:94:e4:42:14:aa:4a:cf:01:4a:44:d8:b0:82:32:32:a8:6e:3d:64:91:ba:22:b1:8d:7c:b4:a2:26:9a:91:65:42 direction=? spid=1802 suid=0  exe="/usr/sbin/sshd" hostname=? addr=? terminal=? res=success'
type=CRYPTO_KEY_USER msg=audit(1623924436.018:210): pid=1802 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=destroy kind=server fp=SHA256:53:5b:b8:5f:92:65:1c:6b:fc:69:28:8b:26:42:c6:58:fa:63:76:43:43:d4:4c:cd:81:1b:cc:52:c6:02:77:fc direction=? spid=1802 suid=0  exe="/usr/sbin/sshd" hostname=? addr=? terminal=? res=success'
type=CRYPTO_KEY_USER msg=audit(1623924436.018:211): pid=1802 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=destroy kind=server fp=SHA256:63:42:8b:7b:d5:ff:b1:e2:91:09:51:8d:35:dd:79:7a:0a:29:b0:5e:86:90:1e:17:f1:c8:dc:f9:fc:e6:cc:3d direction=? spid=1802 suid=0  exe="/usr/sbin/sshd" hostname=? addr=? terminal=? res=success'

# record about params for crypto session
type=CRYPTO_SESSION msg=audit(1623924436.022:212): pid=1801 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=start direction=from-server cipher=chacha20-poly1305@openssh.com ksize=512 mac=<implicit> pfs=curve25519-sha256 spid=1802 suid=74 rport=44796 laddr=192.168.122.104 lport=22  exe="/usr/sbin/sshd" hostname=? addr=192.168.122.1 terminal=? res=success'
type=CRYPTO_SESSION msg=audit(1623924436.023:213): pid=1801 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=start direction=from-client cipher=chacha20-poly1305@openssh.com ksize=512 mac=<implicit> pfs=curve25519-sha256 spid=1802 suid=74 rport=44796 laddr=192.168.122.104 lport=22  exe="/usr/sbin/sshd" hostname=? addr=192.168.122.1 terminal=? res=success'

# [SSH KEYS] record of user-space user authentication attempt
type=USER_AUTH msg=audit(1623924436.083:214): pid=1801 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=pubkey acct="jiri" exe="/usr/sbin/sshd" hostname=? addr=192.168.122.1 terminal=ssh res=failed'
type=USER_AUTH msg=audit(1623924436.083:215): pid=1801 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=pubkey acct="jiri" exe="/usr/sbin/sshd" hostname=? addr=192.168.122.1 terminal=ssh res=failed'

^^ it fails because user had no ssh key on the server

# [PAM] record of user-space user authentication attempt
type=USER_AUTH msg=audit(1623924437.617:216): pid=1801 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=PAM:authentication grantors=pam_unix acct="jiri" exe="/usr/sbin/sshd" hostname=t14s.home.arpa addr=192.168.122.1 terminal=ssh res=success'
type=USER_ACCT msg=audit(1623924437.622:217): pid=1801 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=PAM:accounting grantors=pam_unix,pam_localuser acct="jiri" exe="/usr/sbin/sshd" hostname=t14s.home.arpa addr=192.168.122.1 terminal=ssh res=success'

^^ PAM

# record about crypto key identifier used for crypto purposes
type=CRYPTO_KEY_USER msg=audit(1623924437.622:218): pid=1801 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=destroy kind=session fp=? direction=both spid=1802 suid=74 rport=44796 laddr=192.168.122.104 lport=22  exe="/usr/sbin/sshd" hostname=? addr=192.168.122.1 terminal=? res=success'

# record of user-space user authentication attempt
type=USER_AUTH msg=audit(1623924437.624:219): pid=1801 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=success acct="jiri" exe="/usr/sbin/sshd" hostname=? addr=192.168.122.1 terminal=ssh res=success'

# [PAM] record of user user-space credentials request
type=CRED_ACQ msg=audit(1623924437.625:220): pid=1801 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=PAM:setcred grantors=pam_unix acct="jiri" exe="/usr/sbin/sshd" hostname=t14s.home.arpa addr=192.168.122.1 terminal=ssh res=success'

# record of relevant login information when a user logs in to access the system
type=LOGIN msg=audit(1623924437.626:221): pid=1801 uid=0 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 old-auid=4294967295 auid=1000 tty=(none) old-ses=4294967295 ses=5 res=1

# [SELINUX] record when a user's SELinux role is changed
type=USER_ROLE_CHANGE msg=audit(1623924437.816:222): pid=1801 uid=0 auid=1000 ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='pam: default-context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 selected-context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 exe="/usr/sbin/sshd" hostname=t14s.home.arpa addr=192.168.122.1 terminal=ssh res=success'

# [PAM] record of user-space session start
type=USER_START msg=audit(1623924437.845:223): pid=1801 uid=0 auid=1000 ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=PAM:session_open grantors=pam_selinux,pam_loginuid,pam_selinux,pam_namespace,pam_keyinit,pam_keyinit,pam_limits,pam_systemd,pam_mkhomedir,pam_unix,pam_ldap,pam_lastlog acct="jiri" exe="/usr/sbin/sshd" hostname=t14s.home.arpa addr=192.168.122.1 terminal=ssh res=success'

# record about crypto key identifier used for crypto purposes
type=CRYPTO_KEY_USER msg=audit(1623924437.846:224): pid=1805 uid=0 auid=1000 ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=destroy kind=server fp=SHA256:94:e4:42:14:aa:4a:cf:01:4a:44:d8:b0:82:32:32:a8:6e:3d:64:91:ba:22:b1:8d:7c:b4:a2:26:9a:91:65:42 direction=? spid=1805 suid=0  exe="/usr/sbin/sshd" hostname=? addr=? terminal=? res=success'
type=CRYPTO_KEY_USER msg=audit(1623924437.846:225): pid=1805 uid=0 auid=1000 ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=destroy kind=server fp=SHA256:53:5b:b8:5f:92:65:1c:6b:fc:69:28:8b:26:42:c6:58:fa:63:76:43:43:d4:4c:cd:81:1b:cc:52:c6:02:77:fc direction=? spid=1805 suid=0  exe="/usr/sbin/sshd" hostname=? addr=? terminal=? res=success'
type=CRYPTO_KEY_USER msg=audit(1623924437.846:226): pid=1805 uid=0 auid=1000 ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=destroy kind=server fp=SHA256:63:42:8b:7b:d5:ff:b1:e2:91:09:51:8d:35:dd:79:7a:0a:29:b0:5e:86:90:1e:17:f1:c8:dc:f9:fc:e6:cc:3d direction=? spid=1805 suid=0  exe="/usr/sbin/sshd" hostname=? addr=? terminal=? res=success'

# record of user user-space credentials request
type=CRED_ACQ msg=audit(1623924437.847:227): pid=1805 uid=0 auid=1000 ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=PAM:setcred grantors=pam_unix acct="jiri" exe="/usr/sbin/sshd" hostname=t14s.home.arpa addr=192.168.122.1 terminal=ssh res=success'

# record of user logging in
type=USER_LOGIN msg=audit(1623924437.853:228): pid=1801 uid=0 auid=1000 ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=t14s.home.arpa addr=192.168.122.1 terminal=/dev/pts/1 res=success'

# record of user-space session start
type=USER_START msg=audit(1623924437.853:229): pid=1801 uid=0 auid=1000 ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=t14s.home.arpa addr=192.168.122.1 terminal=/dev/pts/1 res=success'
```

#### logging out

``` shell
# record about crypto key identifier used for crypto purposes
type=CRYPTO_KEY_USER msg=audit(1623924437.857:230): pid=1801 uid=0 auid=1000 ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=destroy kind=server fp=SHA256:63:42:8b:7b:d5:ff:b1:e2:91:09:51:8d:35:dd:79:7a:0a:29:b0:5e:86:90:1e:17:f1:c8:dc:f9:fc:e6:cc:3d direction=? spid=1806 suid=1000  exe="/usr/sbin/sshd" hostname=? addr=? terminal=? res=success'

# record of user-space session termination
type=USER_END msg=audit(1623924440.127:231): pid=1801 uid=0 auid=1000 ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=? addr=? terminal=/dev/pts/1 res=success'
type=USER_LOGOUT msg=audit(1623924440.127:232): pid=1801 uid=0 auid=1000 ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=? addr=? terminal=/dev/pts/1 res=success'

# record about crypto key identifier used for crypto purposes
type=CRYPTO_KEY_USER msg=audit(1623924440.129:233): pid=1801 uid=0 auid=1000 ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=destroy kind=server fp=SHA256:63:42:8b:7b:d5:ff:b1:e2:91:09:51:8d:35:dd:79:7a:0a:29:b0:5e:86:90:1e:17:f1:c8:dc:f9:fc:e6:cc:3d direction=? spid=1805 suid=1000  exe="/usr/sbin/sshd" hostname=? addr=? terminal=? res=success'
type=CRYPTO_KEY_USER msg=audit(1623924440.129:234): pid=1801 uid=0 auid=1000 ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=destroy kind=session fp=? direction=both spid=1805 suid=1000 rport=44796 laddr=192.168.122.104 lport=22  exe="/usr/sbin/sshd" hostname=? addr=192.168.122.1 terminal=? res=success'

# [PAM] record of user-space session termination
type=USER_END msg=audit(1623924440.133:235): pid=1801 uid=0 auid=1000 ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=PAM:session_close grantors=pam_selinux,pam_loginuid,pam_selinux,pam_namespace,pam_keyinit,pam_keyinit,pam_limits,pam_systemd,pam_mkhomedir,pam_unix,pam_ldap,pam_lastlog acct="jiri" exe="/usr/sbin/sshd" hostname=t14s.home.arpa addr=192.168.122.1 terminal=ssh res=success'

# record of user user-space credentials disposal (clearing them)
type=CRED_DISP msg=audit(1623924440.133:236): pid=1801 uid=0 auid=1000 ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=PAM:setcred grantors=pam_unix acct="jiri" exe="/usr/sbin/sshd" hostname=t14s.home.arpa addr=192.168.122.1 terminal=ssh res=success'

# record about crypto key identifier used for crypto purposes
type=CRYPTO_KEY_USER msg=audit(1623924440.133:237): pid=1801 uid=0 auid=1000 ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=destroy kind=server fp=SHA256:94:e4:42:14:aa:4a:cf:01:4a:44:d8:b0:82:32:32:a8:6e:3d:64:91:ba:22:b1:8d:7c:b4:a2:26:9a:91:65:42 direction=? spid=1801 suid=0  exe="/usr/sbin/sshd" hostname=? addr=? terminal=? res=success'
type=CRYPTO_KEY_USER msg=audit(1623924440.133:238): pid=1801 uid=0 auid=1000 ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=destroy kind=server fp=SHA256:53:5b:b8:5f:92:65:1c:6b:fc:69:28:8b:26:42:c6:58:fa:63:76:43:43:d4:4c:cd:81:1b:cc:52:c6:02:77:fc direction=? spid=1801 suid=0  exe="/usr/sbin/sshd" hostname=? addr=? terminal=? res=success'
type=CRYPTO_KEY_USER msg=audit(1623924440.133:239): pid=1801 uid=0 auid=1000 ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=destroy kind=server fp=SHA256:63:42:8b:7b:d5:ff:b1:e2:91:09:51:8d:35:dd:79:7a:0a:29:b0:5e:86:90:1e:17:f1:c8:dc:f9:fc:e6:cc:3d direction=? spid=1801 suid=0  exe="/usr/sbin/sshd" hostname=? addr=? terminal=? res=success'
```

### tls / ssl

#### openssl

a simple https webserver

``` shell
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 365 -nodes                                               # generate
openssl s_server -key key.pem -cert cert.pem -accept 44330 -www \
  -no_ssl2 -no_ssl3 -tls1_2                                      # tls1.2
```

list certs data in ca bundle

``` shell
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/ca-bundle.pem | \
  openssl pkcs7 -print_certs -text -noout | \
  grep -Po '\K(Subject:.*)'                                   # get all subjects
```

## schedulers

### cron

#### random delay for a job

``` shell
man 5 crontab | sed -n '/RANDOM_DELAY/,/^$/p' | fmt -w80
       The RANDOM_DELAY variable allows delaying job startups by random
       amount of minutes with upper limit specified by the variable. The
       random scaling factor is determined during the cron daemon startup
       so it remains constant for the whole run time of the daemon.
```

``` shell
# system crontab file, see escaped '%' !!!
@daily <username> sleep $(($RANDOM \% 3600 )) && <some command>
```

## shell

``` shell
echo one two three | xargs -n1 # multiple columns into one

```

### sed

print range between patterns, include first pattern but not the last
one

``` shell
sed -n '/<patten1>/,/<pattern2>/{/<pattern2>/!p}' <file>

# an example
sed -rn '/^3600507680c8101344000000000069169 dm-[[:digit:]]+/,/^36/{/^36/!p}' mpio.txt
size=212G features='1 queue_if_no_path' hwhandler='1 alua' wp=rw
|-+- policy='service-time 0' prio=50 status=active
| |- 1:0:0:5  sdf  8:80   active ready running
| |- 2:0:0:5  sdy  65:128 active ready running
| |- 3:0:0:5  sdaw 67:0   active ready running
| `- 4:0:0:5  sdbv 68:144 active ready running
`-+- policy='service-time 0' prio=10 status=enabled
  |- 1:0:1:5  sdu  65:64  active ready running
  |- 2:0:1:5  sdap 66:144 active ready running
  |- 3:0:1:5  sdbk 67:224 active ready running
  `- 4:0:1:5  sdch 69:80  active ready running
```

## troubleshooting

### reboot / shutdown

TODO: needs clarification!

``` shell
# graceful shutdown includes 'shutdown' pseudo user
reboot   system boot  4.18.0-80.el8.x8 Mon Aug 31 06:33:11 2020   still running
shutdown system down  4.18.0-80.el8.x8 Mon Aug 31 06:33:01 2020 - Mon Aug 31 06:33:11 2020  (00:00)
```

``` shell
# ungraceful shutdown has only 'reboot' pseudo user
reboot   system boot  4.18.0-147.5.1.e Tue Sep  1 07:16:25 2020   still running
reboot   system boot  4.18.0-147.5.1.e Mon Aug  3 07:10:56 2020   still running
```

### validate LACP on switch

``` shell
# TODO: review
tshark -i <bonded_iface> -c 1 -f "ether proto 0x88cc" -Y "lldp" -O lldp
...
        Chassis Id: JuniperN_cb:d6:80 (f8:c0:01:cb:d6:80)
        Port Id: 757
        System Name = rack10-sw03-lab.brq
    System Description = Juniper Networks, Inc. ex4200-48t , version 12.3R6.6 Build date: 2014-03-13 08:38:30 UTC
    Port Description = ge-1/0/6.0
        0000 100. .... .... = TLV Type: Port Description (4)
        .... ...0 0000 1010 = TLV Length: 10
        Port Description: ge-1/0/6.0
    IEEE 802.3 - Link Aggregation
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1001 = TLV Length: 9
        Organization Unique Code: IEEE 802.3 (0x00120f)
        IEEE 802.3 Subtype: Link Aggregation (0x03)
        Aggregation Status: 0x01
            .... ...1 = Aggregation Capability: Yes
            .... ..0. = Aggregation Status: Disabled
        Aggregated Port Id: 0
```

## virtualization

### qemu

``` shell
qemu-nbd --connect=/dev/nbd0 <qemu_image> # connect eg. a qcow2 image
qemu-nbd -d /dev/nbd0
```

### libvirt

#### dnsmasq enabled network

to extend dnsmasq features network schema and 'dnsmasq:options'
element need to be added

``` shell
<network xmlns:dnsmasq='http://libvirt.org/schemas/network/dnsmasq/1.0'>
  <name>default</name>
  <uuid>b790885f-7f0f-49eb-9009-79ae4318077f</uuid>
  <forward mode='nat'>
    <nat>
      <port start='1024' end='65535'/>
    </nat>
  </forward>
  <bridge name='virbr0' stp='on' delay='0'/>
  <mac address='52:54:00:df:e2:6c'/>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.122.2' end='192.168.122.254'/>
    </dhcp>
  </ip>
  <dnsmasq:options>
    <dnsmasq:option value='log-dhcp'/>
    <dnsmasq:option value='dhcp-match=set:efi-x86_64,option:client-arch,7'/>
    <dnsmasq:option value='dhcp-match=set:i386-pc,option:client-arch,0'/>
    <dnsmasq:option value='dhcp-boot=tag:efi-x86_64,x86_64-efi/shim.efi'/>
    <dnsmasq:option value='dhcp-boot=tag:i386-pc,i386-pc/core.0'/>
  </dnsmasq:options>
</network>
```

#### virsh

``` shell
virsh vol-create-as <pool> <new_vol> <size>G --format <new_format> \
  --backing-vol <backing_vol> --backing-vol-format <old_format>      # create vol based on a template

virsh define <(virsh dumpxml <template> | \
  sed -e '/uuid/d' \
    -e 's/template/ha-01/g' \
    -e 's/\(52:54:00:64:3e\):16/\1:01/')     # create vm based on template vm
```

simulate [sysrq
keys](https://www.kernel.org/doc/html/latest/admin-guide/sysrq.html)

``` shell
virsh <domain> send-key 1 KEY_LEFTALT KEY_SYSRQ KEY_C # sysrq crash
```

#### virt-install

manual installation from CentOS mirror

``` shell
virt-install \
  --name centos7-01 \
  --memory 2048 --disk size=20,target.bus=scsi \
  --vcpus 2 \
  --os-variant centos7.0 \
  --location=http://mirror.slu.cz/centos/7/os/x86_64/
```

##### mpio

it seems libvirt allows multipath only on *raw* format disks, thus
keep that in mind; SLES sets mpio during installation.

```
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw' cache='none'/>
      <source file='<path>' index='2'/>
      <backingStore/>
      <target dev='sdb' bus='scsi'/>
      <shareable/>
      <serial>1234</serial>
      <wwn>5000c50015ea71ad</wwn>
      <boot order='1'/>
      <alias name='scsi0-0-0-1'/>
      <address type='drive' controller='0' bus='0' target='0' unit='1'/>
    </disk>
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw' cache='none'/>
      <source file='<path>' index='1'/>
      <backingStore/>
      <target dev='sdc' bus='scsi'/>
      <shareable/>
      <serial>1234</serial>
      <wwn>5000c50015ea71ad</wwn>
      <alias name='scsi0-0-0-2'/>
      <address type='drive' controller='0' bus='0' target='0' unit='2'/>
    </disk>
    <controller type='scsi' index='0' model='virtio-scsi'>
      <alias name='scsi0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x08' function='0x0'/>
    </controller>
```

and via "internal" iscsi driver

```
<disk type="network" device="lun">
      <driver name="qemu" type="raw" cache="none"/>
      <source protocol="iscsi" name="<target>/<lun>" index="2">
        <host name="<ip>" port="<port>"/>
      </source>
      <target dev="sdb" bus="scsi"/>
      <boot order="1"/>
      <alias name="scsi0-0-0-1"/>
      <address type="drive" controller="0" bus="0" target="0" unit="1"/>
    </disk>
<disk type="network" device="lun">
      <driver name="qemu" type="raw" cache="none"/>
      <source protocol="iscsi" name="<taget>/<lun>" index="1">
        <host name="<ip>" port="<port>"/>
      </source>
      <target dev="sdc" bus="scsi"/>
      <boot order="2"/>
      <alias name="scsi0-0-0-2"/>
      <address type="drive" controller="0" bus="0" target="0" unit="2"/>
    </disk>
```

#### troubleshooting

``` shell
env VIRSH_DEBUG=0 LIBVIRT_DEBUG=1 virsh # or any other libvirt tool
```

### openvswitch

``` shell
systemctl is-active openvswitch  # check if running
systemctl is-enabled openvswitch # check if enabled at boot
lsmod openvswitch                # kernel modules are in net/openvswitch
```

``` shell
ovs-vsctl add-br <name>
ovs-vsctl show

# TODO: SUSE
man ifcfg-ovs-bridge
```

``` shell
# TODO: networkmanager style

nmcli c add type ovs-bridge \
  conn.interface virtual0 con-name virtual0
nmcli c add type ovs-port \
  virtual0 master virtual0 con-name ovs-port-virtual0
nmcli c add type ovs-port \
  conn.interface virtual0 master virtual0 con-name ovs-port-virtual0 \
  conn.zone libvirt \
  ipv4.method manual ipv4.address <cidr> ipv6.method disabled
```

``` shell
# check/set igmp snooping
ovs-vsctl list bridge | grep mcast_snooping_enable
ovs-vsctl set bridge virtual0 mcast_snooping_enable=<value>
```
