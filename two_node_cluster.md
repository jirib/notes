# Two node cluster example

- iSCSI-based shared LUN for SBD fencing device
- fencing triggered via kernel's watchdog
- floating IP
- a fake service

## corosync

``` shell
corosync-keygen # create authkey on first node and distribute to others

# jinja template
cat > /tmp/corosync.j2 <<EOF
totem {
    version: 2
    secauth: on
    crypto_hash: sha256
    crypto_cipher: aes256
    cluster_name: {{ os.environ["cluster_name"] | default('hacluster') }}
    token: 5000
    token_retransmits_before_loss_const: 10
    join: 60
    consensus: 6000
    max_messages: 20
    interface {
        ringnumber: 0
        mcastport:   5405
        ttl: 1
    }
    transport: udpu
}
logging {
    fileline: off
    to_stderr: no
    to_logfile: no
    logfile: /var/log/cluster/corosync.log
    to_syslog: yes
    debug: off
    timestamp: on
    logger_subsys {
        subsys: QUORUM
        debug: off
    }
}
quorum {
    provider: corosync_votequorum
    two_node: 1
}
nodelist {
{%- for ip in os.environ["ips"].split() %}
    node {
        ring0_addr: {{ ip }}
        nodeid: {{ loop.index }}
    }
{%- endfor %}
}
EOF
pip3 install --user jinja2                # install jinja template system
```

``` shell
export ips=$(echo 192.168.122.{189..190}) # export ips env variable

# generate config and print to stdout
python3 -c 'import os; \
  import sys; \
  from jinja2 import Template; \
  data=sys.stdin.read(); \
  t = Template(data); \
  print(t.render(os=os))' < /tmp/envsubst.j2

# distribute config to both nodes!
```

``` shell
systemctl start corosync # on all nodes

corosync-cmapctl nodelist.node                    # list corosync nodes
corosync-cmapctl runtime.totem.pg.mrp.srp.members # list members and state

corosync-quorumtool -l # list nodes
corosync-quorumtool -s # show quorum status of corosync ring
```

## pacemaker

``` shell
systemctl start pacemaker # on all nodes
corosync-cpgtool          # see if pacemaker is known to corosync

crm_mon -1 # show cluster status
```

``` shell
cibadmin -Q -o nodes      # list nodes in pacemaker
cibadmin -Q -o crm_config # list cluster options configuration in pacemaker
crm_verify -LV            # check configuration used by cluster, verbose
                          # can show important info
```

## sbd-based fencing

### iscsi shared lun

``` shell
# using iSCSI shared lun

iscsiadm -m discovery -t st -p <portal>[:port]     # discover targets
iscsiadm -m node -T <target> -l                    # login to the target
```

tune *[iSCSI
timeouts](https://www.suse.com/c/implmenting-mpio-over-iscsi-considerations-common-issues-and-clustering-concerns/)*
for cluster

``` shell
iscsiadm -m node -T <target> -o update \
  -n node.session.timeo.replacement_timeout -v 5   # update replacement value
for i in node,conn[0].timeo.noop_out_{interval,timeout}; do
  iscsiadm -m node -T <target> -o update \
  -n ${i} -v 2                                     # update noop values
```

### sbd

``` shell
lsmod | egrep "(w|dog)"                            # check for watchdog kernel modules
modprobe softdog                                   # load kernel module
echo '<module> /etc/modules-load.d/watchdog.conf # add module to auto-load
systemctl restart systemd-modules-load             # ...
ls -l /dev/watchdog*                               # check watchdog devices

sed 's/^#*\(SBD_DEVICE\)=.*/\1="<shared_lun>"/' \
  /etc/sysconfig/sbd                               # device sbd device

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

crm configure primitive stonith-sbd stonith:external/sbd \
  params pcmk_delay_max=30                         # add fencing device resource,
                                                   # do not forget pcmk_delay_max force
                                                   # two node cluster!
crm configure property stonith-timeout=<value>     # stonith-timeout >= sbd's msgwait + 20%,
                                                   # only on resource, no cloning!
```

## floating ip and clustered service

``` shell
crm configure primitive p-<name> IPaddr2 \
  params ip=<floating_ip> nic=<iface>          # add floating IP resource binded to <iface>
crm configure primitive p-<name> Dummy         # a fake service resource
crm configure group g-<name> p-<name> p-<name> # group IP and service into resource group
```
