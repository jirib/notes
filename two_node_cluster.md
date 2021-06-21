# Two node cluster example

- unicast corosync communication
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

## scenarios

### both nodes die, only one node boots and should start resources

- both are unclean, resources not started because there's no quorum
- in *two_node* mode, *wait_for_all* is enabled by default so there's
  no split brain
```
Jun 09 13:46:07 sle15sp2-ha-01 corosync[1990]:   [TOTEM ] adding new UDPU member {192.168.122.189}
Jun 09 13:46:07 sle15sp2-ha-01 corosync[1990]:   [TOTEM ] adding new UDPU member {192.168.122.190}
Jun 09 13:46:07 sle15sp2-ha-01 corosync[1990]:   [TOTEM ] A new membership (192.168.122.189:256) was formed. Members joined: 1
Jun 09 13:46:07 sle15sp2-ha-01 corosync[1990]:   [VOTEQ ] Waiting for all cluster members. Current votes: 1 expected_votes: 2
Jun 09 13:46:07 sle15sp2-ha-01 corosync[1990]:   [CPG   ] downlist left_list: 0 received
Jun 09 13:46:07 sle15sp2-ha-01 corosync[1990]:   [VOTEQ ] Waiting for all cluster members. Current votes: 1 expected_votes: 2
Jun 09 13:46:07 sle15sp2-ha-01 corosync[1990]:   [VOTEQ ] Waiting for all cluster members. Current votes: 1 expected_votes: 2
Jun 09 13:46:07 sle15sp2-ha-01 corosync[1990]:   [QUORUM] Members[1]: 1
Jun 09 13:46:07 sle15sp2-ha-01 corosync[1990]:   [MAIN  ] Completed service synchronization, ready to provide service.
Jun 09 13:46:07 sle15sp2-ha-01 corosync[1972]: Starting Corosync Cluster Engine (corosync): [  OK  ]
```
- clearing state of other node (down one) - `crm node clearstate <node2>`
``` shell
Jun 09 13:46:09 sle15sp2-ha-01 pacemaker-attrd[2006]:  notice: Pacemaker node attribute manager successfully started and accepting connections
Jun 09 13:46:09 sle15sp2-ha-01 pacemaker-attrd[2006]:  notice: Setting #attrd-protocol[sle15sp2-ha-01]: (unset) -> 2
Jun 09 13:46:09 sle15sp2-ha-01 pacemaker-attrd[2006]:  notice: Recorded local node as attribute writer (was unset)
```
- still alive node does not have quorum (in *two_node* mode
  *expected_votes* is *2* and *wait_for_all* is still active)
``` shell
Jun 09 13:46:09 sle15sp2-ha-01 pacemaker-controld[2008]:  warning: Quorum lost
Jun 09 13:46:09 sle15sp2-ha-01 pacemaker-controld[2008]:  notice: Node sle15sp2-ha-01 state is now member
Jun 09 13:46:09 sle15sp2-ha-01 pacemaker-controld[2008]:  notice: Pacemaker controller successfully started and accepting connections
Jun 09 13:46:09 sle15sp2-ha-01 pacemaker-controld[2008]:  notice: State transition S_STARTING -> S_PENDING
Jun 09 13:46:10 sle15sp2-ha-01 pacemaker-controld[2008]:  notice: Fencer successfully connected
Jun 09 13:46:30 sle15sp2-ha-01 pacemaker-controld[2008]:  warning: Input I_DC_TIMEOUT received in state S_PENDING from crm_timer_popped
Jun 09 13:46:30 sle15sp2-ha-01 pacemaker-controld[2008]:  notice: State transition S_ELECTION -> S_INTEGRATION
Jun 09 13:46:30 sle15sp2-ha-01 pacemaker-controld[2008]:  notice: Updating quorum status to false (call=22)
```
- let's make active node quorable via `corosync-quorumtool -e 1` (see
  `corosync-quorumtool -s` before to understand what would happen)
``` shell
Jun 09 13:47:12 sle15sp2-ha-01 corosync[1990]:   [QUORUM] This node is within the primary component and will provide service.
Jun 09 13:47:12 sle15sp2-ha-01 corosync[1990]:   [QUORUM] Members[1]: 1
```
- active node is quorable now, starts resources
- starting other node (down one) would add node into the cluster as
  member and update quorum *votes*)
``` shell
2021-06-09T14:09:02.405132+02:00 sle15sp2-ha-01 corosync[1990]:   [TOTEM ] A new membership (192.168.122.189:260) was formed. Members joined: 2
2021-06-09T14:09:02.409119+02:00 sle15sp2-ha-01 corosync[1990]:   [CPG   ] downlist left_list: 0 received
2021-06-09T14:09:02.409803+02:00 sle15sp2-ha-01 corosync[1990]:   [CPG   ] downlist left_list: 0 received
2021-06-09T14:09:02.410526+02:00 sle15sp2-ha-01 corosync[1990]:   [QUORUM] Members[2]: 1 2
2021-06-09T14:09:02.410841+02:00 sle15sp2-ha-01 corosync[1990]:   [MAIN  ] Completed service synchronization, ready to provide service.
```
- WTF did it *move*?
``` shell
2021-06-09T14:09:04.424772+02:00 sle15sp2-ha-01 pacemaker-attrd[2006]:  notice: Setting #attrd-protocol[sle15sp2-ha-02]: (unset) -> 2
2021-06-09T14:09:05.468468+02:00 sle15sp2-ha-01 pacemaker-controld[2008]:  notice: State transition S_IDLE -> S_INTEGRATION
2021-06-09T14:09:05.483417+02:00 sle15sp2-ha-01 pacemaker-controld[2008]:  notice: Updating quorum status to true (call=68)
2021-06-09T14:09:05.485886+02:00 sle15sp2-ha-01 hawk-apiserver[1556]: level=info msg="[CIB]: 2:70:24"
2021-06-09T14:09:05.489050+02:00 sle15sp2-ha-01 hawk-apiserver[1556]: level=info msg="[CIB]: 2:70:25"
2021-06-09T14:09:05.492801+02:00 sle15sp2-ha-01 hawk-apiserver[1556]: message repeated 2 times: [ level=info msg="[CIB]: 2:70:25"]
2021-06-09T14:09:06.488531+02:00 sle15sp2-ha-01 pacemaker-schedulerd[2007]:  notice: Watchdog will be used via SBD if fencing is required and stonith-watchdog-timeout is nonzero
2021-06-09T14:09:06.488682+02:00 sle15sp2-ha-01 pacemaker-schedulerd[2007]:  notice:  * Move       p-IP_254        ( sle15sp2-ha-01 -> sle15sp2-ha-02 )
2021-06-09T14:09:06.488741+02:00 sle15sp2-ha-01 pacemaker-schedulerd[2007]:  notice:  * Move       p-Dummy         ( sle15sp2-ha-01 -> sle15sp2-ha-02 )
2021-06-09T14:09:06.488793+02:00 sle15sp2-ha-01 pacemaker-schedulerd[2007]:  notice: Calculated transition 4, saving inputs in /var/lib/pacemaker/pengine/pe-input-58.bz2
```
