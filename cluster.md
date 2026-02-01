# Clusters cheatsheet


## Pacemaker/corosync


### Pacemaker/corosync terminology

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

- *promote* resource action - promotes a resource from a slave resource to a master one
- *demote* resource action - demotes a resource from a master resource to a slave one


### Pacemaker/corosync architecture

- *corosync* - messaging and membership layer (can replicate data across
  cluster?)
- *CRM* - `crmd`/`pacemaker-controld`, cluster resource manager, CRM,
  part of resource allocation layer, `crmd` is main process; maintains
  a consistent view of the cluster membership and orchestrates all the
  other components
- *CIB* - `cib`/`pacemaker-based`, cluster information base,
  configuration, current status, synchronized the CIB across the
  cluster and handles requests to modify it pacemaker, part of
  resource allocation layer; shared copy of state, versioned
- *DC* - designated controller, in-memory state, member managing the master
  copy of the *CIB*, so-called master node, communicate changes of the CIB copy
  to other nodes via CRM
- *PE* - `pegnine`/`pacemaker-schedulerd`, policy engine, running on
  DC, the brain of the cluster; the scheduler determines which actions
  are necessary to achieve the desired state of the cluster; the input
  is a snapshot of the CIB monitors CIB and calculates changes
  required to align with desired state, informs CRM
- *LRM* - `lrm`/`pacemaker-exec`, local resource manager, instructed from CRM
  what to do, local executor
- *RA* - resource agent, logic to start/stop/monitor a resource,
  called from LRM and return values are passed to the CRM, ideally
  OCF, LSB, systemd service units or STONITH
- *OCF* - open cluster framework, standardized resource agents
- *STONITH* - "shoot the other node in the head", fencing resource
  agent, eg. via IPMI…
- *DLM* - distributed lock manager, cluster wide locking (`ocf:pacemaker:controld`)
- *CLVM* - cluster logical volume manager, `lvmlockd`, protects LVM
  metadata on shared storage
- *pacemaker-attrd* - attribute manager, maintains a database of
  attributes for all the cluster nodes; the attributes are
  synchronized across the cluster; the attributes are *usually*
  recorded in the CIB (ie. not all!)


### Pacemaker/corosync maintenances

- maintenance/standby does not make corosync ring detection
  *ineffective*! That is, node can be fenced even if it is in maintenance!
- OS shutdown/reboot can cause a resource to be killed if it runs in *user
  slice* (eg. SAP or old Oracle DB)!
- *maintenances* do NOT run monitor operation thus `crm_mon` output does not
  need to show reality!

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

Best practice:

1. standby
2. stop cluster services (this includes *corosync*)


### Pacemaker fencing

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


### Corosync

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
  It usually does NOT work in clouds.
- *unicast*, usually better; clouds needs higher token (eg. 30000) and
  consensus (eg. 36000); see [Corosync Communication
  Failure](https://www.suse.com/support/kb/doc/?id=000020407)

**NOTE:**
- corosync time values is in miliseconds!
- `token`: 5000 (ms) = 5s timeout
- `token_retransmits_before_loss_consts`: 10 - means how many instances of token
  to send in token timeout interval
- corosync ports note, see also a general ports as defined in [RH
  docs](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/high_availability_add-on_reference/s1-firewalls-haar#tb-portenable-HAAR)
  or see *firewalld* [`high-availability.xml`](https://github.com/firewalld/firewalld/blob/master/config/services/high-availability.xml)
  (note mostly RH specific!)
  ``` shell
  $ man corosync.conf | col -b | sed -n '/^ *mcastport/,/^ *$/{/^ *$/q; p}' | fmt -w72
       mcastport
              This specifies the UDP port number.  It is possible to
              use the same multicast address on a network with the
              corosync services configured for different UDP ports.
              Please note corosync uses two UDP ports mcastport  (for
              mcast receives) and mcastport - 1 (for mcast sends).
              If you have multiple clusters on the same network using
              the same mcastaddr please configure the mcastports with
              a gap.
  ```

How corosync communication work:

1. communication is oneway to establish stable communication ring via "protocol"
   [*corosync_totemnet*](https://www.wireshark.org/docs/dfref/c/corosync_totemnet.html)

   a node sends instances of token based on
   *token_retransmits_before_loss_consts* value to next node and expects return
   from the last node in *token* timeout value

   a three node scenario:

   - node1 sends instances of token to node2 and expects at least one token from
     node3 to return

   - once communication is stable - token passed from the source back to it via
     last node - the node which sent the original token can send messages to all
     other nodes in the already established stable token ring

   - if ring is broken, eg. node1 -> node2 communication error, node1 is the
     first one who detects split brain (*timeout* value)

2. once communiation ring is stable - token passed from the source back to it,
   a node with token can send messages (messages value which should fit to UDP
   datagram) to communicate directly to all nodes in the stable token ring


``` shell
corosync-cmapctl nodelist.node                    # list corosync nodes
corosync-cmapctl runtime.totem.pg.mrp.srp.members # list members and state
corosync-cmapctl runtime.votequorum               # runtime info about quorum

corosync-quorumtool -l          # list nodes
corosync-quorumtool -s          # show quorum status of corosync ring
corosync-quorumtool -e <number> # change number of extected votes

corosync-cfgtool -R # tell all nodes to reload corosync config
```

#### corosync logs

`corosync` logs after start:

``` shell
Feb 01 11:16:53 s153cl01 systemd[1]: Starting Corosync Cluster Engine...
Feb 01 11:16:53 s153cl01 corosync[8725]:   [MAIN  ] Corosync Cluster Engine ('2.4.5'): started and ready to provide service.
Feb 01 11:16:53 s153cl01 corosync[8725]:   [MAIN  ] Corosync built-in features: testagents systemd qdevices qnetd pie relro bindnow
Feb 01 11:16:53 s153cl01 corosync[8730]:   [TOTEM ] Initializing transport (UDP/IP Unicast).
Feb 01 11:16:53 s153cl01 corosync[8730]:   [TOTEM ] Initializing transmit/receive security (NSS) crypto: aes256 hash: sha1
Feb 01 11:16:53 s153cl01 corosync[8730]:   [TOTEM ] The network interface [192.168.123.189] is now up.
Feb 01 11:16:53 s153cl01 corosync[8730]:   [SERV  ] Service engine loaded: corosync configuration map access [0]
Feb 01 11:16:53 s153cl01 corosync[8730]:   [QB    ] server name: cmap
Feb 01 11:16:53 s153cl01 corosync[8730]:   [SERV  ] Service engine loaded: corosync configuration service [1]
Feb 01 11:16:53 s153cl01 corosync[8730]:   [QB    ] server name: cfg
Feb 01 11:16:53 s153cl01 corosync[8730]:   [SERV  ] Service engine loaded: corosync cluster closed process group service v1.01 [2]
Feb 01 11:16:53 s153cl01 corosync[8730]:   [QB    ] server name: cpg
Feb 01 11:16:53 s153cl01 corosync[8730]:   [SERV  ] Service engine loaded: corosync profile loading service [4]
Feb 01 11:16:53 s153cl01 corosync[8730]:   [QUORUM] Using quorum provider corosync_votequorum
Feb 01 11:16:53 s153cl01 corosync[8730]:   [VOTEQ ] Waiting for all cluster members. Current votes: 1 expected_votes: 2
Feb 01 11:16:53 s153cl01 corosync[8730]:   [SERV  ] Service engine loaded: corosync vote quorum service v1.0 [5]
Feb 01 11:16:53 s153cl01 corosync[8730]:   [QB    ] server name: votequorum
Feb 01 11:16:53 s153cl01 corosync[8730]:   [SERV  ] Service engine loaded: corosync cluster quorum service v0.1 [3]
Feb 01 11:16:53 s153cl01 corosync[8730]:   [QB    ] server name: quorum
Feb 01 11:16:53 s153cl01 corosync[8730]:   [TOTEM ] adding new UDPU member {192.168.123.189}
Feb 01 11:16:53 s153cl01 corosync[8730]:   [TOTEM ] adding new UDPU member {192.168.123.192}
Feb 01 11:16:53 s153cl01 corosync[8730]:   [TOTEM ] A new membership (192.168.123.189:76) was formed. Members joined: 1084783549
Feb 01 11:16:53 s153cl01 corosync[8730]:   [VOTEQ ] Waiting for all cluster members. Current votes: 1 expected_votes: 2
Feb 01 11:16:53 s153cl01 corosync[8730]:   [CPG   ] downlist left_list: 0 received
Feb 01 11:16:53 s153cl01 corosync[8730]:   [VOTEQ ] Waiting for all cluster members. Current votes: 1 expected_votes: 2
Feb 01 11:16:53 s153cl01 corosync[8730]:   [VOTEQ ] Waiting for all cluster members. Current votes: 1 expected_votes: 2
Feb 01 11:16:53 s153cl01 corosync[8730]:   [QUORUM] Members[1]: 1084783549
Feb 01 11:16:53 s153cl01 corosync[8730]:   [MAIN  ] Completed service synchronization, ready to provide service.
Feb 01 11:16:53 s153cl01 corosync[8715]: Starting Corosync Cluster Engine (corosync): [  OK  ]
```

`corosync` knows about two members but only *nodeid* *1084783549* joins for now.
This corresponds to (see there's no quorum in this two node cluster!):

``` shell
$ corosync-cmapctl | grep member
runtime.totem.pg.mrp.srp.members.1084783549.config_version (u64) = 0
runtime.totem.pg.mrp.srp.members.1084783549.ip (str) = r(0) ip(192.168.123.189)
runtime.totem.pg.mrp.srp.members.1084783549.join_count (u32) = 1
runtime.totem.pg.mrp.srp.members.1084783549.status (str) = joined

$ corosync-cpgtool -e
Group Name             PID         Node ID
crmd
                      9126      1084783549 (192.168.123.189)
attrd
                      9124      1084783549 (192.168.123.189)
stonith-ng
                      9122      1084783549 (192.168.123.189)
cib
                      9121      1084783549 (192.168.123.189)
sbd:cluster
                      9100      1084783549 (192.168.123.189)

$ corosync-quorumtool -s
Quorum information
------------------
Date:             Tue Feb  1 11:43:29 2022
Quorum provider:  corosync_votequorum
Nodes:            1
Node ID:          1084783549
Ring ID:          1084783549/112
Quorate:          No

Votequorum information
----------------------
Expected votes:   2
Highest expected: 2
Total votes:      1
Quorum:           1 Activity blocked
Flags:            2Node WaitForAll

Membership information
----------------------
    Nodeid      Votes Name
1084783549          1 s153cl01.cl0.example.com (local)
```

When other corosync node joins the following is logged (see quorum was reached
in this two node cluster!):

```
Feb 01 11:24:05 s153cl01 corosync[8730]:   [TOTEM ] A new membership (192.168.123.189:84) was formed. Members joined: 1084783552
Feb 01 11:24:05 s153cl01 corosync[8730]:   [CPG   ] downlist left_list: 0 received
Feb 01 11:24:05 s153cl01 corosync[8730]:   [CPG   ] downlist left_list: 0 received
Feb 01 11:24:05 s153cl01 corosync[8730]:   [QUORUM] This node is within the primary component and will provide service.
Feb 01 11:24:05 s153cl01 corosync[8730]:   [QUORUM] Members[2]: 1084783549 1084783552
Feb 01 11:24:05 s153cl01 corosync[8730]:   [MAIN  ] Completed service synchronization, ready to provide service.
```

And `corosync-cmapctl` would show:

``` shell
$ corosync-cmapctl | grep member
runtime.totem.pg.mrp.srp.members.1084783549.config_version (u64) = 0
runtime.totem.pg.mrp.srp.members.1084783549.ip (str) = r(0) ip(192.168.123.189)
runtime.totem.pg.mrp.srp.members.1084783549.join_count (u32) = 1
runtime.totem.pg.mrp.srp.members.1084783549.status (str) = joined
runtime.totem.pg.mrp.srp.members.1084783552.config_version (u64) = 0
runtime.totem.pg.mrp.srp.members.1084783552.ip (str) = r(0) ip(192.168.123.192)
runtime.totem.pg.mrp.srp.members.1084783552.join_count (u32) = 1
runtime.totem.pg.mrp.srp.members.1084783552.status (str) = joined

$ corosync-cpgtool -e
Group Name             PID         Node ID
crmd
                      9126      1084783549 (192.168.123.189)
                      4320      1084783552 (192.168.123.192)
attrd
                      9124      1084783549 (192.168.123.189)
                      4318      1084783552 (192.168.123.192)
stonith-ng
                      9122      1084783549 (192.168.123.189)
                      4316      1084783552 (192.168.123.192)
cib
                      9121      1084783549 (192.168.123.189)
                      4315      1084783552 (192.168.123.192)
sbd:cluster
                      9100      1084783549 (192.168.123.189)
                      4292      1084783552 (192.168.123.192)

$ corosync-quorumtool -s
Quorum information
------------------
Date:             Tue Feb  1 11:45:15 2022
Quorum provider:  corosync_votequorum
Nodes:            2
Node ID:          1084783549
Ring ID:          1084783549/116
Quorate:          Yes

Votequorum information
----------------------
Expected votes:   2
Highest expected: 2
Total votes:      2
Quorum:           1
Flags:            2Node Quorate WaitForAll

Membership information
----------------------
    Nodeid      Votes Name
1084783549          1 s153cl01.cl0.example.com (local)
1084783552          1 s153cl02.cl0.example.com
```

When a node leaves... (note "leaves", ie. not disappears!)

```
Feb 01 11:35:06 s153cl01 corosync[9101]:   [TOTEM ] A new membership (192.168.123.189:100) was formed. Members left: 1084783552
Feb 01 11:35:06 s153cl01 corosync[9101]:   [CPG   ] downlist left_list: 1 received
Feb 01 11:35:06 s153cl01 corosync[9101]:   [QUORUM] Members[1]: 1084783549
Feb 01 11:35:06 s153cl01 corosync[9101]:   [MAIN  ] Completed service synchronization, ready to provide service.
```

And `corosync-cmapctl` would show:

``` shell
$ corosync-cmapctl | grep member
runtime.totem.pg.mrp.srp.members.1084783549.config_version (u64) = 0
runtime.totem.pg.mrp.srp.members.1084783549.ip (str) = r(0) ip(192.168.123.189)
runtime.totem.pg.mrp.srp.members.1084783549.join_count (u32) = 1
runtime.totem.pg.mrp.srp.members.1084783549.status (str) = joined
runtime.totem.pg.mrp.srp.members.1084783552.config_version (u64) = 0
runtime.totem.pg.mrp.srp.members.1084783552.ip (str) = r(0) ip(192.168.123.192)
runtime.totem.pg.mrp.srp.members.1084783552.join_count (u32) = 1
runtime.totem.pg.mrp.srp.members.1084783552.status (str) = left
```

And when a node or nodes disappear...

``` shell
2022-04-04T19:51:10.069944+01:00 T3PRPDB011 corosync[28003]:   [TOTEM ] A processor failed, forming new configuration.
2022-04-04T19:51:16.081236+01:00 T3PRPDB011 corosync[28003]:   [TOTEM ] A new membership (10.121.239.29:2016) was formed. Members left: 1 2
2022-04-04T19:51:16.081489+01:00 T3PRPDB011 corosync[28003]:   [TOTEM ] Failed to receive the leave message. failed: 1 2
2022-04-04T19:51:16.081685+01:00 T3PRPDB011 corosync[28003]:   [QUORUM] This node is within the non-primary component and will NOT provide any services.
2022-04-04T19:51:16.081846+01:00 T3PRPDB011 corosync[28003]:   [QUORUM] Members[1]: 3
2022-04-04T19:51:35.842885+01:00 T3PRPDB011 corosync[28003]:   [TOTEM ] A new membership (10.121.239.29:2020) was formed. Members
2022-04-04T19:51:35.843290+01:00 T3PRPDB011 corosync[28003]:   [QUORUM] Members[1]: 3
2022-04-04T19:51:42.061348+01:00 T3PRPDB011 corosync[28003]:   [TOTEM ] A new membership (10.121.239.29:2024) was formed. Members
2022-04-04T19:51:42.061638+01:00 T3PRPDB011 corosync[28003]:   [QUORUM] Members[1]: 3
2022-04-04T19:51:52.384522+01:00 T3PRPDB011 corosync[28003]:   [TOTEM ] A new membership (10.121.239.29:2028) was formed. Members
2022-04-04T19:51:52.385047+01:00 T3PRPDB011 corosync[28003]:   [QUORUM] Members[1]: 3
2022-04-04T19:51:59.892504+01:00 T3PRPDB011 corosync[28003]:   [TOTEM ] A new membership (10.121.239.29:2032) was formed. Members
2022-04-04T19:51:59.892889+01:00 T3PRPDB011 corosync[28003]:   [QUORUM] Members[1]: 3
2022-04-04T19:52:06.783170+01:00 T3PRPDB011 corosync[28003]:   [TOTEM ] A new membership (10.121.239.29:2036) was formed. Members
2022-04-04T19:52:06.783665+01:00 T3PRPDB011 corosync[28003]:   [QUORUM] Members[1]: 3
2022-04-04T19:52:18.403755+01:00 T3PRPDB011 corosync[28003]:   [TOTEM ] A new membership (10.121.239.29:2040) was formed. Members
2022-04-04T19:52:18.404132+01:00 T3PRPDB011 corosync[28003]:   [QUORUM] Members[1]: 3
2022-04-04T19:52:24.515971+01:00 T3PRPDB011 corosync[28003]:   [TOTEM ] A new membership (10.121.239.29:2044) was formed. Members
2022-04-04T19:52:24.516287+01:00 T3PRPDB011 corosync[28003]:   [QUORUM] Members[1]: 3
```

A non-tuned corosync in virtualized environment could be detected this way:

``` shell
2023-04-11T16:07:28.761850+02:00 node2 corosync[38932]: [MAIN ] Corosync main process was not scheduled (@1681222048760) for 7917.4106 ms (threshold is 800.0000 ms). Consider token timeout increase.

```

The above line demonstrates:
- that token is: 1000ms
- 80 % of the token timeout reached should be *max scheduling timeout*

During *Live partition migration* (Power) or *vMotion* (VMware) a
short pause of the LPAR/VM occurs, so final memory changes could be
migrated; this may have an impact of the LPAR/VM applications, namely
HA stack. There is no other way how the "migration" could work
considering both hosts do not share memory as one big hardware system.

See [](https://www.suse.com/support/kb/doc/?id=000019795) or how
[`corosync.conf`](https://learn.microsoft.com/en-us/azure/sap/workloads/high-availability-guide-suse-pacemaker)
looks like in Azure documentation.


*corosync* can be also observed on network layer (although there's probably
and [issue](https://bugzilla.suse.com/show_bug.cgi?id=1195394)):

``` shell
$ tshark -r corosync-totemsrp--noencypted--2nodes.pcap \
  -O corosync_totemnet,corosync_totemsrp \
  -Y 'corosync_totemsrp.message_header.type==3' | \
    sed -n '/^Frame/,/^ *$/{/^ *$/q;p}'
Frame 540: 200 bytes on wire (1600 bits), 200 bytes captured (1600 bits)
Linux cooked capture v1
Internet Protocol Version 4, Src: 192.168.0.101, Dst: 239.192.104.1
User Datagram Protocol, Src Port: 5149, Dst Port: 5405
Totem Single Ring Protocol implemented in Corosync Cluster Engine
    Type: join message (3)
    Encapsulated: not mcast message (0)
    Endian detector: 0xff22
    Node ID: 2
    Membership join message (nprocs: 2 nfailed: 0)
        Single Ring Protocol Address (node: 2)
            Node IP address (interface: 0; node: 2)
                Node ID: 2
                Address family: AF_INET (2)
                Address: 192.168.0.101
                Address padding: 08000200c0a8006508000400
            Node IP address (interface: 1; node: 0)
                Node ID: 0
                Address family: Unknown (0)
                Address: 00000000000000000000000000000000
        The number of processor list entries: 2
            Single Ring Protocol Address (node: 2)
                Node IP address (interface: 0; node: 2)
                    Node ID: 2
                    Address family: AF_INET (2)
                    Address: 192.168.0.101
                    Address padding: 08000200c0a8006508000400
                Node IP address (interface: 1; node: 0)
                    Node ID: 0
                    Address family: Unknown (0)
                    Address: 00000000000000000000000000000000
            Single Ring Protocol Address (node: 1)
                Node IP address (interface: 0; node: 1)
                    Node ID: 1
                    Address family: AF_INET (2)
                    Address: 192.168.0.102
                    Address padding: 08000200c0a8006608000400
                Node IP address (interface: 1; node: 0)
                    Node ID: 0
                    Address family: Unknown (0)
                    Address: 00000000000000000000000000000000
        The number of failed list entries: 0
        Ring sequence number: 56
```


#### corosync-qdevice

A "client" of `corosync-qnetd`; even its configuration is in `/etc/corosync/corosync.conf`,
it runs as a separate daemon, thus it has to be started/enabled:

``` shell
$  sed -n '/^quorum/,$p' /etc/corosync/corosync.conf
quorum {
        provider: corosync_votequorum
        #expected_votes: 2
        #two_node: 1
        device {
                votes: 1
                model: net
                net {
                        tls: off
                        host: 192.168.252.1
                        port: 5403
                        algorithm: ffsplit
                        tie_breaker: lowest
                }
        }
}
```

``` shell
$ grep -Pv '^\s*(#|$)' /etc/sysconfig/corosync-qdevice
COROSYNC_QDEVICE_OPTIONS="-q -d"
```


When, for example, `corosync-qdevice` connects to `corosync-qnetd`, the corosync
will report:

``` shell
Apr 30 13:42:31 debug   [VOTEQ ] Received qdevice op 1 req from node 1 [Qdevice]
Apr 30 13:42:31 debug   [VOTEQ ] flags: quorate: No Leaving: No WFA Status: No First: Yes Qdevice: Yes QdeviceAlive: No QdeviceCastVote: No QdeviceMasterWins: No
Apr 30 13:42:31 debug   [VOTEQ ] got nodeinfo message from cluster node 1
Apr 30 13:42:31 debug   [VOTEQ ] nodeinfo message[0]: votes: 1, expected: 0 flags: 0
Apr 30 13:42:31 debug   [VOTEQ ] got nodeinfo message from cluster node 1
Apr 30 13:42:31 debug   [VOTEQ ] nodeinfo message[1]: votes: 1, expected: 2 flags: 24
Apr 30 13:42:31 debug   [VOTEQ ] flags: quorate: No Leaving: No WFA Status: No First: Yes Qdevice: Yes QdeviceAlive: No QdeviceCastVote: No QdeviceMasterWins: No
Apr 30 13:42:31 debug   [VOTEQ ] total_votes=2, expected_votes=2
Apr 30 13:42:31 debug   [VOTEQ ] node 1 state=1, votes=1, expected=2
Apr 30 13:42:31 debug   [VOTEQ ] got getinfo request on 0x56030111bcf0 for node 0
Apr 30 13:42:31 debug   [VOTEQ ] getinfo response error: 1
Apr 30 13:42:31 debug   [VOTEQ ] sending initial status to 0x56030111bcf0
Apr 30 13:42:31 debug   [VOTEQ ] Sending nodelist callback. ring_id = 1/175
Apr 30 13:42:31 debug   [VOTEQ ] Sending quorum callback, quorate = 0
Apr 30 13:42:31 debug   [VOTEQ ] got getinfo request on 0x56030111bcf0 for node 1
Apr 30 13:42:31 debug   [VOTEQ ] getinfo response error: 1
Apr 30 13:42:31 debug   [VOTEQ ] got getinfo request on 0x56030111bcf0 for node 2
Apr 30 13:42:31 debug   [VOTEQ ] getinfo response error: 12
Apr 30 13:42:31 debug   [VOTEQ ] flags: quorate: No Leaving: No WFA Status: No First: Yes Qdevice: Yes QdeviceAlive: Yes QdeviceCastVote: Yes QdeviceMasterWins: No
Apr 30 13:42:31 debug   [VOTEQ ] got nodeinfo message from cluster node 1
Apr 30 13:42:31 debug   [VOTEQ ] nodeinfo message[1]: votes: 1, expected: 2 flags: 120
Apr 30 13:42:31 debug   [VOTEQ ] flags: quorate: No Leaving: No WFA Status: No First: Yes Qdevice: Yes QdeviceAlive: Yes QdeviceCastVote: Yes QdeviceMasterWins: No
Apr 30 13:42:31 debug   [VOTEQ ] total_votes=2, expected_votes=2
Apr 30 13:42:31 debug   [VOTEQ ] node 1 state=1, votes=1, expected=2
Apr 30 13:42:31 debug   [VOTEQ ] node 0 state=1, votes=1
Apr 30 13:42:31 debug   [VOTEQ ] lowest node id: 1 us: 1
Apr 30 13:42:31 debug   [VOTEQ ] highest node id: 1 us: 1
Apr 30 13:42:31 debug   [VOTEQ ] quorum regained, resuming activity
Apr 30 13:42:31 notice  [QUORUM] This node is within the primary component and will provide service.
Apr 30 13:42:31 notice  [QUORUM] Members[1]: 1
Apr 30 13:42:31 debug   [QUORUM] sending quorum notification to (nil), length = 52
Apr 30 13:42:31 debug   [VOTEQ ] Sending quorum callback, quorate = 1
```

Thus, a vote is added and the quorum is obtained.

And, when, it leaves:

``` shell
Apr 30 13:44:36 debug   [VOTEQ ] flags: quorate: Yes Leaving: No WFA Status: No First: Yes Qdevice: Yes QdeviceAlive: Yes QdeviceCastVote: No QdeviceMasterWins: No
Apr 30 13:44:36 debug   [VOTEQ ] got nodeinfo message from cluster node 1
Apr 30 13:44:36 debug   [VOTEQ ] nodeinfo message[1]: votes: 1, expected: 2 flags: 57
Apr 30 13:44:36 debug   [VOTEQ ] flags: quorate: Yes Leaving: No WFA Status: No First: Yes Qdevice: Yes QdeviceAlive: Yes QdeviceCastVote: No QdeviceMasterWins: No
Apr 30 13:44:36 debug   [VOTEQ ] total_votes=2, expected_votes=2
Apr 30 13:44:36 debug   [VOTEQ ] node 1 state=1, votes=1, expected=2
Apr 30 13:44:36 debug   [VOTEQ ] quorum lost, blocking activity
Apr 30 13:44:36 notice  [QUORUM] This node is within the non-primary component and will NOT provide any services.
Apr 30 13:44:36 notice  [QUORUM] Members[1]: 1
Apr 30 13:44:36 debug   [QUORUM] sending quorum notification to (nil), length = 52
Apr 30 13:44:36 debug   [VOTEQ ] Sending quorum callback, quorate = 0
Apr 30 13:44:36 debug   [VOTEQ ] flags: quorate: No Leaving: No WFA Status: No First: Yes Qdevice: No QdeviceAlive: No QdeviceCastVote: No QdeviceMasterWins: No
Apr 30 13:44:36 debug   [QB    ] HUP conn (/dev/shm/qb-3778-3780-19-WXUubU/qb)
Apr 30 13:44:36 debug   [QB    ] qb_ipcs_disconnect(/dev/shm/qb-3778-3780-19-WXUubU/qb) state:2
Apr 30 13:44:36 debug   [MAIN  ] cs_ipcs_connection_closed()
Apr 30 13:44:36 debug   [MAIN  ] cs_ipcs_connection_destroyed()
Apr 30 13:44:36 debug   [QB    ] Free'ing ringbuffer: /dev/shm/qb-3778-3780-19-WXUubU/qb-response-votequorum-header
Apr 30 13:44:36 debug   [QB    ] Free'ing ringbuffer: /dev/shm/qb-3778-3780-19-WXUubU/qb-event-votequorum-header
Apr 30 13:44:36 debug   [QB    ] Free'ing ringbuffer: /dev/shm/qb-3778-3780-19-WXUubU/qb-request-votequorum-header
Apr 30 13:44:36 debug   [QB    ] HUP conn (/dev/shm/qb-3778-3780-18-uSN3US/qb)
Apr 30 13:44:36 debug   [QB    ] qb_ipcs_disconnect(/dev/shm/qb-3778-3780-18-uSN3US/qb) state:2
Apr 30 13:44:36 debug   [MAIN  ] cs_ipcs_connection_closed()
Apr 30 13:44:36 debug   [CMAP  ] exit_fn for conn=0x560301124f90
Apr 30 13:44:36 debug   [MAIN  ] cs_ipcs_connection_destroyed()
Apr 30 13:44:36 debug   [QB    ] Free'ing ringbuffer: /dev/shm/qb-3778-3780-18-uSN3US/qb-response-cmap-header
Apr 30 13:44:36 debug   [QB    ] Free'ing ringbuffer: /dev/shm/qb-3778-3780-18-uSN3US/qb-event-cmap-header
Apr 30 13:44:36 debug   [QB    ] Free'ing ringbuffer: /dev/shm/qb-3778-3780-18-uSN3US/qb-request-cmap-header
Apr 30 13:44:36 debug   [VOTEQ ] got nodeinfo message from cluster node 1
Apr 30 13:44:36 debug   [VOTEQ ] nodeinfo message[1]: votes: 1, expected: 2 flags: 8
Apr 30 13:44:36 debug   [VOTEQ ] flags: quorate: No Leaving: No WFA Status: No First: Yes Qdevice: No QdeviceAlive: No QdeviceCastVote: No QdeviceMasterWins: No
Apr 30 13:44:36 debug   [VOTEQ ] total_votes=2, expected_votes=2
Apr 30 13:44:36 debug   [VOTEQ ] node 1 state=1, votes=1, expected=2
Apr 30 13:44:36 debug   [VOTEQ ] Received qdevice op 0 req from node 1 [Qdevice]
```

That is, losing the quorum.


#### corosync-qnetd

Most distros setup TLS DB store in postinstall package scripts; an exaple from
Debian:

``` shell
    # https://fedoraproject.org/wiki/Changes/NSSDefaultFileFormatSql
    if ! [ -f "$db/cert9.db" ]; then
	if [ -f "$dir/nssdb/cert8.db" ]; then
	    # password file should have an empty line to be accepted
	    [ -f "$pwdfile" -a ! -s "$pwdfile" ] && echo > "$pwdfile"

	    # upgrade to SQLite database
	    certutil -N -d "sql:$db" -f "$pwdfile" -@ "$pwdfile"
	    chmod g+r "$db/cert9.db" "$db/key4.db"
	else
            corosync-qnetd-certutil -i -G
	fi
	chgrp "$user" "$db" "$db/cert9.db" "$db/key4.db"
    fi
```

However, for testing purposes, this can be turned off:

``` shell
$ grep -Pv '^\s*(#|$)' /etc/sysconfig/corosync-qnetd
COROSYNC_QNETD_OPTIONS="-s off -c off -d"
COROSYNC_QNETD_RUNAS=""
```

Below, just summary:

``` shell
$ corosync-qnetd-tool -s
QNetd address:                  *:5403
TLS:                            Unsupported
Connected clients:              0
Connected clusters:             0
Maximum send/receive size:      32768/32768 bytes
```

When a client (`corosync-qdevice`) connects:

``` shell
$ corosync-qnetd-tool -lv
Cluster "jb155sapqe":
    Algorithm:          Fifty-Fifty split
    Tie-breaker:        Node with lowest node ID
    Node ID 1:
        Client address:         ::ffff:192.168.252.100:47222
        HB interval:            8000ms
        Configured node list:   1, 2
        Ring ID:                1.a0
        Membership node list:   1
        Heuristics:             Undefined (membership: Undefined, regular: Undefined)
        TLS active:             No
        Vote:                   No change (ACK)
```


### DLM

``` shell
$ man dlm_controld | sed -n '/^DESCRIPTION/,/^$/{/^$/q;p}' | fmt -w80
DESCRIPTION
       The kernel dlm requires a user daemon to manage lockspace membership.
       dlm_controld manages lockspace membership using corosync cpg groups,
       and translates membership changes into dlm kernel recovery events.
       dlm_controld also manages posix locks for cluster file systems using
       the dlm.
```

``` shell
# see corosync CPG (control process group) exists for DLM

$ corosync-cpgtool -e
Group Name             PID         Node ID
dlm:controld
                      3114               1 (192.168.253.100)
crmd
                      3034               1 (192.168.253.100)
                      1859               2 (192.168.253.101)
attrd
                      3032               1 (192.168.253.100)
                      1857               2 (192.168.253.101)
stonith-ng
                      3030               1 (192.168.253.100)
                      1855               2 (192.168.253.101)
cib
                      3029               1 (192.168.253.100)
                      1854               2 (192.168.253.101)
sbd:cluster
                      3018               1 (192.168.253.100)
                      1842               2 (192.168.253.101)
```

``` shell
$ corosync-cfgtool -s
Printing ring status.
Local node ID 1
RING ID 0
        id      = 192.168.253.100
        status  = ring 0 active with no faults

$ dlm_tool status
cluster nodeid 1 quorate 1 ring seq 270 270
daemon now 5844 fence_pid 0
node 1 M add 5674 rem 0 fail 0 fence 0 at 0 0
node 2 M add 5815 rem 0 fail 0 fence 0 at 0 0
```

If there are lockspace members (for example `lvmlockd` RA), one should see:

``` shell
# first our RA using the lockspace

$ crm configure show lvmlockd
primitive lvmlockd lvmlockd \
        op start timeout=90s interval=0s \
        op stop timeout=90s interval=0s \
        op monitor timeout=90s interval=30s

# note: 'clustered' was for old `clvmd'

$ vgs -o vg_name,vg_clustered,vg_lock_type,vg_lock_args
  VG    Clustered  LockType VLockArgs
  clvg0            dlm      1.0.0:jb155sapqe

# listing DLM internal lockspace

$ dlm_tool ls
dlm lockspaces
name          lvm_clvg0
id            0x45d1d4f1
flags         0x00000000
change        member 1 joined 1 remove 0 failed 0 seq 1,1
members       1

name          lvm_global
id            0x12aabd2d
flags         0x00000000
change        member 1 joined 1 remove 0 failed 0 seq 1,1
members       1

# and corosync CPG for lockspace memberships

$ corosync-cpgtool -e | head -n9
Group Name             PID         Node ID
dlm:ls:lvm_clvg0
                      3702               1 (192.168.253.100)
dlm:ls:lvm_global
                      3702               1 (192.168.253.100)
                      2368               2 (192.168.253.101)
dlm:controld
                      3702               1 (192.168.253.100)
                      2368               2 (192.168.253.101)

```

So, what happens on network level when eg. `vgs` is typed?

``` shell
$  tshark -n -i eth0 -f 'not (udp or stp ) and not (port 22 or port 3260)'
...
    1 0.000000000 192.168.253.101 → 192.168.253.100 DLM3 206 options: message: conversion message
    2 0.000115947 192.168.253.100 → 192.168.253.101 DLM3 222 acknowledge
    3 0.000344159 192.168.253.101 → 192.168.253.100 DLM3 78 acknowledge
    4 0.000361827 192.168.253.100 → 192.168.253.101 SCTP 62 SACK (Ack=1, Arwnd=4194288)
    5 0.008363511 192.168.253.101 → 192.168.253.100 DLM3 206 options: message: conversion message
    6 0.008479394 192.168.253.100 → 192.168.253.101 DLM3 78 acknowledge
    7 0.008581370 192.168.253.101 → 192.168.253.100 SCTP 62 SACK (Ack=1, Arwnd=4194288)
    8 0.209133597 192.168.253.100 → 192.168.253.101 SCTP 62 SACK (Ack=2, Arwnd=4194304)
    9 6.161107176 192.168.253.100 → 192.168.253.101 SCTP 106 HEARTBEAT
   10 6.161481187 192.168.253.101 → 192.168.253.100 SCTP 106 HEARTBEAT_ACK

$ ss -Sna | col -b            # `-S' is SCTP, see below
State    Recv-Q Send-Q        Local Address:Port     Peer Address:Port Process
LISTEN   0      5           192.168.253.100:21064         0.0.0.0:*
ESTAB    0      0           192.168.253.100:21064 192.168.253.101:53872
`- ESTAB 0      0      192.168.253.100%eth0:21064 192.168.253.101:53872
ESTAB    0      0           192.168.253.100:42013 192.168.253.101:21064
`- ESTAB 0      0      192.168.253.100%eth0:42013 192.168.253.101:21064
```

SCTP??? See [Protocols for DLM communication](https://documentation.suse.com/sle-ha/15-SP5/single-html/SLE-HA-administration/#sec-ha-storage-dlm-protocol).

``` shell
$ dlm_tool dump | grep -P '(rrp_mode|protocol)'
4244 cmap totem.rrp_mode = 'passive'
4244 set protocol 1
4244 receive_protocol 2 max 3.1.1.0 run 0.0.0.0
4244 receive_protocol 1 max 3.1.1.0 run 3.1.1.0
4244 run protocol from nodeid 1
4244 receive_protocol 2 max 3.1.1.0 run 3.1.1.0

$ lsmod | grep ^sctp
sctp                  434176  10

$ modinfo sctp | head
filename:       /lib/modules/5.14.21-150500.55.19-default/kernel/net/sctp/sctp.ko.zst
license:        GPL
description:    Support for the SCTP protocol (RFC2960)
author:         Linux Kernel SCTP developers <linux-sctp@vger.kernel.org>
alias:          net-pf-10-proto-132
alias:          net-pf-2-proto-132
suserelease:    SLE15-SP5
srcversion:     FC2AFAA5AE6D0A503192391
depends:        udp_tunnel,libcrc32c,ip6_udp_tunnel
supported:      yes
```



For now only `lvmlockd` RA was added, thus 'lvm_clvg0' has only _one_member:

``` shell
$ dlm_tool ls
dlm lockspaces
name          lvm_clvg0
id            0x45d1d4f1
flags         0x00000000
change        member 1 joined 1 remove 0 failed 0 seq 1,1
members       1

name          lvm_global
id            0x12aabd2d
flags         0x00000000
change        member 2 joined 1 remove 0 failed 0 seq 2,2
members       1 2
```

After adding "shared" VG, that is one which is activated on both nodes (eg. for OCFS2),
this happens:

``` shell
$ crm configure show clvg0
primitive clvg0 LVM-activate \
        params vgname=clvg0 vg_access_mode=lvmlockd activation_mode=shared \
        op start timeout=90s interval=0 \
        op stop timeout=90s interval=0 \
        op monitor interval=90s timeout=90s

# see lvm_clvg0 has two member now!

$ dlm_tool ls
dlm lockspaces
name          lvm_clvg0
id            0x45d1d4f1
flags         0x00000000
change        member 2 joined 1 remove 0 failed 0 seq 1,1
members       1 2

name          lvm_global
id            0x12aabd2d
flags         0x00000000
change        member 2 joined 1 remove 0 failed 0 seq 1,1
members       1 2
```

``` shell
# see that we have 'rrp_mode = "passive"', and 'protocol'

$ dlm_tool dump
5674 config file log_debug = 1 cli_set 0 use 1
5674 dlm_controld 4.1.0 started
5674 our_nodeid 1
5674 node_config 1
5674 node_config 2
5674 found /dev/misc/dlm-control minor 124
5674 found /dev/misc/dlm-monitor minor 123
5674 found /dev/misc/dlm_plock minor 122
5674 /sys/kernel/config/dlm/cluster/comms: opendir failed: 2
5674 /sys/kernel/config/dlm/cluster/spaces: opendir failed: 2
5674 set log_debug 1
5674 set mark 0
5674 cmap totem.rrp_mode = 'passive'
5674 set protocol 1
5674 set /proc/sys/net/core/rmem_default 4194304
5674 set /proc/sys/net/core/rmem_max 4194304
5674 set recover_callbacks 1
5674 cmap totem.cluster_name = 'jb155sapqe'
5674 set cluster_name jb155sapqe
5674 /dev/misc/dlm-monitor fd 13
5674 cluster quorum 1 seq 270 nodes 2
5674 cluster node 1 added seq 270
5674 set_configfs_node 1 192.168.253.100 local 1 mark 0
5674 cluster node 2 added seq 270
5674 set_configfs_node 2 192.168.253.101 local 0 mark 0
5674 cpg_join dlm:controld ...
5674 setup_cpg_daemon 15
5674 dlm:controld conf 1 1 0 memb 1 join 1 left 0
5674 daemon joined 1
5674 dlm:controld ring 1:270 2 memb 1 2
5674 receive_protocol 1 max 3.1.1.0 run 0.0.0.0
5674 daemon node 1 prot max 0.0.0.0 run 0.0.0.0
5674 daemon node 1 save max 3.1.1.0 run 0.0.0.0
5674 set_protocol member_count 1 propose daemon 3.1.1 kernel 1.1.1
5674 receive_protocol 1 max 3.1.1.0 run 3.1.1.0
5674 daemon node 1 prot max 3.1.1.0 run 0.0.0.0
5674 daemon node 1 save max 3.1.1.0 run 3.1.1.0
5674 run protocol from nodeid 1
5674 daemon run 3.1.1 max 3.1.1 kernel run 1.1.1 max 1.1.1
5674 plocks 16
5674 receive_protocol 1 max 3.1.1.0 run 3.1.1.0
5674 send_fence_clear 1 fipu
5674 receive_fence_clear from 1 for 1 result -61 flags 1
5674 fence_in_progress_unknown 0 all_fipu
5815 dlm:controld conf 2 1 0 memb 1 2 join 2 left 0
5815 daemon joined 2
5815 receive_protocol 2 max 3.1.1.0 run 0.0.0.0
5815 daemon node 2 prot max 0.0.0.0 run 0.0.0.0
5815 daemon node 2 save max 3.1.1.0 run 0.0.0.0
5815 receive_protocol 1 max 3.1.1.0 run 3.1.1.0
5815 receive_fence_clear from 1 for 2 result 0 flags 6
5815 receive_protocol 2 max 3.1.1.0 run 3.1.1.0
5815 daemon node 2 prot max 3.1.1.0 run 0.0.0.0
5815 daemon node 2 save max 3.1.1.0 run 3.1.1.0
```


### Pacemaker

*pacemaker* is an advanced, scalable High-Availability cluster resource manager.


``` shell
systemctl start pacemaker # on all nodes (or use 'crm cluster start' instead)
corosync-cpgtool          # see if pacemaker is known to corosync,
                          # these are symlinks to pacemaker daemons,
                          # see `ls -l /usr/lib/pacemaker/'
```

There was a rename of pacemaker components but there are still old names
visible:

``` shell
$ ls -l /usr/lib/pacemaker/
total 832
lrwxrwxrwx 1 root root     15 Oct 14  2021 attrd -> pacemaker-attrd
lrwxrwxrwx 1 root root     15 Oct 14  2021 cib -> pacemaker-based
-rwxr-xr-x 1 root root  14936 Oct 14  2021 cibmon
lrwxrwxrwx 1 root root     18 Oct 14  2021 crmd -> pacemaker-controld
-rwxr-xr-x 1 root root  24296 Oct 14  2021 cts-exec-helper
-rwxr-xr-x 1 root root  31552 Oct 14  2021 cts-fence-helper
lrwxrwxrwx 1 root root     15 Oct 14  2021 lrmd -> pacemaker-execd
-rwxr-xr-x 1 root root  56560 Oct 14  2021 pacemaker-attrd
-rwxr-xr-x 1 root root 107600 Oct 14  2021 pacemaker-based
-rwxr-xr-x 1 root root 370360 Oct 14  2021 pacemaker-controld
-rwxr-xr-x 1 root root  48464 Oct 14  2021 pacemaker-execd
-rwxr-xr-x 1 root root 143224 Oct 14  2021 pacemaker-fenced
-rwxr-xr-x 1 root root  19464 Oct 14  2021 pacemaker-schedulerd
lrwxrwxrwx 1 root root     20 Oct 14  2021 pengine -> pacemaker-schedulerd
lrwxrwxrwx 1 root root     16 Oct 14  2021 stonithd -> pacemaker-fenced
```

cluster configuration:

- in-memory representation
- `/var/lib/pacemaker/cib`

```
/var/lib/pacemaker
├── cib
│   ├── cib-X.raw       # cluster configuration history
│   ├── cib-X.raw.sig
│   └── cib.xml         # latest cluster configuration saved to the disk
└── pengine             # snapshot of a moment of the cluster life
    ├── pe-input-0.bz2  # cluster state of a moment
    └── pe-warn-0.bz2   # something went wrong (fence, reboot), state of what
                        # cluster wants to do about it
```

**WARNING:** this directory is not intended for editing when the cluster is
online!

```
  2022-04-19T13:56:34.055004+02:00 oldhanaa1 pacemaker-based[20832]: error: Digest comparison failed: expected 4010ded1087db5173bd9912cda6e302d, calculated abecc1d59c0b2293b57158cf745280d5
  2022-04-19T13:56:34.055299+02:00 oldhanaa1 pacemaker-based[20832]: error: /var/lib/pacemaker/cib/cib.xml was manually modified while the cluster was active!
```

#### Pacemaker cli tools

``` shell
$ crmadmin -N # show member nodes
member node: oldhanad2 (178438534)
member node: oldhanad1 (178438533)


$ crmadmin -D # show designated coordinator (DC)
Designated Controller is: s153cl01
```

Ongoing activities on the cluster?

``` shell
$ crmadmin -qD # get DC name
s153cl1
$ crmadmin -qS s153cl1
Status of crmd@s153cl1: S_IDLE (ok)
S_IDLE
```

``` shell
$ crm_mon -r -1 # show cluster status
Cluster Summary:
  * Stack: corosync
  * Current DC: consap02 (version 2.0.4+20200616.2deceaa3a-3.9.1-2.0.4+20200616.2deceaa3a) - partition with quorum
  * Last updated: Wed Apr 20 14:30:59 2022
  * Last change:  Wed Apr 20 12:12:57 2022 by root via cibadmin on consap01
  * 2 nodes configured
  * 9 resource instances configured (8 DISABLED)

              *** Resource management is DISABLED ***
  The cluster will not attempt to start, stop or recover services

Node List:
  * Online: [ consap01 consap02 ]

Full List of Resources:
  * stonith-sbd (stonith:external/sbd):  Stopped (unmanaged)
  * Clone Set: cln_SAPHanaTopology_SLE_HDB00 [rsc_SAPHanaTopology_SLE_HDB00] (unmanaged):
    * Stopped (disabled): [ consap01 consap02 ]
  * Clone Set: msl_SAPHana_SLE_HDB00 [rsc_SAPHana_SLE_HDB00] (promotable) (unmanaged):
    * rsc_SAPHana_SLE_HDB00     (ocf::suse:SAPHana):     FAILED consap02 (disabled, unmanaged)
    * rsc_SAPHana_SLE_HDB00     (ocf::suse:SAPHana):     Slave consap01 (disabled, unmanaged)
  * rsc_ip_SLE_HDB00    (ocf::heartbeat:IPaddr2):        Stopped (disabled, unmanaged)
  * rsc_mail    (ocf::heartbeat:MailTo):         Stopped (disabled, unmanaged)
  * Clone Set: cln_diskfull_threshold [sysinfo] (unmanaged):
    * Stopped (disabled): [ consap01 consap02 ]

Failed Resource Actions:
  * rsc_SAPHana_SLE_HDB00_monitor_0 on consap02 'error' (1): call=43, status='complete', exitreason='', last-rc-change='2022-04-20 14:28:02 +01:00', queued=0ms, exec=2476ms
```

*disabled* above means resources were *stopped* before the cluster was put into
maintenance.

Some `crm_mon` details...

- *offline* does not necessary mean the node is down, it **inherits** this value
  from *corosync*, which means the ring/communication is broken
- *UNCLEAN* means one node does not know what is going on on other node


``` shell
$ cibadmin -Q -o nodes # list nodes in pacemaker
<nodes>
  <node id="1084783552" uname="s153cl02"/>
  <node id="1084783549" uname="s153cl01"/>
</nodes>

$ cibadmin -Q -o crm_config # list cluster options configuration in pacemaker
<crm_config>
  <cluster_property_set id="cib-bootstrap-options">
    <nvpair id="cib-bootstrap-options-have-watchdog" name="have-watchdog" value="true"/>
    <nvpair id="cib-bootstrap-options-dc-version" name="dc-version" value="2.0.5+20201202.ba59be712-4.13.1-2.0.5+20201202.ba59be712"/>
    <nvpair id="cib-bootstrap-options-cluster-infrastructure" name="cluster-infrastructure" value="corosync"/>
    <nvpair id="cib-bootstrap-options-cluster-name" name="cluster-name" value="s153cl0"/>
    <nvpair name="stonith-timeout" value="12" id="cib-bootstrap-options-stonith-timeout"/>
    <nvpair name="maintenance-mode" value="true" id="cib-bootstrap-options-maintenance-mode"/>
  </cluster_property_set>
</crm_config>

$ cibadmin -Q --xpath '//*/primitive[@type="external/sbd"]' # query with xpath
<primitive id="stonith-sbd" class="stonith" type="external/sbd">
  <instance_attributes id="stonith-sbd-instance_attributes">
    <nvpair name="pcmk_delay_max" value="30" id="stonith-sbd-instance_attributes-pcmk_delay_max"/>
  </instance_attributes>
</primitive>
```

``` shell
$ crm_verify -LV            # check configuration used by cluster, verbose
                          # can show important info
```

general cluster mgmt

``` shell
$ crm_mon                                                 # general overview, part of pacemaker
$ crm_mon [-n | --group-by-node ]
$ crm_mon -nforA                                          # incl. fail, counts, operations...
$ cibadmin [-Q | --query]                                 # expert xml administration, part of pacemaker
$ crm_attribute --type <scope> --name <attribute> --query # another query solution
```

#### Pacemaker resources

Resources failures and what would happen:

- *monitor* failure -> stop -> start (*"did you try to stop and start it again?*")
- *start* failure -> blocked to start locally via *fail-count*
  `<nvpair id="status-2-fail-count-PlanetX.start_0" name="fail-count-PlanetX#start_0" value="INFINITY"/>`
- *stop* failure -> fence (we cannot be sure what a resource won't mess with
  data thus STONITH)

Note, one can define *on-fail* resource operation action, see
[resource
operations](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/high_availability_add-on_reference/s1-resourceoperate-haar). For
example, *start* failure leads to _block_.


### crm (crmsh)

- by default *root* and *haclient* group members can manage cluster
- some `crm` actions require SSH working between nodes, either
  passwordless root or via a user configured with `crm options user
  <user>` (then it requires passwordless `sudoers` rule)

``` shell
crm
crm help <topic>    # generic syntax for help
crm status          # similar to *crm_mon*, part of crmsh
```


#### crm: acls

- same users and userids on all nodes
- users must be in *haclient* user group
- users need to have rights to run `/usr/bin/crm`


#### crm: backup and restore

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


#### crm: collocating resources

Reads from right to left, if last right resource runs somewhere, do action
defined with next-to-last and all previous resources.

```
colocation <id> <score>: <resource> <resource>

# an example
colocation c1 inf: p-goodservice p-badservice
```

The above reads: if `p-badservice` runs somehwere always run `p-goodservice`
together.


#### crm: grouping resources

Reads from left to right, order is respected, this influence state of the
resources, that is states is respected in order, that is if a resource on the
left in the list is stopped, then resources on the right side are stopped too.

```
group <name> <res> <res>...

# an example
group g-grp1 p-goodservice p-badservice
```

The above reads: start `p-goodservice` and then `p-badservice`.


#### crm: resource operations


``` shell
crm ra classes # list RA classes
crm ra list ocf # list ocf RA class resources
crm ra list ocf <providers> # list ocf:<provider> RAs
crm ra info [<class>:[<provider>:]]<type> # show RA info and options
```

``` shell
crm resource status # show status of resources

crm resource # interactive shell for resources
crm configure [edit] # configuration edit via editor
                     # do not forget commit changes!
crm move     # careful, creates constraints
crm resource constraints <resource> # show resource constraints
```

``` shell
crm resource [trace | untrace] <resource>
```

tracing logs in `/var/lib/heartbeat/trace_ra` (SUSE), filenames as
`<resource>.<action>.<date>`.


#### crm: hacks

``` shell
$ crm configure show related:Dummy
primitive dummy Dummy \
        op monitor timeout=20s interval=10s \
        op_params depth=0 \
        meta target-role=Stopped

# ex script for batch editing

$ cat /tmp/ex-script 
/dummy/
s/dummy/dummy-test/
a
        params state=/run/resource-agents/foobar.state fake=fake \

$ function myeditor() { ex '+source /tmp/ex-script' -sc '%wq!' $@; }

$ export -f myeditor

$ EDITOR=myeditor crm configure edit

$ crm configure show related:Dummy
primitive dummy-test Dummy \
        params state="/run/resource-agents/foobar.state" fake=fake \
        op monitor timeout=20s interval=10s \
        op_params depth=0 \
        meta target-role=Stopped
```

Of course, `crm configure show` dump, edit and then `crm configure
load update <file>` would be probably better ;)

``` shell
$ diff --label current --label new -u0 \
    <(printf 'cib use cib.xml\nconfigure show\n' | crm -f -) \
    <(printf 'cib use temp\nconfigure show\n' | crm -f -)
--- current
+++ new
@@ -885,0 +886 @@
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-CJP-ERS CLO-clvm GRP-CJP-ERS
@@ -886,0 +888,2 @@
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-CJP-SAP CLO-clvm GRP-CJP-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-CRP-ERS CLO-clvm GRP-CRP-ERS
@@ -887,0 +891,2 @@
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-CRP-SAP CLO-clvm GRP-CRP-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-M1P-ERS CLO-clvm GRP-M1P-ERS
@@ -888,0 +894,2 @@
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-M1P-SAP CLO-clvm GRP-M1P-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-PR1-ERS CLO-clvm GRP-PR1-ERS
@@ -889,0 +897,2 @@
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-PR1-SAP CLO-clvm GRP-PR1-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-PRX-ERS CLO-clvm GRP-PRX-ERS
@@ -890,0 +900,2 @@
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-PRX-SAP CLO-clvm GRP-PRX-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-S1P-ERS CLO-clvm GRP-S1P-ERS
@@ -891,0 +903,16 @@
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-S1P-SAP CLO-clvm GRP-S1P-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-W1E-SAP CLO-clvm GRP-W1E-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-W1I-SAP CLO-clvm GRP-W1I-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-W7E-SAP CLO-clvm GRP-W7E-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-W7I-SAP CLO-clvm GRP-W7I-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-W8E-SAP CLO-clvm GRP-W8E-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-W8I-SAP CLO-clvm GRP-W8I-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-W9E-SAP CLO-clvm GRP-W9E-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-W9I-SAP CLO-clvm GRP-W9I-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-WD0-SAP CLO-clvm GRP-WD0-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-WD1-SAP CLO-clvm GRP-WD1-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-WP0-SAP CLO-clvm GRP-WP0-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-WP1-SAP CLO-clvm GRP-WP1-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-WP2-SAP CLO-clvm GRP-WP2-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-WP3-SAP CLO-clvm GRP-WP3-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-WSP-ERS CLO-clvm GRP-WSP-ERS
@@ -892,0 +920,2 @@
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-WSP-SAP CLO-clvm GRP-WSP-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-X7P-ERS CLO-clvm GRP-X7P-ERS
@@ -893,0 +923,2 @@
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-X7P-SAP CLO-clvm GRP-X7P-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-X8P-ERS CLO-clvm GRP-X8P-ERS
@@ -894,0 +926,2 @@
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-X8P-SAP CLO-clvm GRP-X8P-SAP
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-X9P-ERS CLO-clvm GRP-X9P-ERS
@@ -895,0 +929 @@
+order ORD-GRP-DLM-CLVM-BEFORE-GRP-X9P-SAP CLO-clvm GRP-X9P-SAP
@@ -917,0 +952 @@
+colocation col-vg-with-dlm inf: ( GRP-CJP-ERS GRP-CJP-NFS GRP-CJP-SAP GRP-CRP-ERS GRP-CRP-NFS GRP-CRP-SAP GRP-M1P-ERS GRP-M1P-NFS GRP-M1P-SAP GRP-PR1-ERS GRP-PR1-NFS GRP-PR1-SAP GRP-PRX-ERS GRP-PRX-NFS GRP-PRX-SAP GRP-S1P-ERS GRP-S1P-NFS GRP-S1P-SAP GRP-W1E-SAP GRP-W1I-SAP GRP-W7E-SAP GRP-W7I-SAP GRP-W8E-SAP GRP-W8I-SAP GRP-W9E-SAP GRP-W9I-SAP GRP-WD0-SAP GRP-WD1-SAP GRP-WP0-SAP GRP-WP1-SAP GRP-WP2-SAP GRP-WP3-SAP GRP-WSP-ERS GRP-WSP-NFS GRP-WSP-SAP GRP-X7P-ERS GRP-X7P-NFS GRP-X7P-SAP GRP-X8P-ERS GRP-X8P-NFS GRP-X8P-SAP GRP-X9P-ERS GRP-X9P-NFS GRP-X9P-SAP ) CLO-clvm
```

The patch might be applied to `crm configure show` dumped output, and
reapplied via `crm configure load update <file>`.


#### crm: maintenance

``` shell
crm configure property maintenance-mode=<true|false> # global maintenance

crm node maintenance <node> # node maintenance start
crm node ready <node>       # node maintenance stop

crm resource maintenance <on|off> # (un)sets meta maintenance attribute

crm resource <manage|unmanage> <resource> # set/unsets is-managed mode, ie. *unmanaged*

crm node standby <node> # put node into standby mode (moving away resources)
crm node online <node> # put node online to allow hosting resources
```


#### crm: updateing a resource

``` shell
crm resource ban <service_resource> <node> # prevent resource from running on the node
                                           # where service resouce is going to be updated,
                                           # moves resource out of node
...
crm resource clear <service_resource>      # ...
...
```


#### crm: rebooting a node scenario

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


#### crm: ordering constraints

```
crm configure edit

< order <id> Mandatory: <resource>:<status> <resource>:<action>

# an example

crm configure edit

< order o-mariadb_before_webserver Mandatory: g-mariadb:start g-webserver:start
```


#### crm: defining location constraints

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


#### crm: tips & tricks

``` shell
$ crm
crm(live/jb154sapqe01)# cib import /tmp/pe-input-325.bz2
crm(pe-input-325/jb154sapqe01)# cibstatus origin
shadow:pe-input-325
```

``` shell
$ crm
crm(pe-input-325/jb154sapqe01)# configure show related:grp_QSA_ASCS16
group grp_QSA_ASCS16 rsc_ip_QSA_ASCS16 rsc_ip_QSA_ECC_CI rsc_lvm_QSA_ASCS16 rsc_fs_QSA_ASCS16 rsc_sap_QSA_ASCS16 \
        meta target-role=Started \
        meta resource-stickiness=3000
colocation col_TWS_with_ASCS16 inf: grp_QSA_ASCS16 grp_QSA_TWS
colocation col_W00_with_ASCS16 inf: grp_QSA_ASCS16 grp_QSW_W00
colocation col_sap_QSA_not_both -5000: grp_QSA_ERS02 grp_QSA_ASCS16
order ord_cl-storage_before_grp_QSA_ASCS16 Mandatory: cl-storage grp_QSA_ASCS16
```


#### Pacemaker/corosync troubleshooting

1\. see transitions which trigger an action

Basically there's `LogAction` lines following by generated transition,
thus the next `awk` stuff gets only relevant transitions.

``` shell
$ awk 'BEGIN { start=0; } /(LogAction.*\*|Calculated)/ { if($0 ~ /pe-input/ && start != 1) { next; }; print;  if($0 ~ /LogAction/) { start=1; } else { start=0; }; }' pacemaker.log | head -n 8
Sep 02 13:18:02 [27794] example2    pengine:   notice: LogAction:   * Recover    rsc_azure-events:1                  (                   example1 )
Sep 02 13:18:02 [27794] example2    pengine:   notice: LogAction:   * Recover    rsc_SAPHana_UP3_HDB00:1             (            Master example1 )
Sep 02 13:18:02 [27794] example2    pengine:   notice: LogAction:   * Recover    rsc_SAPHanaTopology_UP3_HDB00:1     (                   example1 )
Sep 02 13:18:02 [27794] example2    pengine:   notice: process_pe_message: Calculated transition 219198, saving inputs in /var/lib/pacemaker/pengine/pe-input-3141.bz2
Sep 02 13:18:02 [27794] example2    pengine:   notice: LogAction:   * Recover    rsc_azure-events:1                  (                   example1 )
Sep 02 13:18:02 [27794] example2    pengine:   notice: LogAction:   * Recover    rsc_SAPHana_UP3_HDB00:1             (            Master example1 )
Sep 02 13:18:02 [27794] example2    pengine:   notice: LogAction:   * Recover    rsc_SAPHanaTopology_UP3_HDB00:1     (                   example1 )
Sep 02 13:18:02 [27794] example2    pengine:   notice: process_pe_message: Calculated transition 219199, saving inputs in /var/lib/pacemaker/pengine/pe-input-3142.bz2
```

Sorting PE files is not so straightforward...

``` shell
$ ls hb_report-Wed-11-Jan-2023/*/pengine/*.bz2 | while read f ; do date=$(bzcat $f | grep -Po 'execution-date="\K(\d+)(?=.*)'); echo $f $(date -d @${date}); done | sort -V -k4
hb_report-Wed-11-Jan-2023/example01/pengine/pe-input-340.bz2 Wed Jan 11 08:55:26 CET 2023
hb_report-Wed-11-Jan-2023/example01/pengine/pe-input-341.bz2 Wed Jan 11 08:56:01 CET 2023
hb_report-Wed-11-Jan-2023/example01/pengine/pe-input-342.bz2 Wed Jan 11 08:56:52 CET 2023
hb_report-Wed-11-Jan-2023/example01/pengine/pe-input-343.bz2 Wed Jan 11 08:57:35 CET 2023
hb_report-Wed-11-Jan-2023/example01/pengine/pe-input-344.bz2 Wed Jan 11 08:58:20 CET 2023
hb_report-Wed-11-Jan-2023/example01/pengine/pe-input-345.bz2 Wed Jan 11 08:58:22 CET 2023
hb_report-Wed-11-Jan-2023/example02/pengine/pe-warn-15.bz2 Wed Jan 11 09:00:54 CET 2023
hb_report-Wed-11-Jan-2023/example02/pengine/pe-input-157.bz2 Wed Jan 11 09:01:07 CET 2023
hb_report-Wed-11-Jan-2023/example02/pengine/pe-input-158.bz2 Wed Jan 11 09:04:31 CET 2023
hb_report-Wed-11-Jan-2023/example02/pengine/pe-input-159.bz2 Wed Jan 11 09:05:05 CET 2023
hb_report-Wed-11-Jan-2023/example02/pengine/pe-input-160.bz2 Wed Jan 11 09:06:55 CET 2023
hb_report-Wed-11-Jan-2023/example02/pengine/pe-input-161.bz2 Wed Jan 11 09:21:57 CET 2023
hb_report-Wed-11-Jan-2023/example02/pengine/pe-input-162.bz2 Wed Jan 11 09:30:44 CET 2023
hb_report-Wed-11-Jan-2023/example02/pengine/pe-input-163.bz2 Wed Jan 11 09:30:44 CET 2023
hb_report-Wed-11-Jan-2023/example02/pengine/pe-input-164.bz2 Wed Jan 11 09:47:42 CET 2023
hb_report-Wed-11-Jan-2023/example02/pengine/pe-input-165.bz2 Wed Jan 11 11:59:25 CET 2023
hb_report-Wed-11-Jan-2023/example02/pengine/pe-input-166.bz2 Wed Jan 11 11:59:34 CET 2023
hb_report-Wed-11-Jan-2023/example02/pengine/pe-input-167.bz2 Wed Jan 11 11:59:38 CET 2023
hb_report-Wed-11-Jan-2023/example02/pengine/pe-input-168.bz2 Wed Jan 11 11:59:42 CET 2023
hb_report-Wed-11-Jan-2023/example02/pengine/pe-input-169.bz2 Wed Jan 11 11:59:46 CET 2023
hb_report-Wed-11-Jan-2023/example02/pengine/pe-input-170.bz2 Wed Jan 11 11:59:48 CET 2023
hb_report-Wed-11-Jan-2023/example02/pengine/pe-input-171.bz2 Wed Jan 11 11:59:51 CET 2023
hb_report-Wed-11-Jan-2023/example02/pengine/pe-input-172.bz2 Wed Jan 11 11:59:54 CET 2023
hb_report-Wed-11-Jan-2023/example02/pengine/pe-warn-16.bz2 Wed Jan 11 12:09:11 CET 2023
hb_report-Wed-11-Jan-2023/example01/pengine/pe-input-346.bz2 Wed Jan 11 12:09:26 CET 2023
hb_report-Wed-11-Jan-2023/example01/pengine/pe-input-347.bz2 Wed Jan 11 12:09:54 CET 2023
hb_report-Wed-11-Jan-2023/example01/pengine/pe-input-348.bz2 Wed Jan 11 12:12:46 CET 2023
hb_report-Wed-11-Jan-2023/example01/pengine/pe-input-349.bz2 Wed Jan 11 12:13:14 CET 2023
hb_report-Wed-11-Jan-2023/example01/pengine/pe-input-350.bz2 Wed Jan 11 12:14:52 CET 2023
```

A node is "back" _online_:

```
May 17 15:51:01 [4234] node1       crmd:     info: peer_update_callback: Client node1/peer now has status [online] (DC=true, changed=4000000)
```

What is going to be executed for a transition in details?

``` shell
$ crm_simulate -S -x /tmp/pe-input-3902.bz2 | sed -n '/^Transition Summary/,/^Using the/p'
Transition Summary:
  * Start      rsc_ip_db2ptr_EWP        (                 node2 )  blocked
  * Start      rsc_nc_db2ptr_EWP        (                 node2 )  blocked
  * Promote    rsc_Db2_db2ptr_EWP:0     ( Slave -> Master node2 )

Executing Cluster Transition:
  * Pseudo action:   msl_Db2_db2ptr_EWP_pre_notify_promote_0
  * Resource action: rsc_Db2_db2ptr_EWP notify on node2
  * Pseudo action:   msl_Db2_db2ptr_EWP_confirmed-pre_notify_promote_0
  * Pseudo action:   msl_Db2_db2ptr_EWP_promote_0
  * Resource action: rsc_Db2_db2ptr_EWP promote on node2
  * Pseudo action:   msl_Db2_db2ptr_EWP_promoted_0
  * Pseudo action:   msl_Db2_db2ptr_EWP_post_notify_promoted_0
  * Resource action: rsc_Db2_db2ptr_EWP notify on node2
  * Pseudo action:   msl_Db2_db2ptr_EWP_confirmed-post_notify_promoted_0
  * Pseudo action:   g_ip_db2ptr_EWP_start_0
  * Resource action: rsc_Db2_db2ptr_EWP monitor=31000 on node2
Using the original execution date of: 2023-05-17 07:50:58Z

$ crm_simulate -VVVVVV -S -x /tmp/pe-input-3902.bz2 2>&1 | grep log_synapse_action
(log_synapse_action)    debug: [Action   19]: Pending pseudo op g_ip_db2ptr_EWP_start_0          (priority: 0, waiting: 44)
(log_synapse_action)    debug: [Action   58]: Pending resource op rsc_Db2_db2ptr_EWP_post_notify_promote_0 on node2 (priority: 1000000, waiting: 43)
(log_synapse_action)    debug: [Action   57]: Pending resource op rsc_Db2_db2ptr_EWP_pre_notify_promote_0 on node2 (priority: 0, waiting: 41)
(log_synapse_action)    debug: [Action   26]: Pending resource op rsc_Db2_db2ptr_EWP_monitor_31000 on node2 (priority: 0, waiting: 25 44)
(log_synapse_action)    debug: [Action   25]: Pending resource op rsc_Db2_db2ptr_EWP_promote_0   on node2 (priority: 0, waiting: 39)
(log_synapse_action)    debug: [Action   44]: Pending pseudo op msl_Db2_db2ptr_EWP_confirmed-post_notify_promoted_0 (priority: 1000000, waiting: 43 58)
(log_synapse_action)    debug: [Action   43]: Pending pseudo op msl_Db2_db2ptr_EWP_post_notify_promoted_0 (priority: 1000000, waiting: 40 42)
(log_synapse_action)    debug: [Action   42]: Pending pseudo op msl_Db2_db2ptr_EWP_confirmed-pre_notify_promote_0 (priority: 0, waiting: 41 57)
(log_synapse_action)    debug: [Action   41]: Pending pseudo op msl_Db2_db2ptr_EWP_pre_notify_promote_0 (priority: 0, waiting: none)
(log_synapse_action)    debug: [Action   40]: Pending pseudo op msl_Db2_db2ptr_EWP_promoted_0    (priority: 1000000, waiting: 25)
(log_synapse_action)    debug: [Action   39]: Pending pseudo op msl_Db2_db2ptr_EWP_promote_0     (priority: 0, waiting: 42)
```

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
# pacemaker 2.x

# filter cluter related events and search for 'pe-input' string which shows
# what pengine/scheduler decided how transition configuration should look like
$ grep -P \
  '(SAPHana|sap|corosync|pacemaker-(attrd|based|controld|execd|schedulerd|fenced)|stonith|systemd)\[\d+\]' \
  /var/log/pacemaker/pacemaker.log | less
```


### Pacemaker resource agents

A hack to print ocf-based RA required paramenters and other stuff

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


#### Pacemaker troubleshooting

##### unexpected reboot I.

*oldhana2* was rebooted, cca around 13:20.

``` shell
$ grep 'Linux version' oldhanad2/messages
2022-04-21T13:23:03.881400+02:00 oldhanad2 kernel: [    0.000000] Linux version 5.3.18-150300.59.60-default (geeko@buildhost) (gcc version 7.5.0 (SUSE Linux)) #1 SMP Fri Mar 18 18:37:08 UTC 2022 (79e1683)
```
Let's see if it was fenced...

``` shell
$ sed -n '1,/^2022-04-21T13:23:03/p' ha-log.txt | \
  grep -P \
  '(SAPHana|sap|corosync|pacemaker-(attrd|based|controld|execd|schedulerd|fenced)|stonith|systemd)\[\d+\]' \
  | grep -ni reboot
354307:2022-04-21T13:21:38.866101+02:00 oldhanad1 pacemaker-schedulerd[26189]:  notice:  * Fence (reboot) oldhanad2 'peer is no longer part of the cluster'
354312:2022-04-21T13:21:38.867641+02:00 oldhanad1 pacemaker-controld[26190]:  notice: Requesting fencing (reboot) of node oldhanad2
354315:2022-04-21T13:21:38.868521+02:00 oldhanad1 pacemaker-fenced[26186]:  notice: Client pacemaker-controld.26190.b64beaf2 wants to fence (reboot) 'oldhanad2' with device '(any)'
354316:2022-04-21T13:21:38.868607+02:00 oldhanad1 pacemaker-fenced[26186]:  notice: Requesting peer fencing (reboot) targeting oldhanad2
354321:2022-04-21T13:21:38.989800+02:00 oldhanad1 pacemaker-fenced[26186]:  notice: Requesting that oldhanad1 perform 'reboot' action targeting oldhanad2
354322:2022-04-21T13:21:38.990116+02:00 oldhanad1 pacemaker-fenced[26186]:  notice: killer is eligible to fence (reboot) oldhanad2: dynamic-list
354421:2022-04-21T13:21:51.257505+02:00 oldhanad1 pacemaker-fenced[26186]:  notice: Operation 'reboot' [1951] (call 2 from pacemaker-controld.26190) for host 'oldhanad2' with device 'killer' returned: 0 (OK)
354422:2022-04-21T13:21:51.257803+02:00 oldhanad1 pacemaker-fenced[26186]:  notice: Operation 'reboot' targeting oldhanad2 on oldhanad1 for pacemaker-controld.26190@oldhanad1.a127b270: OK
354424:2022-04-21T13:21:51.259400+02:00 oldhanad1 pacemaker-controld[26190]:  notice: Peer oldhanad2 was terminated (reboot) by oldhanad1 on behalf of pacemaker-controld.26190: OK
```
Let's see what was corosync ring before the fence/reboot happened...

``` shell
$ sed -n '1,/^2022-04-21T13:23:03/p' ha-log.txt | \
  grep -P 'corosync.*(TOTEM|QUORUM|CPG)' | \
  grep -Pv '(ignoring|Invalid packet data|Digest does not match)'
2022-04-21T13:21:31.828859+02:00 oldhanad1 corosync[26152]:   [TOTEM ] A processor failed, forming new configuration.
2022-04-21T13:21:37.830133+02:00 oldhanad1 corosync[26152]:   [TOTEM ] A new membership (10.162.193.133:116) was formed. Members left: 178438534
2022-04-21T13:21:37.830212+02:00 oldhanad1 corosync[26152]:   [TOTEM ] Failed to receive the leave message. failed: 178438534
2022-04-21T13:21:37.830267+02:00 oldhanad1 corosync[26152]:   [CPG   ] downlist left_list: 1 received
2022-04-21T13:21:37.831069+02:00 oldhanad1 corosync[26152]:   [QUORUM] Members[1]: 178438533
2022-04-21T13:21:38.743694+02:00 oldhanad1 corosync[26152]:   [TOTEM ] Automatically recovered ring 0
```

The above shows ungraceful disappearance of the node from corosync ring. In this
case `kill -9` was used but the same could be if whole network communication
would stop working between nodes.

``` shell
$ sed -n '1,/^2022-04-21T13:23:03/p' ha-log.txt | \
  grep -P '(pacemaker-(attrd|based|controld|execd|schedulerd|fenced)|stonith)\[\d+\]'
2022-04-21T13:21:37.831919+02:00 oldhanad1 pacemaker-controld[26190]:  notice: Our peer on the DC (oldhanad2) is dead
2022-04-21T13:21:37.832181+02:00 oldhanad1 pacemaker-based[26185]:  notice: Node oldhanad2 state is now lost
2022-04-21T13:21:37.832419+02:00 oldhanad1 pacemaker-attrd[26188]:  notice: Lost attribute writer oldhanad2
2022-04-21T13:21:37.832478+02:00 oldhanad1 pacemaker-controld[26190]:  notice: State transition S_NOT_DC -> S_ELECTION
2022-04-21T13:21:37.832525+02:00 oldhanad1 pacemaker-based[26185]:  notice: Purged 1 peer with id=178438534 and/or uname=oldhanad2 from the membership cache
2022-04-21T13:21:37.832567+02:00 oldhanad1 pacemaker-controld[26190]:  notice: Node oldhanad2 state is now lost
2022-04-21T13:21:37.832621+02:00 oldhanad1 pacemaker-attrd[26188]:  notice: Node oldhanad2 state is now lost
2022-04-21T13:21:37.832667+02:00 oldhanad1 pacemaker-attrd[26188]:  notice: Removing all oldhanad2 attributes for peer loss
2022-04-21T13:21:37.832707+02:00 oldhanad1 pacemaker-attrd[26188]:  notice: Purged 1 peer with id=178438534 and/or uname=oldhanad2 from the membership cache
2022-04-21T13:21:37.832746+02:00 oldhanad1 pacemaker-attrd[26188]:  notice: Recorded local node as attribute writer (was unset)
2022-04-21T13:21:37.832786+02:00 oldhanad1 pacemaker-controld[26190]:  notice: State transition S_ELECTION -> S_INTEGRATION
2022-04-21T13:21:37.833037+02:00 oldhanad1 pacemaker-fenced[26186]:  notice: Node oldhanad2 state is now lost
2022-04-21T13:21:37.833125+02:00 oldhanad1 pacemaker-fenced[26186]:  notice: Purged 1 peer with id=178438534 and/or uname=oldhanad2 from the membership cache
2022-04-21T13:21:37.859192+02:00 oldhanad1 pacemaker-controld[26190]:  notice: Updating quorum status to true (call=128)
2022-04-21T13:21:38.865044+02:00 oldhanad1 pacemaker-schedulerd[26189]:  warning: Cluster node oldhanad2 will be fenced: peer is no longer part of the cluster
2022-04-21T13:21:38.865201+02:00 oldhanad1 pacemaker-schedulerd[26189]:  warning: Node oldhanad2 is unclean
2022-04-21T13:21:38.865701+02:00 oldhanad1 pacemaker-schedulerd[26189]:  warning: killer_stop_0 on oldhanad2 is unrunnable (node is offline)
2022-04-21T13:21:38.865825+02:00 oldhanad1 pacemaker-schedulerd[26189]:  warning: p-IP1_stop_0 on oldhanad2 is unrunnable (node is offline)
2022-04-21T13:21:38.865907+02:00 oldhanad1 pacemaker-schedulerd[26189]:  warning: Scheduling Node oldhanad2 for STONITH
2022-04-21T13:21:38.866101+02:00 oldhanad1 pacemaker-schedulerd[26189]:  notice:  * Fence (reboot) oldhanad2 'peer is no longer part of the cluster'
2022-04-21T13:21:38.866214+02:00 oldhanad1 pacemaker-schedulerd[26189]:  notice:  * Move       killer     ( oldhanad2 -> oldhanad1 )
2022-04-21T13:21:38.866304+02:00 oldhanad1 pacemaker-schedulerd[26189]:  notice:  * Move       p-IP1      ( oldhanad2 -> oldhanad1 )
2022-04-21T13:21:38.867223+02:00 oldhanad1 pacemaker-schedulerd[26189]:  warning: Calculated transition 0 (with warnings), saving inputs in /var/lib/pacemaker/pengine/pe-warn-6.bz2
2022-04-21T13:21:38.867566+02:00 oldhanad1 pacemaker-controld[26190]:  notice: Processing graph 0 (ref=pe_calc-dc-1650540098-21) derived from /var/lib/pacemaker/pengine/pe-warn-6.bz2
2022-04-21T13:21:38.867641+02:00 oldhanad1 pacemaker-controld[26190]:  notice: Requesting fencing (reboot) of node oldhanad2
2022-04-21T13:21:38.867755+02:00 oldhanad1 pacemaker-controld[26190]:  notice: Initiating start operation killer_start_0 locally on oldhanad1
2022-04-21T13:21:38.867855+02:00 oldhanad1 pacemaker-controld[26190]:  notice: Requesting local execution of start operation for killer on oldhanad1
2022-04-21T13:21:38.868521+02:00 oldhanad1 pacemaker-fenced[26186]:  notice: Client pacemaker-controld.26190.b64beaf2 wants to fence (reboot) 'oldhanad2' with device '(any)'
2022-04-21T13:21:38.868607+02:00 oldhanad1 pacemaker-fenced[26186]:  notice: Requesting peer fencing (reboot) targeting oldhanad2
2022-04-21T13:21:38.868833+02:00 oldhanad1 pacemaker-execd[26187]:  notice: executing - rsc:killer action:start call_id:70
2022-04-21T13:21:38.989800+02:00 oldhanad1 pacemaker-fenced[26186]:  notice: Requesting that oldhanad1 perform 'reboot' action targeting oldhanad2
2022-04-21T13:21:38.990116+02:00 oldhanad1 pacemaker-fenced[26186]:  notice: killer is eligible to fence (reboot) oldhanad2: dynamic-list
2022-04-21T13:21:40.078030+02:00 oldhanad1 pacemaker-execd[26187]:  notice: killer start (call 70) exited with status 0 (execution time 1208ms, queue time 0ms)
2022-04-21T13:21:40.078369+02:00 oldhanad1 pacemaker-controld[26190]:  notice: Result of start operation for killer on oldhanad1: ok
2022-04-21T13:21:51.257505+02:00 oldhanad1 pacemaker-fenced[26186]:  notice: Operation 'reboot' [1951] (call 2 from pacemaker-controld.26190) for host 'oldhanad2' with device 'killer' returned: 0 (OK)
2022-04-21T13:21:51.257803+02:00 oldhanad1 pacemaker-fenced[26186]:  notice: Operation 'reboot' targeting oldhanad2 on oldhanad1 for pacemaker-controld.26190@oldhanad1.a127b270: OK
2022-04-21T13:21:51.259260+02:00 oldhanad1 pacemaker-controld[26190]:  notice: Stonith operation 2/1:0:0:455cd14f-a928-4de5-a0df-2e579a28b160: OK (0)
2022-04-21T13:21:51.259400+02:00 oldhanad1 pacemaker-controld[26190]:  notice: Peer oldhanad2 was terminated (reboot) by oldhanad1 on behalf of pacemaker-controld.26190: OK
2022-04-21T13:21:51.259532+02:00 oldhanad1 pacemaker-controld[26190]:  notice: Initiating start operation p-IP1_start_0 locally on oldhanad1
2022-04-21T13:21:51.259653+02:00 oldhanad1 pacemaker-controld[26190]:  notice: Requesting local execution of start operation for p-IP1 on oldhanad1
2022-04-21T13:21:51.260111+02:00 oldhanad1 pacemaker-execd[26187]:  notice: executing - rsc:p-IP1 action:start call_id:71
2022-04-21T13:21:51.752904+02:00 oldhanad1 pacemaker-execd[26187]:  notice: p-IP1 start (call 71, PID 1998) exited with status 0 (execution time 493ms, queue time 0ms)
2022-04-21T13:21:51.753448+02:00 oldhanad1 pacemaker-controld[26190]:  notice: Result of start operation for p-IP1 on oldhanad1: ok
2022-04-21T13:21:51.754685+02:00 oldhanad1 pacemaker-controld[26190]:  notice: Transition 0 (Complete=5, Pending=0, Fired=0, Skipped=0, Incomplete=0, Source=/var/lib/pacemaker/pengine/pe-warn-6.bz2): Complete
2022-04-21T13:21:51.754792+02:00 oldhanad1 pacemaker-controld[26190]:  notice: State transition S_TRANSITION_ENGINE -> S_IDLE
```

What happened? `controld` (*cluster resource manager*) is informed node is dead,
finally `schedulerd` (*policy engine*) decided to fence the node because it is
*unclean* (it does not have an idea what is going on with this node), `fenced`
is asked to prepare fencing the node, `execd` (*local resource manager*) in
practice runs fence agent to STONITH the node.

Summary:

- an unexpected node left
  `corosync[26152]:   [TOTEM ] Failed to receive the leave message. failed: 178438534`
- because of unclean status the node is going to be fenced
  `pacemaker-schedulerd[26189]:  notice:  * Fence (reboot) oldhanad2 'peer is no longer part of the cluster'`
- fence actually happends


### HAWK - web mgmt

[hawk](https://github.com/ClusterLabs/hawk) needs that a user is in
*haclient* group; it uses PAM
([*passwd*](https://github.com/ClusterLabs/hawk/blob/f9838ba95ed7a23ef4f8156b2b69031e8fadd19c/hawk/app/models/session.rb#L52)
service):

and web-based hawk (suse) *7630/tcp*

``` shell
# from a login attempt
$ strace -e status=successful -s 256 -f -e trace=file $(systemd-cgls -u hawk-backend.service | tail -n +2 | awk '{ ORS=" "; printf("-p %d ", $2) }') 2>&1 | grep /etc
[pid  6849] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
[pid  6849] stat("/etc/crypto-policies/back-ends/gnutls.config", {st_mode=S_IFREG|0644, st_size=1413, ...}) = 0
[pid  6849] openat(AT_FDCWD, "/etc/crypto-policies/back-ends/gnutls.config", O_RDONLY|O_CLOEXEC) = 3
[pid  6855] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
[pid  6855] stat("/etc/crypto-policies/back-ends/gnutls.config", {st_mode=S_IFREG|0644, st_size=1413, ...}) = 0
[pid  6855] openat(AT_FDCWD, "/etc/crypto-policies/back-ends/gnutls.config", O_RDONLY|O_CLOEXEC) = 3
[pid  6856] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
[pid  6856] access("/etc/pam.d/passwd", R_OK) = 0
[pid  6856] openat(AT_FDCWD, "/etc/nsswitch.conf", O_RDONLY|O_CLOEXEC) = 3
[pid  6856] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
[pid  6856] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
[pid  6856] openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
[pid  6856] openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
[pid  6856] openat(AT_FDCWD, "/etc/group", O_RDONLY|O_CLOEXEC) = 3
[pid  6856] stat("/etc/pam.d", {st_mode=S_IFDIR|0755, st_size=4096, ...}) = 0
[pid  6856] openat(AT_FDCWD, "/etc/pam.d/passwd", O_RDONLY) = 3
[pid  6856] openat(AT_FDCWD, "/etc/pam.d/common-auth", O_RDONLY) = 4
[pid  6856] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 5
[pid  6856] openat(AT_FDCWD, "/etc/pam.d/common-account", O_RDONLY) = 4
[pid  6856] openat(AT_FDCWD, "/etc/pam.d/common-password", O_RDONLY) = 4
[pid  6856] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 5
[pid  6856] openat(AT_FDCWD, "/etc/pam.d/common-session", O_RDONLY) = 4
[pid  6856] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 5
[pid  6856] openat(AT_FDCWD, "/etc/pam.d/other", O_RDONLY) = 3
[pid  6856] openat(AT_FDCWD, "/etc/login.defs", O_RDONLY) = 3
[pid  6856] openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
[pid  6856] openat(AT_FDCWD, "/etc/shadow", O_RDONLY|O_CLOEXEC) = 3
[pid  6856] openat(AT_FDCWD, "/etc/security/pam_env.conf", O_RDONLY) = 3
[pid  6856] openat(AT_FDCWD, "/etc/environment", O_RDONLY) = 3
[pid  6856] openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
[pid  6856] openat(AT_FDCWD, "/etc/login.defs", O_RDONLY) = 3
[pid  6857] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
[pid  6857] stat("/etc/crypto-policies/back-ends/gnutls.config", {st_mode=S_IFREG|0644, st_size=1413, ...}) = 0
[pid  6857] openat(AT_FDCWD, "/etc/crypto-policies/back-ends/gnutls.config", O_RDONLY|O_CLOEXEC) = 3
[pid  6858] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
[pid  6858] stat("/etc/crypto-policies/back-ends/gnutls.config", {st_mode=S_IFREG|0644, st_size=1413, ...}) = 0
[pid  6858] openat(AT_FDCWD, "/etc/crypto-policies/back-ends/gnutls.config", O_RDONLY|O_CLOEXEC) = 3
[pid  6864] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
[pid  6864] stat("/etc/crypto-policies/back-ends/gnutls.config", {st_mode=S_IFREG|0644, st_size=1413, ...}) = 0
[pid  6864] openat(AT_FDCWD, "/etc/crypto-policies/back-ends/gnutls.config", O_RDONLY|O_CLOEXEC) = 3
```


### SBD - storage based death aka STONITH block device

What is purpose of SBD?

- fence agent/device (STONITH)
- self-fence if SBD device can't be read for some time (Shoot myself in the head, SMITH) ??
  https://www.suse.com/support/kb/doc/?id=000017950
- monitor SBD device (if any)
- monitor Pacemaker CIB
- monitor corosync health

*SBD_STARTMODE=clean* in `/etc/sysconfig/sdb` (SUSE) to prevent
starting cluster if non-clean state exists on SBD

SBD sets a used watchdog `timeout` based on `SBD_WATCHDOG_TIMEOUT` on its start.

> SBD_WATCHDOG_TIMEOUT (e.g. in /etc/sysconfig/sbd) is already the
> timeout the hardware watchdog is configured to by sbd-daemon.
> sbd-daemon is triggering faster - timeout_loop defaults to 1s but
> is configurable.
> Cf. https://lists.clusterlabs.org/pipermail/users/2016-December/021051.html

``` shell
$ grep -H '' /sys/class/watchdog/watchdog0/{timeout,identity,state} 2>/dev/null
/sys/class/watchdog/watchdog0/timeout:5
/sys/class/watchdog/watchdog0/identity:iTCO_wdt
/sys/class/watchdog/watchdog0/state:active

$ grep -Pv '^\s*(#|$)' /etc/sysconfig/sbd | grep WATCHDOG_TIMEOUT
SBD_WATCHDOG_TIMEOUT=5
```

See: https://github.com/ClusterLabs/sbd/blob/8cd0885a48a676dd27f0a9ef1c860990cb4d1307/src/sbd-watchdog.c#L100 .

RH does not support `softdog` based SBDs!

``` shell
sbd query-watchdog                                 # check if sbd finds watcdog devices
sbd -w <watchdog_device> test-watchdog             # test if reset via watchdog works,
                                                   # this RESETS node!
```

*sbd* watches both *corosync* and *pacemaker*; as for Pacemaker:

> Pacemaker is setting the node unclean which pacemaker-watcher (one
> of sbd daemons) sees as it is connected to the cib.  This is why the
> mechanism is working (sort of - see the discussion in my pull
> request in the sbd-repo) on nodes without stonithd as well
> (remote-nodes).  If you are running sbd with a block-device there is
> of course this way of communication as well between pacemaker and
> sbd.  (e.g. via fence_sbd fence-agent)
> Cf. https://lists.clusterlabs.org/pipermail/users/2016-December/021074.html

SBD watchers:

``` shell
$ systemd-cgls -u sbd.service
Unit sbd.service (/system.slice/sbd.service):
├─2703 sbd: inquisitor
├─2704 sbd: watcher: /dev/disk/by-id/scsi-36001405714d7f9602b045ee82274b815 - slot: 5 - uuid: 41e0e03c-5618-459e-b3ea-73ddb98d442a
├─2705 sbd: watcher: Pacemaker
└─2706 sbd: watcher: Cluster
```

- `inquisitor`, a kind of dead-men switch
- `watcher: /dev/disk/by-id/scsi-36001405714d7f9602b045ee82274b815 -
  slot: 5 - uuid: 41e0e03c-5618-459e-b3ea-73ddb98d442a`, monitors
  shared disk device
- `watcher: Pacemaker`, monitors if the cluster partition the node is
  in is still quorate according to Pacemaker CIB, and the node itself
  is still considered online and healthy by Pacemaker
- `watcher: Cluster`, monitors if the cluster is still quorate
  according to Corosync's node count

As for corosync watcher, it seems it is "registred" into corosync:

```
$ corosync-cpgtool | grep -A1 sbd
sbd:cluster\x00
                      2706       178438533 (10.162.193.133)
$ ps auxww | grep '[2]706'
root      2706  0.0  0.0 135268 39364 ?        SL   Apr21   3:59 sbd: watcher: Cluster
```

``` shell
sbd -d /dev/<shared_lun> create                    # prepares shared lun for SBD
sbd -d /dev/<shared_lun> dump                      # info about SBD
```

``` shell
# . /etc/sysconfig/sbd;export SBD_DEVICE;sbd dump;sbd list
==Dumping header on disk /dev/loop0
Header version     : 2.1
UUID               : 8233d0a1-1f94-4d88-9e22-485d4dfc1080
Number of slots    : 255
Sector size        : 512
Timeout (watchdog) : 5
Timeout (allocate) : 2
Timeout (loop)     : 1
Timeout (msgwait)  : 10

# dd if=/dev/loop0 bs=32 count=2 2>/dev/null | xxd
00000000: 5342 445f 5342 445f 02ff 0000 0000 0200  SBD_SBD_........
00000010: 0000 0005 0000 0002 0000 0001 0000 000a  ................
00000020: 0182 33d0 a11f 944d 889e 2248 5d4d fc10  ..3....M.."H]M..
00000030: 8000 0000 0000 0000 0000 0000 0000 0000  ................
```

``` shell

systemctl enable sbd                               # MUST be enabled, creates dependency
                                                   # on cluster stack services
systemctl list-dependencies sbd --reverse --all    # check sbd is part of cluster stack

sbd -d /dev/<shared_lun> list                      # list nodes slots and messages

# to make following tests work, sbd has to be running (as part of corosync)
sbd -d /dev/<shared_lun>  message <node> test      # node's sbd would log the test

sbd -d <block_dev> message <node> clear # clear sbd state for a node, restart pacemaker!
```


Two disks SBD:

TODO: ...

```
int quorum_read(int good_servants)
{
	if (disk_count > 2)
		return (good_servants > disk_count/2);
	else
		return (good_servants > 0);
}
```
Cf. https://github.com/ClusterLabs/sbd/blob/92ff8d811c68c0fcf8a406cf4f333fff37da30f9/src/sbd-inquisitor.c#L475.

Diskless SBD:

Usually three nodes, a kind of self-fence feature.

- inquisitor
- watcher: Pacemaker
- watcher: Cluster

It's not visible on `crm configure show` as resource, only property
`cib-bootstrap-options` stonith options need to be set. It will
self-fence if cannot see other nodes.

In diskless SBD, this is what `stonith_admin` thinks about it:

``` shell
$ crm configure show type:property
property cib-bootstrap-options: \
        have-watchdog=true \
        no-quorum-policy=freeze \
        dc-version="2.1.5+20221208.a3f44794f-150500.6.14.4-2.1.5+20221208.a3f44794f" \
        cluster-infrastructure=corosync \
        cluster-name=jb155sapqe \
        stonith-watchdog-timeout=-1

$ crm configure show related:external/sbd | grep -c '' # that is, no 'external/sbd' primitive
0

$ stonith_admin -L
watchdog
1 fence device found

$ stonith_admin -l $(hostname)
watchdog
1 fence device found
```

In pacemaker.log the above query logs...

```
May 10 08:28:15.633 jb155sapqe02 pacemaker-fenced    [1865] (can_fence_host_with_device)        info: watchdog is eligible to fence (off) jb155sapqe02: static-list
```

Thus, it is a hack, IMO.


## csync2

Clusterfile syncronization, `/etc/csync2/csync2.cfg`, *30865/tcp*, key-based authentication

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

Wrong peer certificate!

``` shell
jb155sapqe02:~ # csync2 -xv
Connecting to host jb155sapqe01 (SSL) ...
Connect to 192.168.252.100:30865 (jb155sapqe01).
Peer did provide a wrong SSL X509 cetrificate.

jb155sapqe02:~ # openssl x509 \
  -in /etc/csync2/csync2_ssl_cert.pem -inform PEM -outform DER | xxd -p
308202cf30820256a00302010202140b22b7456312e2ad6410c924d2f55d
bf0bace40d300a06082a8648ce3d04030230819e310b3009060355040613
022d2d3112301006035504080c09536f6d6553746174653111300f060355
04070c08536f6d654369747931193017060355040a0c10536f6d654f7267
616e697a6174696f6e31193017060355040b0c10536f6d654f7267616e69
7a6174696f6e3111300f06035504030c08536f6d654e616d65311f301d06
092a864886f70d01090116106e616d65406578616d706c652e636f6d301e
170d3234313132383133343732335a170d3333303231343133343732335a
30819e310b3009060355040613022d2d3112301006035504080c09536f6d
6553746174653111300f06035504070c08536f6d65436974793119301706
0355040a0c10536f6d654f7267616e697a6174696f6e3119301706035504
0b0c10536f6d654f7267616e697a6174696f6e3111300f06035504030c08
536f6d654e616d65311f301d06092a864886f70d01090116106e616d6540
6578616d706c652e636f6d3076301006072a8648ce3d020106052b810400
2203620004af32f54fd831a468c78bd4bd4c271fad9d19fd2e1ec6cf18c4
c6ca8edaa8529cca22f811e979bbb5fbc5eb53a3c07308c9c755671196fc
70f6345294cd5422c73a7a592406869028d5fdd5bf85421708e230c6a6eb
d752cc9e9429d17c5adf34a3533051301d0603551d0e04160414c8757186
c1a1b3705ffdef78131998a961c9849f301f0603551d23041830168014c8
757186c1a1b3705ffdef78131998a961c9849f300f0603551d130101ff04
0530030101ff300a06082a8648ce3d04030203670030640230425117a116
e284b9c5bc01862c91e21e233f57044b4597cda2f775caa770427a9bf118
00c3e0fa17cb28f535be3657ee02300ae2ea87439066cc793b9d640b44b0
23f34d33f8ee65615a2d31a8e94657ad5bda7cab220345bcecfeb16ade26
8341f7

jb155sapqe02:~ # ssh jb155sapqe01 \
  "sqlite3 /var/lib/csync2/jb155sapqe01.db3 \"SELECT certdata from x509_cert where peername = 'jb155sapqe02';\"" | fold -w60
308202CF30820256A0030201020214666D487F078E301754D06DB028FF5E
C4B5F8E782300A06082A8648CE3D04030230819E310B3009060355040613
022D2D3112301006035504080C09536F6D6553746174653111300F060355
04070C08536F6D654369747931193017060355040A0C10536F6D654F7267
616E697A6174696F6E31193017060355040B0C10536F6D654F7267616E69
7A6174696F6E3111300F06035504030C08536F6D654E616D65311F301D06
092A864886F70D01090116106E616D65406578616D706C652E636F6D301E
170D3233303931323037333632305A170D3331313132393037333632305A
30819E310B3009060355040613022D2D3112301006035504080C09536F6D
6553746174653111300F06035504070C08536F6D65436974793119301706
0355040A0C10536F6D654F7267616E697A6174696F6E3119301706035504
0B0C10536F6D654F7267616E697A6174696F6E3111300F06035504030C08
536F6D654E616D65311F301D06092A864886F70D01090116106E616D6540
6578616D706C652E636F6D3076301006072A8648CE3D020106052B810400
2203620004D395908B7DC38DF493366BB8FF92DD99ABBA3C8F8423CAEF0A
CEB1A7C46A3EC04DB83E82BDF61C43A53716FCC4F01C9BE8D664E62BE3DD
590F0E5AAC262E173EDE1ECC6853AEB403ED45D096C8C4CA2A649DD9EBEA
71BF1195F57B87E890E91AA3533051301D0603551D0E04160414C5997188
D0FB5CC99344780BF729203DDBA4608C301F0603551D23041830168014C5
997188D0FB5CC99344780BF729203DDBA4608C300F0603551D130101FF04
0530030101FF300A06082A8648CE3D040302036700306402304A3837F9CE
7FE76E5CA1A344861D1B00118AF2A39D700D87A1A128A2946085509F2B3C
47B1E886DB37A25561835152A302307270994CB73C1AD05B40FE4DE42C11
3C9FC10BDA5E7D771C1301439CF958409C62B973060F7A795F08F75F88C5
EB3B33

# so they really differ!
```


### DRBD in cluster

Some notes about drbd design:

- *primary*/*secondary*: primary has r/w, secondary NOT even r/o !!!
- *single primary mode*: ONLY ONE node has r/w (a fail-over scenario)
- *dual-primary  mode*:  more  nodes  has r/w  (this  would  require  a
  filesystem which implements locking, eg. ocfs2)
- *async replication*: aka 'Protocol A', write is considered completed
  on primary node(s) if written to local disk and the replication
  packet placed in local TCP send buffer (thus, when this 'local'
  machine crashed, no updates on the other node !!!)
- *sync replicaiton*: aka 'Protocol C', write is considered completed on
  primary node(s) if local and remote disk writes are confirmed
- DRBD >= 9 allows multiple nodes replication without 'stacking'
- *inconsistent* data state: data are partly obsolete, partly updated
- *suspended replication*: when a replication link is congested, drbd
  can temporarily suspend replication
- *online device verification*: an intergrity check, a good candicate
  for cron job (think about it as *mdraid sync_action*-like action)
- *split brain*: a situation when both nodes were switched to
  *primary* while being previosly disconnected (ie. likely two
  diverging sets of data exist); do NOT confuse with a *cluster
  partition* !!!

Configs `/etc/drbd.{conf,d/*.res}`

``` shell
drbdadm [create | up | status] <resource>
drbdadm new-current-uuid --clear-bitmap <resource>/0
```

DRBD can be used under Pacemaker/Corosync, the RA is in *drbd-utils*
package on SUSE.

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

Handlers, `fence-peer`, fences other node and puts location constraint
so other node cannot be used if not synced:

``` shell
$ grep crm-fence /var/log/messages
2023-05-22T12:47:51.528164+02:00 node02 crm-fence-peer.9.sh[18335]: DRBD_BACKING_DEV_0=/dev/sdb DRBD_CONF=/etc/drbd.conf DRBD_CSTATE=Connecting DRBD_LL_DISK=/dev/sdb DRBD_MINOR=0 DRBD_MINOR_0=0 DRBD_MY_ADDRESS=10.40.40.42 DRBD_MY_AF=ipv4 DRBD_MY_NODE_ID=1 DRBD_NODE_ID_0=node01 DRBD_NODE_ID_1=node02 DRBD_PEER_ADDRESS=10.40.40.41 DRBD_PEER_AF=ipv4 DRBD_PEER_NODE_ID=0 DRBD_RESOURCE=r0 DRBD_VOLUME=0 UP_TO_DATE_NODES=0x00000002 /usr/lib/drbd/crm-fence-peer.9.sh
2023-05-22T12:47:51.930204+02:00 node02 crm-fence-peer.9.sh[18335]: /
2023-05-22T12:47:51.931920+02:00 node02 crm-fence-peer.9.sh[18335]: INFO peers are (node-level) fenced, my disk is UpToDate: placed constraint 'drbd-fence-by-handler-r0-ms-p-drbd-r0'
```

After fence, the location constraint is created:

```
$ crm configure show type:location
location drbd-fence-by-handler-r0-ms-p-drbd-r0 ms-p-drbd-r0 \
        rule $role=Master -inf: #uname ne node02
```

`after-resync-target` is a handler which removes _location_ constraint
when the node is in sync:

```
$ grep -P '(Linux version|unfence)' /var/log/messages | tail -n3
2023-05-22T13:48:19.311670+02:00 node01 kernel: [    0.000000][    T0] Linux version 5.14.21-150400.24.21-default (geeko@buildhost) (gcc (SUSE Linux) 7.5.0, GNU ld (GNU Binutils; SUSE Linux Enterprise 15) 2.37.20211103-150100.7.37) #1 SMP PREEMPT_DYNAMIC Wed Sep 7 06:51:18 UTC 2022 (974d0aa)
2023-05-22T13:52:46.024106+02:00 node01 crm-unfence-peer.9.sh[3681]: DRBD_BACKING_DEV=/dev/sdb DRBD_CONF=/etc/drbd.conf DRBD_CSTATE=Connected DRBD_LL_DISK=/dev/sdb DRBD_MINOR=0 DRBD_MY_ADDRESS=10.40.40.41 DRBD_MY_AF=ipv4 DRBD_MY_NODE_ID=0 DRBD_NODE_ID_0=node01 DRBD_NODE_ID_1=node02 DRBD_PEER_ADDRESS=10.40.40.42 DRBD_PEER_AF=ipv4 DRBD_PEER_NODE_ID=1 DRBD_RESOURCE=r0 DRBD_VOLUME=0 UP_TO_DATE_NODES='' /usr/lib/drbd/crm-unfence-peer.9.sh
2023-05-22T13:52:46.179836+02:00 node01 crm-unfence-peer.9.sh[3681]: INFO Removed constraint 'drbd-fence-by-handler-r0-ms-p-drbd-r0'
```

#### Clustered DRBD troubleshooting

On first node, `drbdadm up <res>` is executed (`drbd01` is the resource name here):

```
2023-02-06T16:43:30.921702+01:00 jb154sapqe01 kernel: [18310.608989][T25362] drbd drbd01: Starting worker thread (from drbdsetup [25362])
2023-02-06T16:43:30.926543+01:00 jb154sapqe01 kernel: [18310.615090][T25368] drbd drbd01 jb154sapqe02: Starting sender thread (from drbdsetup [25368])
2023-02-06T16:43:31.002626+01:00 jb154sapqe01 kernel: [18310.688562][T25381] drbd drbd01/0 drbd1: meta-data IO uses: blk-bio
2023-02-06T16:43:31.002637+01:00 jb154sapqe01 kernel: [18310.689931][T25381] drbd drbd01/0 drbd1: disk( Diskless -> Attaching )
2023-02-06T16:43:31.002638+01:00 jb154sapqe01 kernel: [18310.691079][T25381] drbd drbd01/0 drbd1: Maximum number of peer devices = 1
2023-02-06T16:43:31.002639+01:00 jb154sapqe01 kernel: [18310.692308][T25381] drbd drbd01: Method to ensure write ordering: flush
2023-02-06T16:43:31.006611+01:00 jb154sapqe01 kernel: [18310.693393][T25381] drbd drbd01/0 drbd1: drbd_bm_resize called with capacity == 2097016
2023-02-06T16:43:31.006621+01:00 jb154sapqe01 kernel: [18310.694739][T25381] drbd drbd01/0 drbd1: resync bitmap: bits=262127 words=4096 pages=8
2023-02-06T16:43:31.006622+01:00 jb154sapqe01 kernel: [18310.695950][T25381] drbd1: detected capacity change from 0 to 2097016
2023-02-06T16:43:31.006623+01:00 jb154sapqe01 kernel: [18310.696925][T25381] drbd drbd01/0 drbd1: size = 1024 MB (1048508 KB)

2023-02-06T16:43:31.011445+01:00 jb154sapqe01 kernel: [18310.699910][T25381] drbd drbd01/0 drbd1: recounting of set bits took additional 0ms
2023-02-06T16:43:31.011454+01:00 jb154sapqe01 kernel: [18310.701195][T25381] drbd drbd01/0 drbd1: disk( Attaching -> Inconsistent )
2023-02-06T16:43:31.014416+01:00 jb154sapqe01 kernel: [18310.702390][T25381] drbd drbd01/0 drbd1 jb154sapqe02: pdsk( DUnknown -> Outdated )
2023-02-06T16:43:31.014421+01:00 jb154sapqe01 kernel: [18310.703587][T25381] drbd drbd01/0 drbd1: attached to current UUID: 0000000000000004
2023-02-06T16:43:31.022032+01:00 jb154sapqe01 kernel: [18310.710893][T25384] drbd drbd01 jb154sapqe02: conn( StandAlone -> Unconnected )
2023-02-06T16:43:31.025714+01:00 jb154sapqe01 kernel: [18310.713251][T25363] drbd drbd01 jb154sapqe02: Starting receiver thread (from drbd_w_drbd01 [25363])
2023-02-06T16:43:31.025723+01:00 jb154sapqe01 kernel: [18310.714925][T25388] drbd drbd01 jb154sapqe02: conn( Unconnected -> Connecting )
```

Then on the second node, `drbdadm up <res>` was executed:

```
2023-02-06T16:44:25.097928+01:00 jb154sapqe02 kernel: [ 4133.662936][T23971] drbd drbd01: Starting worker thread (from drbdsetup [23971])
2023-02-06T16:44:25.105031+01:00 jb154sapqe02 kernel: [ 4133.668966][T23977] drbd drbd01 jb154sapqe01: Starting sender thread (from drbdsetup [23977])
2023-02-06T16:44:25.121096+01:00 jb154sapqe02 systemd[1]: Started Disk encryption utility (cryptctl) - contact key server to unlock disk sys-devices-virtual-block-drbd1 and keep the server informed.
2023-02-06T16:44:25.157486+01:00 jb154sapqe02 kernel: [ 4133.712273][T23985] drbd drbd01/0 drbd1: meta-data IO uses: blk-bio
2023-02-06T16:44:25.157517+01:00 jb154sapqe02 kernel: [ 4133.714282][T23985] drbd drbd01/0 drbd1: disk( Diskless -> Attaching )
2023-02-06T16:44:25.157520+01:00 jb154sapqe02 kernel: [ 4133.716103][T23985] drbd drbd01/0 drbd1: Maximum number of peer devices = 1
2023-02-06T16:44:25.157522+01:00 jb154sapqe02 kernel: [ 4133.717721][T23985] drbd drbd01: Method to ensure write ordering: flush
2023-02-06T16:44:25.157522+01:00 jb154sapqe02 kernel: [ 4133.719474][T23985] drbd drbd01/0 drbd1: drbd_bm_resize called with capacity == 2097016
2023-02-06T16:44:25.157524+01:00 jb154sapqe02 kernel: [ 4133.721096][T23985] drbd drbd01/0 drbd1: resync bitmap: bits=262127 words=4096 pages=8
2023-02-06T16:44:25.157527+01:00 jb154sapqe02 kernel: [ 4133.722356][T23985] drbd1: detected capacity change from 0 to 2097016
2023-02-06T16:44:25.157528+01:00 jb154sapqe02 kernel: [ 4133.723414][T23985] drbd drbd01/0 drbd1: size = 1024 MB (1048508 KB)
2023-02-06T16:44:25.179919+01:00 jb154sapqe02 kernel: [ 4133.739954][T23985] drbd drbd01/0 drbd1: recounting of set bits took additional 0ms
2023-02-06T16:44:25.179943+01:00 jb154sapqe02 kernel: [ 4133.741308][T23985] drbd drbd01/0 drbd1: disk( Attaching -> Inconsistent )
2023-02-06T16:44:25.179948+01:00 jb154sapqe02 kernel: [ 4133.742480][T23985] drbd drbd01/0 drbd1 jb154sapqe01: pdsk( DUnknown -> Outdated )
2023-02-06T16:44:25.179949+01:00 jb154sapqe02 kernel: [ 4133.743973][T23985] drbd drbd01/0 drbd1: attached to current UUID: 0000000000000004
2023-02-06T16:44:25.206361+01:00 jb154sapqe02 kernel: [ 4133.771504][T24001] drbd drbd01 jb154sapqe01: conn( StandAlone -> Unconnected )
2023-02-06T16:44:25.209702+01:00 jb154sapqe02 kernel: [ 4133.773775][T23972] drbd drbd01 jb154sapqe01: Starting receiver thread (from drbd_w_drbd01 [23972])
2023-02-06T16:44:25.213091+01:00 jb154sapqe02 kernel: [ 4133.777431][T24004] drbd drbd01 jb154sapqe01: conn( Unconnected -> Connecting )
2023-02-06T16:44:25.753573+01:00 jb154sapqe02 kernel: [ 4134.315811][T24004] drbd drbd01 jb154sapqe01: Handshake to peer 0 successful: Agreed network protocol version 120
2023-02-06T16:44:25.753606+01:00 jb154sapqe02 kernel: [ 4134.317930][T24004] drbd drbd01 jb154sapqe01: Feature flags enabled on protocol level: 0xf TRIM THIN_RESYNC WRITE_SAME WRITE_ZEROES.
2023-02-06T16:44:25.753620+01:00 jb154sapqe02 kernel: [ 4134.320172][T24004] drbd drbd01 jb154sapqe01: Starting ack_recv thread (from drbd_r_drbd01 [24004])
2023-02-06T16:44:25.845197+01:00 jb154sapqe02 kernel: [ 4134.406569][T24004] drbd drbd01 jb154sapqe01: Preparing remote state change 639728590
2023-02-06T16:44:25.863084+01:00 jb154sapqe02 kernel: [ 4134.423659][T24004] drbd drbd01/0 drbd1 jb154sapqe01: drbd_sync_handshake:
2023-02-06T16:44:25.863102+01:00 jb154sapqe02 kernel: [ 4134.424900][T24004] drbd drbd01/0 drbd1 jb154sapqe01: self 0000000000000004:0000000000000000:0000000000000000:0000000000000000 bits:0 flags:24
2023-02-06T16:44:25.863105+01:00 jb154sapqe02 kernel: [ 4134.427164][T24004] drbd drbd01/0 drbd1 jb154sapqe01: peer 0000000000000004:0000000000000000:0000000000000000:0000000000000000 bits:0 flags:24
2023-02-06T16:44:25.863107+01:00 jb154sapqe02 kernel: [ 4134.429441][T24004] drbd drbd01/0 drbd1 jb154sapqe01: uuid_compare()=no-sync by rule=just-created-both
2023-02-06T16:44:25.873019+01:00 jb154sapqe02 kernel: [ 4134.434324][T24004] drbd drbd01 jb154sapqe01: Committing remote state change 639728590 (primary_nodes=0)
2023-02-06T16:44:25.873030+01:00 jb154sapqe02 kernel: [ 4134.436028][T24004] drbd drbd01 jb154sapqe01: conn( Connecting -> Connected ) peer( Unknown -> Secondary )
2023-02-06T16:44:25.873031+01:00 jb154sapqe02 kernel: [ 4134.437557][T24004] drbd drbd01/0 drbd1 jb154sapqe01: pdsk( Outdated -> Inconsistent ) repl( Off -> Established )
```

And the log on the first node continues...

```
2023-02-06T16:44:25.754225+01:00 jb154sapqe01 kernel: [18365.439854][T25388] drbd drbd01 jb154sapqe02: Handshake to peer 1 successful: Agreed network protocol version 120
2023-02-06T16:44:25.754257+01:00 jb154sapqe01 kernel: [18365.441974][T25388] drbd drbd01 jb154sapqe02: Feature flags enabled on protocol level: 0xf TRIM THIN_RESYNC WRITE_SAME WRITE_ZEROES.
2023-02-06T16:44:25.754263+01:00 jb154sapqe01 kernel: [18365.444465][T25388] drbd drbd01 jb154sapqe02: Starting ack_recv thread (from drbd_r_drbd01 [25388])
2023-02-06T16:44:25.841754+01:00 jb154sapqe01 kernel: [18365.528511][T25370] drbd drbd01: Preparing cluster-wide state change 639728590 (0->1 499/146)
2023-02-06T16:44:25.859864+01:00 jb154sapqe01 kernel: [18365.544541][T25388] drbd drbd01/0 drbd1 jb154sapqe02: drbd_sync_handshake:
2023-02-06T16:44:25.859876+01:00 jb154sapqe01 kernel: [18365.545914][T25388] drbd drbd01/0 drbd1 jb154sapqe02: self 0000000000000004:0000000000000000:0000000000000000:0000000000000000 bits:0 flags:24
2023-02-06T16:44:25.859879+01:00 jb154sapqe01 kernel: [18365.548222][T25388] drbd drbd01/0 drbd1 jb154sapqe02: peer 0000000000000004:0000000000000000:0000000000000000:0000000000000000 bits:0 flags:24
2023-02-06T16:44:25.859880+01:00 jb154sapqe01 kernel: [18365.550515][T25388] drbd drbd01/0 drbd1 jb154sapqe02: uuid_compare()=no-sync by rule=just-created-both
2023-02-06T16:44:25.870707+01:00 jb154sapqe01 kernel: [18365.555374][T25370] drbd drbd01: State change 639728590: primary_nodes=0, weak_nodes=0
2023-02-06T16:44:25.870717+01:00 jb154sapqe01 kernel: [18365.556749][T25370] drbd drbd01: Committing cluster-wide state change 639728590 (28ms)
2023-02-06T16:44:25.870718+01:00 jb154sapqe01 kernel: [18365.558110][T25370] drbd drbd01 jb154sapqe02: conn( Connecting -> Connected ) peer( Unknown -> Secondary )
2023-02-06T16:44:25.870719+01:00 jb154sapqe01 kernel: [18365.559746][T25370] drbd drbd01/0 drbd1 jb154sapqe02: pdsk( Outdated -> Inconsistent ) repl( Off -> Established )
```


### Oracle cluster filesystem aka OCFS2

``` shell
$  mkfs.ocfs2 -L jb155sapqe-shared-lvm-ocfs2-0 /dev/sda
mkfs.ocfs2 1.8.7
Cluster stack: pcmk
Cluster name: jb155sapqe
Stack Flags: 0x0
NOTE: Feature extended slot map may be enabled
Label: jb155sapqe-shared-lvm-ocfs2-0
Features: sparse extended-slotmap backup-super unwritten inline-data strict-journal-super xattr indexed-dirs refcount discontig-bg append-dio
Block size: 4096 (12 bits)
Cluster size: 4096 (12 bits)
Volume size: 1073741824 (262144 clusters) (262144 blocks)
Cluster groups: 9 (tail covers 4096 clusters, rest cover 32256 clusters)
Extent allocator size: 4194304 (1 groups)
Journal size: 67108864
Node slots: 2
Creating bitmaps: done
Initializing superblock: done
Writing system files: done
Writing superblock: done
Writing backup superblock: 0 block(s)
Formatting Journals: done
Growing extent allocator: done
Formatting slot map: done
Formatting quota files: done
Writing lost+found: done
mkfs.ocfs2 successful

$ wipefs /dev/sda
DEVICE OFFSET TYPE  UUID                                 LABEL
sda    0x2000 ocfs2 2f8ab0fa-5f5f-486f-9518-5837f0662116 jb155sapqe-shared-lvm-ocfs2-0
```

SLES does not support anymore *o2cb* cluster stack:

``` shell
$ /sys/fs/ocfs2/cluster_stack
pcmk
```

Pacemaker/corosync stack configuration for *OCFS2* with
*"independent"* DLM and OCFS2 primitive:

``` shell
primitive dlm ocf:pacemaker:controld \
        op monitor interval=60 timeout=60 \
        op start timeout=90s interval=0s \
        op stop timeout=100s interval=0s
primitive ocfs2-0 Filesystem \
        params directory="/srv/ocfs2-0" fstype=ocfs2 device="/dev/disk/by-id/scsi-3600140534d0904dc8a24843897c4ad18" \
        op monitor interval=20 timeout=40
clone cl-dlm dlm \
        meta interleave=true
clone cl-ocfs2-0 ocfs2-0 \
        meta interleave=true
colocation co-ocfs2-1-with-dlm inf: cl-ocfs2-0 cl-dlm
order o-dlm-before-ocfs2-0 Mandatory: cl-dlm cl-ocfs2-0
```

Some `o2info` details:

``` shell
$ o2info --mkfs /dev/disk/by-id/scsi-3600140534d0904dc8a24843897c4ad18 | fmt -w80
-N 2 -J size=67108864 -b 4096 -C 4096 --fs-features
backup-super,strict-journal-super,sparse,extended-slotmap,userspace-stack,inline-data,xattr,indexed-dirs,refcount,discontig-bg,append-dio,unwritten
-L jb155sapqe-shared-lvm-ocfs2-0
```

See `userspace-stack`, that refers to:

``` shell
$ modinfo -d ocfs2_stack_user
ocfs2 driver for userspace cluster stacks
```

`o2info --volinfo` reveals number of cluster nodes too:

``` shell
$ o2info --volinfo /dev/sda
       Label: jb155sapqe-shared-lvm-ocfs2-0
        UUID: 80038ED0D6B44AF7B617AE40DC337DF8
  Block Size: 4096
Cluster Size: 4096
  Node Slots: 2
    Features: backup-super strict-journal-super sparse extended-slotmap
    Features: userspace-stack inline-data xattr indexed-dirs refcount
    Features: discontig-bg append-dio unwritten
```
