# SAP training

## SAP applications:

- SAP Netweaver
  * the SAP app with external database
  * a kind of transaction application (db transactions create SAP transaction;
    enqueue (ENQ) locks/process on one node <==> enqueue replication server (ERS)
    synchronization on other node, high-availability (HA) extremely important!
  * flavors (how locks is replicated):
    - ENSA1 (obsolete; shared memory over network; ERS cluster resource agents
      run only when both nodes are up)
    - ENSA2 (replication designed as client/server mode; ERS cluster resource
      agents run on both nodes)
- SAP HANA
  * the SAP app including memory-based built-in database, runs only on Linux
  * flavors:
    - HANA1 (many online tutorials refer to this because it was novelty and not
      easy to setup)
    - HANA2


### SAP Hana

Some SAP basic vocabulary/info:

- *SID* aka SAP System Identification
- *SAP instance number*, 00-94, define also a port "offset" from usual TCP port
  ``` shell
  # comments inline
  $ lm:ps1adm> ps auxww | grep '[h]dbindex'
  spsadm    3856  3.8 19.5 11325428 7834684 ?    Sl   Apr28 678:11 hdbindexserver -port 30103
                                                                                         ^^ instance number of SPS sid
  ps1adm   28702  4.2 11.3 7355672 4542208 ?     Sl   May05 296:08 hdbindexserver -port 30003
                                                                                         ^^ instance number of PS1 sid
- `/usr/sap/sapservices`, this file is NOT included/ran as usual shell script but
  it contains info about local SIDs/instances
  ``` shell
  lm:ps1adm> cat /usr/sap/sapservices
  #!/bin/sh
  LD_LIBRARY_PATH=/usr/sap/PS1/HDB00/exe:$LD_LIBRARY_PATH;export LD_LIBRARY_PATH;/usr/sap/PS1/HDB00/exe/sapstartsrv pf=/usr/sap/PS1/SYS/profile/PS1_HDB00_lm -D -u ps1adm
                                                                                                 ^^ instance number
  limit.descriptors=1048576
  LD_LIBRARY_PATH=/usr/sap/SPS/HDB01/exe:$LD_LIBRARY_PATH;export LD_LIBRARY_PATH;/usr/sap/SPS/HDB01/exe/sapstartsrv pf=/usr/sap/SPS/SYS/profile/SPS_HDB01_lm -D -u spsadm
                                                                                                 ^^ instance number
  ```

SUSE SAP documentation:
[documentation.suse.com/sbp/all/](https://documentation.suse.com/sbp/all)


#### HOWTO install SAP HANA2 for testing on SLES

SAP HANA needs only little space in `/usr/` (`/usr/sap`), it creates a lot of
symlinks to real HANA directory (eg. `/hana`).

``` shell
$ zypper in -t pattern sap-hana
$ zypper in supportutils-plugin-ha-sap

$ saptune solution verify

$ findmnt | grep /hana
├─/hana/data                          /dev/mapper/hana-lvol0                              xfs        rw,relatime,attr2,inode64,logbufs=8,logbsize=32k,noquota
├─/hana/log                           /dev/mapper/hana-lvol1                              xfs        rw,relatime,attr2,inode64,logbufs=8,logbsize=32k,noquota
└─/hana/shared                        192.168.0.1:/data/nfs/xxxxxx/jb154sapqe/hana-shared nfs4       rw,relatime,vers=4.2,rsize=1048576,wsize=1048576,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=192.168.0.57,local_lock=none,addr=192.168.0.1
```

OS tunning:

saptune v1, sapconf (old but also for plain SLES), new saptune written
in Go and uses tuned (only SLES4SAP)

An installation media should be available:

``` shell
$ mount -t nfs <nfsserver>:/srv/nfs/sap /mnt # install media
$ cd /mnt
$ cd /HANA2
$ cd SPS05rev57 # version/revision of SAP HANA
$ cd x86_64
$ cat CDLABEL.ASC
$ cd DATA_UNITS
$ cd HDB_LCM_LINUX_X86_64 # Hana database life-cycle management
```

Starting the installer:

``` shell
$ ./hdblcm --action=install --dump_configfile_template=/root/hana.tmpl # template config

$ ./hdblcm --action=install --ignore=check_min_mem # installer
...
> 1 (install action)
> 2 (server component)
> /hana/shared
> 1 (install new system)
> 2 (server component)
> /hana/shared
> <local hostname>
> n (add hosts to the system? scale-out)
> SID -> BSD
> instance number -> 00
> default (local host worker group)
> 2 (index)
> n (log encryption)
> <enter>
> <enter>
> maximum memory allocation -> n
> resource limits -> y
> <password> -> Suse1234
> <password> -> Suse1234
> ..
> ..
> y (continue)
```

##### Post-installation steps

SAP always works under a `<sid>adm` user, eg. `bsdadm`.

``` shell
$ su - bsdadm
bsdadm> pwd
/usr/sap/BSD/HDB00

bsdadm> find /usr/sap -type l -ls 2>/dev/null
   926065      0 lrwxrwxrwx   1  bsdadm   sapsys         23 May 10 14:45 /usr/sap/BSD/SYS/global -> /hana/shared/BSD/global
   926067      0 lrwxrwxrwx   1  bsdadm   sapsys         36 May 10 14:45 /usr/sap/BSD/SYS/exe/hdb -> /hana/shared/BSD/exe/linuxx86_64/hdb
   926063      0 lrwxrwxrwx   1  bsdadm   sapsys         24 May 10 14:45 /usr/sap/BSD/SYS/profile -> /hana/shared/BSD/profile
   971103      0 lrwxrwxrwx   1  bsdadm   sapsys         22 May 10 14:46 /usr/sap/BSD/HDB00 -> /hana/shared/BSD/HDB00

bsdadm> ls -ld /usr/sap/BSD/HDB00
lrwxrwxrwx 1 bsdadm sapsys 22 May 10 14:43 /usr/sap/BSD/HDB00 -> /hana/shared/BSD/HDB00
```

SAP has its own tools, of course:

``` shell
bsdadm> HDB info
USER          PID     PPID  %CPU        VSZ        RSS COMMAND
bsdadm      28370    28369   0.1      18576       8444 -sh
bsdadm      28566    28370   0.0      13992       3804  \_ /bin/sh /usr/sap/BSD/HDB00/HDB info
bsdadm      28601    28566   0.0      41516       3840      \_ ps fx -U bsdadm -o user:8,pid:8,ppid:8,pcpu:5,vsz:10,rs
bsdadm      18448        1   0.0     715956      54596 hdbrsutil  --start --port 30003 --volume 3 --volumesuffix mnt00
bsdadm      18058        1   0.0     715896      52216 hdbrsutil  --start --port 30001 --volume 1 --volumesuffix mnt00
bsdadm      17924        1   0.0      23368       3068 sapstart pf=/hana/shared/BSD/profile/BSD_HDB00_oldhanae2
bsdadm      17931    17924   0.0     460420      71640  \_ /usr/sap/BSD/HDB00/oldhanae2/trace/hdb.sapBSD_HDB00 -d -nw
bsdadm      17951    17931   2.7    8861708    5766336      \_ hdbnameserver
bsdadm      18161    17931   0.5     458104     136576      \_ hdbcompileserver
bsdadm      18164    17931   7.7     982372     409248      \_ hdbpreprocessor
bsdadm      18210    17931   4.3    8833816    5873876      \_ hdbindexserver -port 30003
bsdadm      18213    17931   1.0    3714108    1297932      \_ hdbxsengine -port 30007
bsdadm      18668    17931   0.5    2387428     588576      \_ hdbwebdispatcher
bsdadm      17773        1   0.0     502516      34116 /usr/sap/BSD/HDB00/exe/sapstartsrv pf=/hana/shared/BSD/profile/
```

``` shell
bsdadm> sapcontrol -nr 00 -function GetProcessList

11.05.2022 11:19:18
GetProcessList
OK
name, description, dispstatus, textstatus, starttime, elapsedtime, pid
hdbdaemon, HDB Daemon, GREEN, Running, 2022 05 10 14:45:54, 20:33:24, 17931
hdbcompileserver, HDB Compileserver, GREEN, Running, 2022 05 10 14:46:35, 20:32:43, 18161
hdbnameserver, HDB Nameserver, GREEN, Running, 2022 05 10 14:45:54, 20:33:24, 17951
hdbpreprocessor, HDB Preprocessor, GREEN, Running, 2022 05 10 14:46:35, 20:32:43, 18164
hdbwebdispatcher, HDB Web Dispatcher, GREEN, Running, 2022 05 10 14:47:37, 20:31:41, 18668
hdbindexserver, HDB Indexserver-BSD, GREEN, Running, 2022 05 10 14:46:35, 20:32:43, 18210
hdbxsengine, HDB XSEngine-BSD, GREEN, Running, 2022 05 10 14:46:35, 20:32:43, 18213
```

``` shell
# sapcontrol can be run under 'root' user too

id ; /usr/sap/hostctrl/exe/sapcontrol -nr 00 -function GetProcessList
uid=0(root) gid=0(root) groups=0(root)

11.05.2022 11:42:51
GetProcessList
OK
name, description, dispstatus, textstatus, starttime, elapsedtime, pid
hdbdaemon, HDB Daemon, GREEN, Running, 2022 05 10 14:45:54, 20:56:57, 17931
hdbcompileserver, HDB Compileserver, GREEN, Running, 2022 05 10 14:46:35, 20:56:16, 18161
hdbnameserver, HDB Nameserver, GREEN, Running, 2022 05 10 14:45:54, 20:56:57, 17951
hdbpreprocessor, HDB Preprocessor, GREEN, Running, 2022 05 10 14:46:35, 20:56:16, 18164
hdbwebdispatcher, HDB Web Dispatcher, GREEN, Running, 2022 05 10 14:47:37, 20:55:14, 18668
hdbindexserver, HDB Indexserver-BSD, GREEN, Running, 2022 05 10 14:46:35, 20:56:16, 18210
hdbxsengine, HDB XSEngine-BSD, GREEN, Running, 2022 05 10 14:46:35, 20:56:16, 18213
```

`sapcontrol -nr <instance> -function GetProcessList` explanation:

- *Green*, all OK
- *Yellow*, on the way/changing status
- *Grey*, off

SAP also includes python helpers:

``` shell
bsdadm> alias | grep cdpy
cdpy='cd $DIR_INSTANCE/exe/python_support'

oldhanae1:bsdadm> cdpy

oldhanae1:bsdadm> pwd
/usr/sap/BSD/HDB00/exe/python_support

oldhanae1:bsdadm> ls -1 | head
base_classes.py
cancelCursor.py
cancellationTestUtils.py
cds
ComboBox.dat
ComboBox.py
connectionManager.py
convertConcatAttributes.py
convertMDC.py
decoratedDbApiCursor.py
```

SAP HANA configuration:

``` shell
bsdadm> pwd
/usr/sap/BSD/HDB00

bsdadm> alias | grep cdcoc
cdcoc='cd /usr/sap/$SAPSYSTEMNAME/SYS/global/hdb/custom/config'

bsdadm> cdcoc

bsdadm> pwd
/usr/sap/BSD/SYS/global/hdb/custom/config

bsdadm> cat global.ini
# global.ini last modified 2022-05-10 14:47:40.123881 by /usr/sap/BSD/HDB00/exe/hdbnsutil -initTopology --workergroup=default --set_user_system_pw
[multidb]
mode = multidb
database_isolation = low
singletenant = yes

[persistence]
basepath_datavolumes = /hana/data/BSD
basepath_logvolumes = /hana/log/BSD

[system_information]
usage = test
```

SAP HANA logs:

``` shell
bsdadm> alias | grep cdtrace
cdtrace='cd $DIR_INSTANCE/$VTHOSTNAME/trace'

bsdadm> cdtrace ; pwd
/usr/sap/BSD/HDB00/oldhanae1/trace

bsdadm> ls -1 *.log
available.log
hdbinst_2022-05-10_14.45.06_2152.log
sapstart.log
sapstartsrv.log
```

SAP processes:

- hdbnameserver - core element, a kind of load balancer
- hdbindexserver - another core element
- ...

##### Test system replication setup

- two nodes with SAP HANA installed, same SID and instance
- working TCP/IP and SSH
- HW resources (???)

``` shell
# first check global.ini
bsdadm> cdcoc

bsdadm> cat global.ini
# global.ini last modified 2022-05-10 14:47:40.123881 by /usr/sap/BSD/HDB00/exe/hdbnsutil -initTopology --workergroup=default --set_user_system_pw
[multidb]
mode = multidb
database_isolation = low
singletenant = yes

[persistence]
basepath_datavolumes = /hana/data/BSD
basepath_logvolumes = /hana/log/BSD

[system_information]
usage = test

bsdadm> HDBSettings.sh systemReplicationStatus.py
this system is not a system replication site
```

Then initiate system replication:

``` shell
bsdadm> hdbnsutil -sr_enable --name=world # name site is unique for each host!
nameserver is active, proceeding ...
error: system replication prerequisite check failed;exception 3000302: Backup has not yet been executed on primary system! Please backup primary system.
;
failed. trace file nameserver_oldhanae1.00000.000.trc may contain more error details.
```

The above failed because there has not been done backup yet!

Thus, the backup first (`-i XX` is instance number)!

``` shell
bsdadm> hdbsql -u SYSTEM -d SYSTEMDB -i 00 "BACKUP DATA FOR FULL SYSTEM USING FILE ('backup')"
Password:
0 rows affected (overall time 67.691963 sec; server time 67.690426 sec)
```

Then re-try to initiate system replication:

``` shell
bsdadm> hdbnsutil -sr_enable --name=world # name site is unique for each host
nameserver is active, proceeding ...
successfully enabled system as system replication source site
done.
```

Post-action step on supposed to be primary node:

``` shell
bsdadm> cat global.ini
# global.ini last modified 2022-05-11 12:30:20.759224 by hdbnameserver
[multidb]
mode = multidb
database_isolation = low
singletenant = yes

[persistence]
basepath_datavolumes = /hana/data/BSD
basepath_logvolumes = /hana/log/BSD

[system_information]
usage = test

[system_replication]
mode = primary
actual_mode = primary
site_id = 1
site_name = world
```

Copy the keys for SAP HANA2 to supposed to be secondary node via eg. `scp`:

``` shell
bsdadm> alias cdglo
cdglo='cd /usr/sap/$SAPSYSTEMNAME/SYS/global'

bsdadm> cdglo ; pwd
/usr/sap/BSD/SYS/global

bsdadm> alias cdglo
cdglo='cd /usr/sap/$SAPSYSTEMNAME/SYS/global'

bsdadm> cdglo ; pwd
/usr/sap/BSD/SYS/global

bsdadm> ls -1 security/rsecssfs/*/*
security/rsecssfs/data/SSFS_BSD.DAT
security/rsecssfs/key/SSFS_BSD.KEY

bsdadm> ls -l /usr/sap/BSD/SYS/global/security/rsecssfs/data/SSFS_BSD.DAT
-rw-r--r-- 1 bsdadm sapsys 2960 May 10 14:48 /usr/sap/BSD/SYS/global/security/rsecssfs/data/SSFS_BSD.DAT
```

On secondary instance stop HANA

``` shell
bsdadm> HDB stop
hdbdaemon will wait maximal 300 seconds for NewDB services finishing.
Stopping instance using: /usr/sap/BSD/SYS/exe/hdb/sapcontrol -prot NI_HTTP -nr 00 -function Stop 400

11.05.2022 12:20:51
Stop
OK
Waiting for stopped instance using: /usr/sap/BSD/SYS/exe/hdb/sapcontrol -prot NI_HTTP -nr 00 -function WaitforStopped 600 2


11.05.2022 12:21:19
WaitforStopped
OK
hdbdaemon is stopped.
```

Add the secondary node to our system replication (again the *name* should be
unique!):

``` shell
bsdadm> hdbnsutil -sr_register --remoteHost=oldhanae1 --remoteInstance=00 --replicationMode=sync --name=world2
--operationMode not set; using default from global.ini/[system_replication]/operation_mode: logreplay
adding site ...
nameserver oldhanae2:30001 not responding.
collecting information ...
updating local ini files ...
done.

bsdadm> cdcoc
oldhanae2:bsdadm> cat global.ini
# global.ini last modified 2022-05-11 12:38:06.109471 by hdbnsutil -sr_register --remoteHost=oldhanae1 --remoteInstance=00 --replicationMode=sync --name=world2
[multidb]
mode = multidb
database_isolation = low
singletenant = yes

[persistence]
basepath_datavolumes = /hana/data/BSD
basepath_logvolumes = /hana/log/BSD

[system_information]
usage = test

[system_replication]
timetravel_logreplay_mode = auto
site_id = 2
mode = sync
actual_mode = sync
site_name = world2
operation_mode = logreplay

[system_replication_site_masters]
1 = oldhanae1:30001
```

System replication checks:

``` shell
bsdadm> alias | grep cdpy
cdpy='cd $DIR_INSTANCE/exe/python_support'

bsdadm> HDBSettings.sh systemReplicationStatus.py
nameserver oldhanae2:30001 not responding.
nameserver oldhanae2:30001 not responding.
this system is not a system replication site

bsdadm> HDB start

StartService
Impromptu CCC initialization by 'rscpCInit'.
  See SAP note 1266393.
OK
OK
Starting instance using: /usr/sap/BSD/SYS/exe/hdb/sapcontrol -prot NI_HTTP -nr 00 -function StartWait 2700 2


11.05.2022 12:46:10
Start
OK

11.05.2022 12:46:40
StartWait
OK

bsdadm> HDBSettings.sh systemReplicationStatus.py
this system is either not running or not primary system replication site

Local System Replication State
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

mode: SYNC
site id: 2
site name: world2
active primary site: 1
primary masters: oldhanae1

bsdadm> HDBSettings.sh systemReplicationStatus.py  ;echo $?
this system is either not running or not primary system replication site

Local System Replication State
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

mode: SYNC
site id: 2
site name: world2
active primary site: 1
primary masters: oldhanae1
12
```

Again check on primary

``` shell
bsdadm> HDBSettings.sh systemReplicationStatus.py ; echo $?
|Database |Host      |Port  |Service Name |Volume ID |Site ID |Site Name |Secondary |Secondary |Secondary |Secondary |Secondary     |Replication |Replication |Replication    |
|         |          |      |             |          |        |          |Host      |Port      |Site ID   |Site Name |Active Status |Mode        |Status      |Status Details |
|-------- |--------- |----- |------------ |--------- |------- |--------- |--------- |--------- |--------- |--------- |------------- |----------- |----------- |-------------- |
|SYSTEMDB |oldhanae1 |30001 |nameserver   |        1 |      1 |world     |oldhanae2 |    30001 |        2 |world2    |YES           |SYNC        |ACTIVE      |               |
|BSD      |oldhanae1 |30007 |xsengine     |        2 |      1 |world     |oldhanae2 |    30007 |        2 |world2    |YES           |SYNC        |ACTIVE      |               |
|BSD      |oldhanae1 |30003 |indexserver  |        3 |      1 |world     |oldhanae2 |    30003 |        2 |world2    |YES           |SYNC        |ACTIVE      |               |

status system replication site "2": ACTIVE
overall system replication status: ACTIVE

Local System Replication State
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

mode: PRIMARY
site id: 1
site name: world
15
```

Some SR command:

``` shell
bsdadm> hdbnsutil | grep -P -- '^\s*-sr_(enable|disable|register|unregister|takeover|state|fullsync)'
  -sr_enable [--name=<site alias>]                                       - enables a site for serving as system replication source site
  -sr_disable                                                            - disables system replication capabilities on source site
  -sr_register --remoteHost=<primary master host>                        - registers a site to a source site
  -sr_unregister [--id=<site id>|--name=<site name>]                     - on primary: removes secondary with given id/name from primary, leaving the secondary untouched
  -sr_fullsync --enable|--disable                                        - enables or disables full sync on primary system
  -sr_takeover                                                           - switches system replication primary site to the calling site
  -sr_state                                                              - shows status information about system replication site
  -sr_stateConfiguration                                                 - shows configuration of system replication site based on INI files
  -sr_stateHostMapping                                                   - shows host mapping of system replication from topology
```

###### SAP HANA cluster

SUSE [SAP HANA System Replication Scale-Up - Performance Optimized
Scenario](https://documentation.suse.com/sbp/all/single-html/SLES4SAP-hana-sr-guide-PerfOpt-15/#id-example-cluster-configuration).

The below configuration is taken from the above SUSE docs:

``` shell
# jinja template
cat > /tmp/sap_cluster.j2 <<EOF
{%- set sid=os.environ["_SID"].strip() -%}
{%- set inst=os.environ["_INSTID"].strip() -%}
{%- set ip=os.environ["_IP"].strip() -%}

primitive rsc_SAPHanaTopology_{{ sid }}_HDB{{ inst }} ocf:suse:SAPHanaTopology \
    op monitor interval=10 timeout=300 \
    op start interval=0 timeout=300 \
    op stop interval=0 timeout=300 \
    params SID={{ sid }} InstanceNumber={{ inst }}

primitive rsc_SAPHana_{{ sid }}_HDB{{ inst }} ocf:suse:SAPHana \
    op monitor interval=61 role=Slave timeout=700 \
    op start interval=0 timeout=3600 \
    op stop interval=0 timeout=3600 \
    op promote interval=0 timeout=3600 \
    op monitor interval=60 role=Master timeout=700 \
    params SID={{ sid }} InstanceNumber={{ inst }} PREFER_SITE_TAKEOVER=true \
           DUPLICATE_PRIMARY_TIMEOUT=7200 AUTOMATED_REGISTER=false \
    meta priority=100

primitive rsc_ip_{{ sid }}_HDB{{ inst }} ocf:heartbeat:IPaddr2 \
    op monitor interval=10 timeout=20 \
    params ip="{{ ip }}"

primitive stonith-sbd stonith:external/sbd \
    params pcmk_delay_max=15

ms msl_SAPHana_{{ sid }}_HDB{{ inst }} rsc_SAPHana_{{ sid }}_HDB{{ inst }} \
    meta clone-max=2 clone-node-max=1 interleave=true
clone cln_SAPHanaTopology_{{ sid }}_HDB{{ inst }} rsc_SAPHanaTopology_{{ sid }}_HDB{{ inst }} \
    meta clone-node-max=1 interleave=true
colocation col_saphana_ip_{{ sid }}_HDB{{ inst }} 2000: \
    rsc_ip_{{ sid }}_HDB{{ inst }}:Started msl_SAPHana_{{ sid }}_HDB{{ inst }}:Master
order ord_SAPHana_{{ sid }}_HDB{{ inst }} 2000: \
    cln_SAPHanaTopology_{{ sid }}_HDB{{ inst }} msl_SAPHana_{{ sid }}_HDB{{ inst }}

property cib-bootstrap-options: \
    cluster-infrastructure=corosync \
    stonith-enabled=true \
    stonith-action=reboot \
    stonith-timeout=150 \
    priority-fencing-delay=30

rsc_defaults rsc-options: \
    resource-stickiness=1000 \
    migration-threshold=5000

op_defaults op-options: \
    timeout=600 \
    record-pending=true
EOF
```

NOTE!!! `PREFER_SITE_TAKEOVER` wins/overwrites `migration-threshold`!!!


``` shell
pip3 install --user jinja2 # install jinja template system

export _SID=BSD           # export the SID
export _INSTID=00         # export the instance number
export _IP=192.168.67.149 # export the virtual IP

# generate config and print to stdout
python3 -c 'import os; \
  import sys; \
  from jinja2 import Template; \
  data=sys.stdin.read(); \
  t = Template(data); \
  print(t.render(os=os))' < /tmp/sap_cluster.j2 | tee /tmp/sap_cluster.txt
```

Loading the SAP HANA cluster configuration into the cluster:

``` shell
crm configure property maintenance-mode=true
crm configure load update <file>
```

Comments about `crm_mon` output:

```
Active Resources:
  * rsc_ip_TUT_HDB00    (ocf::heartbeat:Dummy):  Started oldhanab1
  * stonith-sbd (stonith:external/sbd):  Started oldhanab2
  * Clone Set: msl_SAPHana_TUT_HDB00 [rsc_SAPHana_TUT_HDB00] (promotable):
    * Masters: [ oldhanab1 ]
    * Slaves: [ oldhanab2 ]
  * Clone Set: cln_SAPHanaTopology_TUT_HDB00 [rsc_SAPHanaTopology_TUT_HDB00]:
    * Started: [ oldhanab1 oldhanab2 ]
```

Inspecting cluster node attributes (comments inline):

*NOTE*: that node attributes could show multiple SAP HANA sids/instances, so it
could be not very readable.

```
Node Attributes:
  * Node: oldhanae1:
    * hana_bsd_clone_state              : PROMOTED
           ^                              ^
           |                              |
           +-- SID                        +-- primary
                                              other could be:
                                              - WAITING4PRIMARY
                                              - DEMOTED
                                              - UNDEFINED
    * hana_bsd_op_mode                  : logreplay
    * hana_bsd_remoteHost               : oldhanae2
    * hana_bsd_roles                    : 4:P:master1:master:worker:master
                                          ^ ^
                                          | |
                                          | +-- role (primary or secondary)
                                          +-- 1   = off, but not synced
                                              2/3 = transitioning
                                              4    = all ok
    * hana_bsd_site                     : world
                                          ^
                                          |
                                          +-- site name
    * hana_bsd_srmode                   : sync
    * hana_bsd_sync_state               : PRIM
                                          ^
                                          |
                                          +-- as HDBSettings.sh systemReplication.py RC '15'
                                              - SFAIL = sync failure, secondary won't be promoted!
                                              - SOK   = OK
    * hana_bsd_vhost                    : oldhanae1
    * lpa_bsd_lpt                       : 1652270919
                                          ^
                                          |
                                          +-- epoch time only on primary
                                              on secondary it is a "status"
                                              - 10 = KO
                                              - 20 = doing something
                                              - 30 = OK
    * master-rsc_SAPHana_BSD_HDB00      : 150
  * Node: oldhanae2:
    * hana_bsd_clone_state              : DEMOTED
    * hana_bsd_op_mode                  : logreplay
    * hana_bsd_remoteHost               : oldhanae1
    * hana_bsd_roles                    : 4:S:master1:master:worker:master
    * hana_bsd_site                     : world2
    * hana_bsd_srmode                   : sync
    * hana_bsd_sync_state               : SOK

    * hana_bsd_vhost                    : oldhanae2
    * lpa_bsd_lpt                       : 30
    * master-rsc_SAPHana_BSD_HDB00      : 100
```

If both nodes think there are primary, see global.ini; the suppposed econdary
should be re-registered.

SRHook:

SRHook - a connection between cluster and SAP environment

1. `crm configure property maintenance-mode=true`
2. stop HANA (eg. via `HDB stop` or `sapcontrol`)
3. add/configure SRHook
4. start HANA
5. `crm configure property maintenance-mode=false`

Cluster does monitor (pulls data at every monitor internal) but SRHook
can make HANA push updates to the cluster.

SRHooks uses `sudo`:

``` shell
$ cat > /etc/sudoers.d/sap_cluster.conf <<EOF
<sid>adm ALL=(ALL) NOPASSWD: /usr/sbin/crm_attribute -n hana_<sid>_site_srHook_\*
EOF
```

SRHook setup:

``` shell
$ su - bsdadm
bsdadm> cdcoc
```

Add
[SRHook](https://documentation.suse.com/sbp/all/single-html/SLES4SAP-hana-sr-guide-costopt-15/#id-1.10.9.4)
part into `global.ini`:

```
[ha_dr_provider_saphanasr]
provider = SAPHanaSR
path = /usr/share/SAPHanaSR/
execution_order = 1

[trace]
ha_dr_saphanasr = info
```

Check `global.ini` after adding SRHook part:

``` shell
bsdadm> cat global.ini
# global.ini last modified 2022-05-11 12:30:20.759224 by hdbnameserver
[multidb]
mode = multidb
database_isolation = low
singletenant = yes

[persistence]
basepath_datavolumes = /hana/data/BSD
basepath_logvolumes = /hana/log/BSD

[system_information]
usage = test

[system_replication]
mode = primary
actual_mode = primary
site_id = 1
site_name = world

[ha_dr_provider_saphanasr]
provider = SAPHanaSR
path = /usr/share/SAPHanaSR/
execution_order = 1

[trace]
ha_dr_saphanasr = info
```

See the cluster got the SRHook:

``` shell
$ crm configure show | grep -A 1 SR:
property SAPHanaSR: \
        hana_bsd_site_srHook_world2=SOK
```

Validation:

``` shell
bsdadm> cdtrace
bsdadm> grep -m1 srHo nameserver_*
nameserver_oldhanae1.30001.000.trc:[15186]{-1}[-1/-1] 2022-05-12 13:48:47.477185 i ha_dr_SAPHanaSR  SAPHanaSR.py(00116) : SAPHanaSR CALLING CRM: <sudo /usr/sbin/crm_attribute -n hana_bsd_site_srHook_world2 -v SFAIL -t crm_config -s SAPHanaSR> rc=0
```

``` shell
$ grep -m 1 -P 'srHook.*SOK' /var/log/pacemaker/pacemaker.log
May 03 12:48:33 oldhanae1 pacemaker-based     [1575] (cib_perform_op)   info: +  /cib/configuration/crm_config/cluster_property_set[@id='SAPHanaSR']/nvpair[@id='SAPHanaSR-hana_yh0_site_srHook_whitewine']:  @value=SOK
```


#### Support tools from OS like SLES

``` shell
# SLES related only

$ rpm -qi supportutils-plugin-ha-sap | sed -n '/^Description/,$p'
Description :
Extends supportconfig functionality to include system information for
SAP and HA cluster. The supportconfig saves the related logs.
Distribution: SUSE Linux Enterprise 15

$ supportconfig
...
$ tar tJf /var/log/scc_oldhanae2_220511_1147.txz | grep sap
scc_oldhanae2_220511_1147/plugin-ha_sap.txt
scc_oldhanae2_220511_1147/plugin-sapconf.txt
scc_oldhanae2_220511_1147/plugin-saptune.txt

$ tar xOJf /var/log/scc_oldhanae2_220511_1147.txz \
  scc_oldhanae2_220511_1147/plugin-ha_sap.txt | grep -P '^# (rpm|/bin|/usr)'
# /usr/lib/supportconfig/plugins/ha_sap
# rpm -V SAPHanaSR
# rpm -V sapconf
# rpm -V tuned
# rpm -V saptune
# rpm -V sap-suse-cluster-connector
# /bin/grep -v '^\s*\#\|^$' /etc/nsswitch.conf | head -5
# /bin/grep -E ^[[:alnum:]]{3}adm: /etc/passwd
# /bin/systemctl status sapconf
# /bin/systemctl status tuned.service
# /usr/sap/hostctrl/exe/saphostexec -version |tail -30
# /usr/sap/hostctrl/exe/saphostexec -status
# /bin/systemctl status sapinit
# /usr/bin/cat /usr/sap/sapservices
# /usr/sap/hostctrl/exe/saphostctrl -function ListInstances
# /bin/ps -U bsdadm -f
# /bin/su - bsdadm -c 'HDB version'
# /usr/bin/id bsdadm
# /usr/sbin/SAPHanaSR-monitor
# /usr/sbin/SAPHanaSR-showAttr
# /bin/su - bsdadm -c 'hdbnsutil -sr_state'
# /bin/su - bsdadm -c 'HDBSettings.sh landscapeHostConfiguration.py --sapcontrol=1'
# /bin/su - bsdadm -c 'HDBSettings.sh systemReplicationStatus.py'
# /bin/su - bsdadm -c 'HDBSettings.sh systemOverview.py'
# /bin/su - bsdadm -c 'HDB info'
# /bin/su - bsdadm -c 'sapcontrol -nr 00 -function GetSystemInstanceList'
# /bin/su - bsdadm -c 'sapcontrol -nr 00 -function GetProcessList'
# /usr/sap/BSD/SYS/global/hdb/custom/config/global.ini
# /usr/sap/BSD/SYS/global/hdb/custom/config/nameserver.ini
# /usr/sap/BSD/SYS/profile/BSD_HDB00_oldhanae2
# /bin/rpm -qa | grep -E 'sap-suse-cluster-connector|sap_suse_cluster_connector'
# /bin/su - bsdadm -c 'sapcontrol -nr 00 -function HAGetFailoverConfig'
# /bin/su - bsdadm -c 'sapcontrol -nr 00 -function HACheckFailoverConfig'
# /bin/su - bsdadm -c 'sapcontrol -nr 00 -function HACheckConfig'
# /usr/sbin/crm_mon -A -r -1
# /usr/sbin/crm configure show obscure:passw*
# /bin/grep -E -i 'saphana|SAPDatabase|SAPInstance|SAPStartsrv|sapcontrol|saphostctrl|sap_suse_cluster_connector' /var/log/messages | tail -1000
# /bin/grep -E -i 'saphana|SAPDatabase|SAPInstance|SAPStartsrv|sapcontrol|saphostctrl' /var/log/pacemaker.log | tail -1000
```


### redoing replication deployment

Cf. https://help.sap.com/docs/SAP_HANA_PLATFORM/4e9b18c116aa42fc84c7dbfd02111aba/9a4a4cdcda454663ba0c75d180c7ed11.html?version=2.0.04&locale=en-US

1. `cdglo ; ls -1 security/rsecssfs/*/*` -
   [keys](https://documentation.suse.com/sbp/all/single-html/SLES4SAP-hana-sr-guide-costopt-15/#id-1.9.8.4)
   present on second node
2. [backup](https://documentation.suse.com/sbp/all/single-html/SLES4SAP-hana-sr-guide-costopt-15/#id-1.9.6.3):
   ``` shell
   # if not already backup present then...
   $ hdbsql -u SYSTEM -d SYSTEMDB -i $TINSTANCE "BACKUP DATA FOR FULL SYSTEM USING FILE ('backup')"
   ```
   backup can use also database user
   [key](https://documentation.suse.com/sbp/all/single-html/SLES4SAP-hana-sr-guide-costopt-15/#id-create-a-database-user-key-in-sidadms-keystore)
   (in YaST)
3. SSH works between nodes; `sudo`
   [rules](https://documentation.suse.com/sbp/all/single-html/SLES4SAP-hana-sr-guide-costopt-15/#id-allowing-sidadm-to-access-the-cluster)
   are present
   ```
   # SAPHanaSR-ScaleUp entries for writing srHook cluster attribute
   <sid>adm ALL=(ALL) NOPASSWD: /usr/sbin/crm_attribute -n hana_<sid>_site_srHook_*
   ```
3. on primary node, HDB must be running
4. do on the other node
   ``` shell
   # check if replication is setup
   $ hdbnsutil -sr_stateConfiguration

   $ echo $TINSTANCE; sapcontrol -nr $TINSTANCE -function StopSystem HDB
   20

   08.03.2023 14:41:54
   StopSystem
   OK

   $ hdbnsutil -sr_unregister --id=JB154SAPQE02

   # HDB must be started after that again
   $ HDB start
   ```
3. back on primary node
   ``` shell
   $ hdbnsutil -sr_disable
   # check replication again
   $ hdbnsutil -sr_stateConfiguration
   ```
4. clear cluster configuration
   ``` shell
   $ systemctl stop pacemaker
   $ systemctl preset sbd pacemaker

   $ find /var/lib/pacemaker/ /var/log/YaST2/ /var/log/pacemaker/ /var/log/messages-* -type f -delete
   $ : > /etc/sysconfig/sbd /etc/csync2/csync2.cfg /var/log/messages
   $ export 'Y2DEBUG=1' > /etc/environment
   $ export Y2DEBUG=1

   $ { umask=077; /usr/bin/openssl ecparam -genkey -name secp384r1 -out /etc/csync2/csync2_ssl_key.pem; cat << EOF | \
       /usr/bin/openssl req -new -key /etc/csync2/csync2_ssl_key.pem -x509 -days 3000 -out /etc/csync2/csync2_ssl_cert.pem;
   > --
   > SomeState
   > SomeCity
   > SomeOrganization
   > SomeOrganization
   > SomeName
   > name@example.com
   > EOF
   > }
   ```
5. check DB passwords
   ``` shell
   $ hdbsql -i $TINSTANCE -u SYSTEM -p <password>

   Welcome to the SAP HANA Database interactive terminal.

   Type:  \h for help with commands
     \q to quit

   hdbsql RHP=>
   ```
6. ...


## SAP cluster integration


### sap_suse_cluster_connector

[`sap_suse_cluster_connector`](https://www.suse.com/c/sap-netweaver-suse-cluster-integration-new-sap_suse_cluster_connector-version-3-0-0/)
is a software tool which sits between SAP start and control framework
for SAP NetWeaver or S/4 HANA instances and the SUSE cluster component
pacemaker.

With `sap_suse_cluster_connector` (it is a RPM package), one can
inform cluster from SAP tools about maintenance and can also see
instance status inside SAP mgmt tools.

TODO: confirm the section below

***
- host_profile ???
- restart sapstartsrv
- logs of sapstartsrv process ??
- sapcontrol -nr <nr> -function HAGetFailoverconfig

new comments for sapcontrol:
- HAGetFailoverconfig
- HACheckconfig
- HACheckFailoverconfig
- HAFailoverToNode
***
