# NFS cheatsheet

What NFS protocol version are support?

``` shell
# cat /proc/fs/nfsd/versions
-2 +3 +4 +4.1 +4.2
```

## /etc/exports

- long lines can be wrapped with a backslash `\`
- an exported filesystem should be separated from hosts and hosts
  declaration from one another with *a space* character
- *NO space* between the host identifier and first parenthesis of
  options!

Options:

- `anonuid/anonguid`, maps "nobody" to a special UID/GID

## NFSv4

*NFSv4* does NOT require `rpcbind`, no longer requirement of separate
TCP callback connection (ie. server does not need to contact the
client directly by itself); mounting and locking protocols are part of
NFSv4. **BUT** although NFSv4 does not require `rpcbind`, it requires
internally communicating with `rpc.mountd`, see [How to run NFS4-only
Server without rpcbind on SLES 12 or
15](https://www.suse.com/support/kb/doc/?id=000019530) for details,
but it is not involved in any over-the-wire operations.

- in-kernel *nfsd* listening on 2049/TCP
- `rpc.idmapd`, provides NFSv4 client and NFSv4 server upcalls, which
  map between on-the-wire NFSv4 names (strings in the form of
  `user@domain`) and local UIDs and GIDs. `/etc/idmapd.conf` must be
  configured and `Domain` must be agreed to make ID mapping to
  function properly

for every >= 4.0 nfs client `nfsd` keeps a record in `/proc/fs/nfsd/clients`

``` shell
grep -RH '' /proc/fs/nfsd/clients/11 2>/dev/null | grep clients
/proc/fs/nfsd/clients/11/info:clientid: 0x3c51cb4c6107cb15
/proc/fs/nfsd/clients/11/info:address: "10.0.0.2:876"
/proc/fs/nfsd/clients/11/info:status: confirmed
/proc/fs/nfsd/clients/11/info:name: "Linux NFSv4.2 server1"
/proc/fs/nfsd/clients/11/info:minor version: 2
/proc/fs/nfsd/clients/11/info:Implementation domain: "kernel.org"
/proc/fs/nfsd/clients/11/info:Implementation name: "Linux 5.3.18-24.75-default #1 SMP Thu Jul 15 10:17:58 UTC 2021 (44308a6) x86_64"
/proc/fs/nfsd/clients/11/info:Implementation time: [0, 0]
```

In *NFSv4.0 only* a TCP port has to be opened for callbacks, see
`callback_tcpport` in `nfs` module. Newer NFSv4 revisions do not need
this.

NFSv4 can work in Kerberos mode:

``` shell
$ grep -Pv '^\s*(#|$)' /etc/sysconfig/nfs  | grep NFS_SECURITY_GSS
NFS_SECURITY_GSS="yes"

$ grep -Pv '^\s*(#|$)' /etc/idmapd.conf
[General]
Verbosity = 0
Pipefs-Directory = /var/lib/nfs/rpc_pipefs
Domain = example.com
[Mapping]
Nobody-User = nobody
Nobody-Group = nobody
```

NFSv$ ACLs are "not visible" as usual UGO or ACLs:

``` shell
testovic@jb155sapqe01:/home/example.com/testovic> ls -al /mnt/
total 5
drwx------  2 nobody domain users   64 Mar  4 19:06 .
drwxr-xr-x 25 root   root         4096 Mar  4 14:13 ..

testovic@jb155sapqe01:/home/example.com/testovic> getfacl -e /mnt/
getfacl: Removing leading '/' from absolute path names
# file: mnt/
# owner: nobody
# group: domain\040users
user::rwx
group::---
other::---

testovic@jb155sapqe01:/home/example.com/testovic> nfs4_getfacl /mnt/
A:fdn:testovic@example.com:rwaDdxtTcCoy
A:fd:SYSTEM@NT AUTHORITY:rwaDdxtTcCoy
A:fd:Administrators@BUILTIN:rwaDdxtTcCoy
A:fd:Users@BUILTIN:rxtcy
A:d:Users@BUILTIN:a
A:d:Users@BUILTIN:w
A:fdi:CREATOR OWNER@:rwaDdxtTcCoy

# and a practical test

testovic@jb155sapqe01:/home/example.com/testovic> echo 'Hello World!' > /mnt/testovic.txt

testovic@jb155sapqe01:/home/example.com/testovic> ls -l /mnt/testovic.txt
-rw-r--r-- 1 testovic domain users 13 Mar  4 19:12 /mnt/testovic.txt

testovic@jb155sapqe01:/home/example.com/testovic> getfacl /mnt/testovic.txt
getfacl: Removing leading '/' from absolute path names
# file: mnt/testovic.txt
# owner: testovic
# group: domain\040users
user::rw-
group::r--
other::r--

testovic@jb155sapqe01:/home/example.com/testovic> nfs4_getfacl /mnt/testovic.txt
A::OWNER@:rwadtTcCoy
A::GROUP@:rtcy
A::Everyone@:rtc
```


## NFSv3

- in-kernel *nfsd* listening on 2049/{tcp,udp}
- `rpcbind` (previously `portmapper`) is required, accepts port
  reservations from local RPC services, makes them available to remote
  RPC services
- `rpc.mountd`, processes `MOUNT` requests from NFSv3 clients, checks
  that the requested NFS share is currently exported anf if the client
  is allowed to access it
- `lockd`, a kernel thread running on both client and server,
  implementing Network Lock Manager (NLM) protocol, which enables
  NFSv3 clients to lock files on the server
- `rpc.statd`, the Network Status Monitor (NSM) RPC protocol
  implementation, which notifies NFSv3 client when an NFS server is
  restarted without being gracefully brought down (???)

- *autofs* requires NFSv3 daemons for operation

`rpc.mountd` registers every successful mount request of clients into
`/var/lib/nfs/rmtab`. If a client doesn't unmount a NFS filesystem
before shutting down, there would be salve inforation in `rmtab`.

when a NFS server shuts down/reboots, `rpc.mountd` consults `rmtab`
and notifies clients that the server is to be
shutdown/rebooted. out-of-date `rmtab` does not cause shutdown to
hang.

for every < 4.0 nfs client `rpc.mountd` on nfs server keeps a record
in `/var/lib/nfs/rmtab`

``` shell
grep -RH '' /var/lib/nfs/rmtab
/var/lib/nfs/rmtab:10.0.0.2:/tmp:0x00000001
```

## NFS server

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


## NFS client

An usual check:

``` shell
# usually nfsv3 commands
rpcbind -p <nfs_server>   # list registered services in rpcbind
showmount -e <nfs_server> # list remote exports
```


## NFS troubleshooting


### NFS server troubleshooting

A description of `/proc/net/rpc/nfsd` could be found at [nfsd stats
explained :
/proc/net/rpc/nfsd](https://web.archive.org/web/20210409075630/https://www.svennd.be/nfsd-stats-explained-procnetrpcnfsd/).

``` shell
grep -RH '^address: ' /proc/fs/nfsd/clients/*/info # list clients
cat /var/lib/nfs/rpc_pipefs/nfsd4_cb/clnt*/info    # more brief info

grep -RH '' /proc/fs/nfsd/ 2>/dev/null
```


### NFS client troubleshooting

How to check if a mounted share is part of same exported share?

``` shell
$ grep -P '/(mnt|tmp/chroot)' /etc/mtab
127.0.0.1:/foo/all /mnt nfs4 rw,relatime,vers=4.2,rsize=1048576,wsize=1048576,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=127.0.0.1,local_lock=none,addr=127.0.0.1 0 0
127.0.0.1:/foo/all/bar /tmp/chroot nfs4 rw,relatime,vers=4.2,rsize=1048576,wsize=1048576,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=127.0.0.1,local_lock=none,addr=127.0.0.1 0 0

$ man mountpoint | grep -A1 -P -- '^\s*-d' | fmt -w 80
       -d, --fs-devno
           Show the major/minor numbers of the device that is mounted on
           the given directory.

$ for i in /mnt /tmp/chroot ; do mountpoint -d $i ; done
0:83
0:83
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

### Stale NFS Filehandles

Network File System (NFS) clients usually send the server a LOOKUP
call to convert a filename in a particular directory to a
filehandle. Because calls on the wire are expensive, these lookups are
usually cached so that later NFS operations can simply use the cached
filehandle.

When a server reports Stale NFS Filehandle on an NFS call (ESTALE). It
is in effect stating that the filehandle in the request is no longer
valid. This can happen for several reasons:

The inode which the filehandle refers to is no longer present on the
server. This can happen if someone, for instance, were to remove the
file on the server without the client being aware of. Typically, when
this occurs, the NFS client will transparently handle the ESTALE
error, and report back that the file no longer exists.

The filesystem id portion of the filehandle has changed. This can
happen if the device major/minor number of a filesystem has changed,
or if someone has assigned a new fsid= option to the filesystem,
without having the clients re-mounting it. When this occurs, typically
every filehandle on a filesystem will go stale, including the root
filehandle (the filehandle corresponding to the top-level directory of
the mount).

This is also seen in NFS clusters when the device major/minor numbers
of the filesystem are not consistent on all cluster nodes. One way to
work around this is to export using a consistent fsid= option on all
the nodes.

A machine has rebooted, or cluster failover has occurred, and the
server's IP address has come online before the filesystem is mounted
or the NFS server has exported it. This is most often seen with
improperly configured clustered NFS servers.

See:
https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-c02071844


## nfsstat

Details about `nfsstat` can be found at this
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
