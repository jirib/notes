# SUSE Enterprise Linux cheatsheet


## Repository Mirroring Tools aka RMT

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

Exporting RMT data/settings/repos, for later import by SMLM/SUMA:

``` shell
$ rmt-cli export data /mnt   
I, [2026-01-14T14:19:28.481153 #223]  INFO -- : Exporting data from SCC to /mnt
I, [2026-01-14T14:19:28.481224 #223]  INFO -- : Exporting products
I, [2026-01-14T14:19:28.481250 #223]  INFO -- : Loading product data from SCC
I, [2026-01-14T14:19:40.326513 #223]  INFO -- : Loading product data from SCC
I, [2026-01-14T14:20:07.634814 #223]  INFO -- : Exporting repositories
I, [2026-01-14T14:20:07.634888 #223]  INFO -- : Loading repository data from SCC
I, [2026-01-14T14:20:18.495096 #223]  INFO -- : Exporting subscriptions
I, [2026-01-14T14:20:18.495170 #223]  INFO -- : Loading subscription data from SCC
I, [2026-01-14T14:20:18.573574 #223]  INFO -- : Exporting orders

$ find /mnt -ls
      128      0 drwxr-xr-x   2 _rmt     nginx         213 Jan 14 14:20 /mnt
      131      0 -rw-r--r--   1 _rmt     nginx           0 Jan 14 13:44 /mnt/.mounted
      132   7284 -rw-r--r--   1 _rmt     nginx     7458003 Jan 14 14:19 /mnt/organizations_products.json
      133  11992 -rw-r--r--   1 _rmt     nginx    12278786 Jan 14 14:20 /mnt/organizations_products_unscoped.json
      134   1964 -rw-r--r--   1 _rmt     nginx     2007997 Jan 14 14:20 /mnt/organizations_repositories.json
      135     20 -rw-r--r--   1 _rmt     nginx       18772 Jan 14 14:20 /mnt/organizations_subscriptions.json
      136      4 -rw-r--r--   1 _rmt     nginx           2 Jan 14 14:20 /mnt/organizations_orders.json
$ rmt-cli export settings /mnt
Settings saved at /mnt/repos.json.
$ find /mnt -ls
      128      0 drwxr-xr-x   2 _rmt     nginx         231 Jan 14 14:20 /mnt
      131      0 -rw-r--r--   1 _rmt     nginx           0 Jan 14 13:44 /mnt/.mounted
      132   7284 -rw-r--r--   1 _rmt     nginx     7458003 Jan 14 14:19 /mnt/organizations_products.json
      133  11992 -rw-r--r--   1 _rmt     nginx    12278786 Jan 14 14:20 /mnt/organizations_products_unscoped.json
      134   1964 -rw-r--r--   1 _rmt     nginx     2007997 Jan 14 14:20 /mnt/organizations_repositories.json
      135     20 -rw-r--r--   1 _rmt     nginx       18772 Jan 14 14:20 /mnt/organizations_subscriptions.json
      136      4 -rw-r--r--   1 _rmt     nginx           2 Jan 14 14:20 /mnt/organizations_orders.json
      137     12 -rw-r--r--   1 _rmt     nginx        9665 Jan 14 14:20 /mnt/repos.json

# exporting 'repos' seem to export into export "root"
$ rmt-cli export repos /mnt
...snipped...

$ jq -r '.[].url' /export/repos.json | grep -Po '\.com/\K(.*)' | head
SUSE/Updates/SLE-SERVER/12-SP5/x86_64/update/
SUSE/Updates/SLE-SERVER-INSTALLER/12-SP5/x86_64/update/
SUSE/Products/SLE-SERVER/12-SP5/x86_64/product/
SUSE/Updates/RES/8/x86_64/update/
SUSE/Updates/RES-AS/8/x86_64/update/
SUSE/Updates/RES-CB/8/x86_64/update/
SUSE/Updates/SLE-Product-WE/15-SP5/x86_64/update/
SUSE/Products/SLE-Product-WE/15-SP5/x86_64/product/
SUSE/Updates/SLL/9/x86_64/update/
SUSE/Updates/SLL-AS/9/x86_64/update/

$ ls /export/SUSE/
Updates
```


## SLES Product / Registration

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


## SLE Micro

How does it boot?

```
# wrapped lines for readability

[    0.024518][    T0] Kernel command line: BOOT_IMAGE=/boot/vmlinuz-5.14.21-150500.55.19-default
  root=UUID=4c55d806-7db6-48df-9657-6786842d88ce rd.timeout=60 console=ttyS0,115200 console=tty0
  security=selinux selinux=1 splash=none net.ifnames=0 ignition.firstboot dasd_mod.dasd=autodetect
  ignition.platform.id=qemu
...
Welcome to SUSE Linux Enterprise Micro 5.5  (x86_64) - Kernel 5.14.21-150500.55.19-default (ttyS0).

SSH host key: SHA256:NEGqMg1WjBAcInuuQqMd2qvDRefbS4jce+PqpeZJH/8 (RSA)
SSH host key: SHA256:QLwEXcXPfqow7H8aSFSE3hlgsI6kvji6fmKi+X8POtM (DSA)
SSH host key: SHA256:jldoqlHlASKqInUU6HiwvqbX6glRf7wZZwCqzDsJlZg (ECDSA)
SSH host key: SHA256:1UyphaashvUtmxurSRRbPUSv0vmOLCKYRnX+8mYDEt4 (ED25519)
eth0: 192.168.252.181 fe80::5054:ff:feda:c551


Activate the web console with: systemctl enable --now cockpit.socket

jbm55qe01 login: root
Password:
jbm55qe01:~ # cat /etc/os-release
NAME="SLE Micro"
VERSION="5.5"
VERSION_ID="5.5"
PRETTY_NAME="SUSE Linux Enterprise Micro 5.5"
ID="sle-micro"
ID_LIKE="suse"
ANSI_COLOR="0;32"
CPE_NAME="cpe:/o:suse:sle-micro:5.5"
```

Note, that adding non-root user requires the filesystem where such a
user home directory is located to be mounted! That is, add a section
to the *ignition* config explicitly (but for *root*, it is OK since
for `/root` there's `x-initrd.mount` mount option).


## SLES templating

``` shell
# generic
: > /etc/machine-id # machine-id in /var/lib/dbus is symlink
rm /etc/ssh/{ssh_host*,moduli}
rm /etc/udev/rules.d/*-persistent-*.rules

# iscsi initiator
# https://www.suse.com/zh-cn/support/kb/doc/?id=000020752
rm /etc/iscsi/initiatorname.iscsi

<editor> /etc/default/grub # path to block device

# suse specific
rm /etc/zypp/credentials.d/SCCcredentials
rm /etc/zypp/services.d/*
rm /var/lib/wicked/{duid,iaid,lease-eth0-dhcp-ipv4}.xml

<editor> /etc/default/grub_installdevice # path to block device
<editor> /etc/sysconfig/network/if{cfg,route}-eth0

# tips:
# - enable serial console so `virsh console <domain>' works

find /var/log -type f -exec sh -c ': > $1' {} {} \;
: > /root/.bash_history
rm -rf /var/cache/*
```

Let's create new VM `s153.qcow2`/`s153qb01.xml` from
eg. `_s153.qcow2`/`_s153.xml` template.

``` shell
$ template=foo
$ newvm=bar
$ slesver=15.3

$ qemu-img create -f qcow2 -b _${slesver//./}.qcow2 -F qcow2 s${slesver//./}qb01.qcow2 21G

$ virsh define <(virsh dumpxml ${template} | \
  sed -e '/uuid/d' \
    -e '/mac address/d' \
    -e 's/<name>.*<\/name>/<name>'${newvm}'<\/name>/' \
    -e 's/sle\/[^"]*/sle\/'${slesver}'/' )
```


## SUSE customer center (SCC)

a little and stupid wrapper for SCC/swagger [API](
  https://scc.suse.com/api/package_search/v4/documentation)

``` shell
$ cat ~/bin/sccpkgsearch
#!/bin/bash
#set -x
set -o pipefail

PACKAGE=$1
VERSION=$2

prod_url='https://scc.suse.com/api/package_search/products'
pkg_url='https://scc.suse.com/api/package_search/packages?product_id=%s&query=%s'

get_prodid() {
    local _prod="SLES/${VERSION/-SP/.}/x86_64"
    curl -sL -X 'GET' \
         -H 'accept: application/json' \
         -H 'Accept: application/vnd.scc.suse.com.v4+json' \
        ${prod_url} | \
        jq -e -r --arg prod ${_prod} \
           '.data[] | select(.identifier == $prod) | .id'
}

# main
PRODID=$(get_prodid)
curl -sL -X 'GET' \
     -H 'accept: application/json' \
     -H 'Accept: application/vnd.scc.suse.com.v4+json' \
     $(printf "${pkg_url}" ${PRODID} ${PACKAGE}) | \
    jq -re --arg pkg ${PACKAGE} \
       '.data[] | select(.name == $pkg) | { name, version} | @text' | \
    awk -v pkg=$PACKAGE -F: \
        '{ gsub(/"/,""); gsub(/}/,""); print pkg"-"$(NF)".x86_64.rpm" }' | \
    sort -Vu
```

``` shell
$ sccpkgsearch samba 15-SP3
samba-4.13.4+git.187.5ad4708741a.x86_64.rpm
samba-4.13.6+git.211.555d60b24ba.x86_64.rpm
samba-4.13.10+git.236.0517d0e6bdf.x86_64.rpm
samba-4.13.13+git.528.140935f8d6a.x86_64.rpm
samba-4.13.13+git.531.903f5c0ccdc.x86_64.rpm
samba-4.13.13+git.539.fdbc44a8598.x86_64.rpm
```


## SUSE support

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


### supportconfig

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


## YaST

YaST ruby debugger:

``` shell
$ zypper in 'rubygem(byebug)'
$ Y2DEBUGGER=1 yast2 sap_ha
```

``` shell
# in other terminal
$ byebug -R 3344
Connecting to byebug server...
Connected.
Return value is: nil

[70, 79] in /usr/lib64/ruby/vendor_ruby/2.5.0/yast/debugger.rb
   70:         byebug
   71:         # Now you can inspect the current state in the debugger,
   72:         # or use "next" to continue.
   73:         # Use "help" command to see the available commands, see more at
   74:         # https://github.com/deivid-rodriguez/byebug/blob/master/GUIDE.md
=> 75:       end
   76: 
   77:       # start the Ruby debugger if "Y2DEBUGGER" environment
   78:       # variable is set to "1", "remote" or "manual" (the test is case
   79:       # insensitive, "y2debugger" variable can be also used)
(byebug)
```

``` shell
(byebug) break SapHA::SemanticChecks#hana_is_running
*** Warning: breakpoint source is not yet defined
Created breakpoint 1 at SapHA::SemanticChecks:hana_is_running
(byebug) info breakpoints
Num Enb What
1   y   at SapHA::SemanticChecks:hana_is_running
(byebug) c
(byebug) 
Stopped by breakpoint 1 at /usr/share/YaST2/lib/sap_ha/semantic_checks.rb:270

(byebug) frame
--> #0  SapHA::SemanticChecks.hana_is_running(system_id#String, instance_number#String, nodes#Array) at /usr/share/YaST2/lib/sap_ha/semantic_checks.rb:270

[265, 274] in /usr/share/YaST2/lib/sap_ha/semantic_checks.rb
   265:       shown_value = hide_value ? "" : value
   266:       report_error(flag, message || "The value must be a non-empty string", field_name, shown_value)
   267:     end
   268: 
   269:     def hana_is_running(system_id, instance_number, nodes)
=> 270:       flag = true
   271:       message = ''
   272:       my_ips = SapHA::System::Network.ip_addresses
   273:       procname = "hdb.sap#{system_id.upcase}_HDB#{instance_number}"
   274:       if @no_test

(byebug) display system_id
1: system_id = "ABC"
(byebug) display instance_number
2: instance_number = "00"
(byebug) display nodes
3: nodes = ["192.168.252.253", "192.168.252.190"]
(byebug) display SapHA::System::Network.ip_addresses
6: SapHA::System::Network.ip_addresses = ["192.168.252.253"]
(byebug) display "hdb.sap#{system_id.upcase}_HDB#{instance_number}"
8: "hdb.sap#{system_id.upcase}_HDB#{instance_number}" = "hdb.sapABC_HDB00"
(byebug) display @no_test
9: @no_test = nil
(byebug) n
1: system_id = "ABC"
2: instance_number = "00"
3: nodes = ["192.168.252.253", "192.168.252.190"]
4: flag = true
5: message = ""
6: SapHA::System::Network.ip_addresses = ["192.168.252.253"]
7: procname = "hdb.sapABC_HDB00"
8: "hdb.sap#{system_id.upcase}_HDB#{instance_number}" = "hdb.sapABC_HDB00"
9: @no_test = nil

[283, 292] in /usr/share/YaST2/lib/sap_ha/semantic_checks.rb
   283:             flag = false
   284:             message += "<br>No SAP HANA #{system_id} is running on #{node}"
   285:           end
   286:         end
   287:       end
=> 288:       report_error(flag, message, '', '')
   289:     end
   290: 
   291:     # Check if string is a block device
   292:     # @param value [String] device path
```


## Zypper

To run `zypper` non-interactively do:

``` shell
$ zypper --non-interactive install --auto-agree-with-licenses -y <package>
```

Repos:

``` shell
$ zypper lr # list repos
$ zypper lr -d <repo> # details about a repo
$ zypper mr -e <repo>
$ zypper mr -e --all # enable all repos

# install from disabled repository
$ zypper -v --plus-content SUSE-PackageHub-15-SP3-Backports-Pool install tmate
```

To add a repo non-interactively do:

``` shell
$ zypper -n -q ar -f [-p <prio>] <url> <name>

# or import rpm gpg key manually, an example:
# rpm --import https://brave-browser-rpm-release.s3.brave.com/brave-core.asc

$ zypper --gpg-auto-import-keys ref
```

Patterns:

``` shell
zypper pt
zypper in -t pattern <pattern_name>

```

``` shell
zypper search --provides --type package -x view
```

Packages:

``` shell
# zypper rm -u <package> # removes package and all deps
# zypper se -x --provides /usr/bin/gnat # search package owning path
# zypper se -x --provides 'libssl.so.1.1(OPENSSL_1_1_1)(64bit)'
Loading repository data...
Reading installed packages...

S | Name          | Summary                                     | Type
--+---------------+---------------------------------------------+--------
i | libopenssl1_1 | Secure Sockets and Transport Layer Security | package
```

Patches:

``` shell
zypper lp
zypper pchk
zypper patch # updates only affected/vulnerable packages
```

Zypper/RPM signing keys:

``` shell
$ rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SUMMARY}\n' gpg-pubkey | grep -i 'suse package signing key'
gpg-pubkey-39db7c82-66c5d91a gpg(SuSE Package Signing Key <build@suse.de>)

# let's remove gpg-pubkey
$ rpm -e $(rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SUMMARY}\n' gpg-pubkey | grep -i 'suse package signing key' | cut -d' ' -f1)
$ rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SUMMARY}\n' gpg-pubkey | grep -i 'suse package signing key' | wc -l
0

# clean cache
$ zypper cc -a
$ ls -1 /var/cache/zypp/raw/*15*SP*/repodata/repomd.xml.key
ls: cannot access '/var/cache/zypp/raw/*15*SP*/repodata/repomd.xml.key': No such file or directory

# refresh to obtain the keys
$ zypper --gpg-auto-import-keys refresh

$ ls -1 /var/cache/zypp/raw/*15*SP*/repodata/repomd.xml.key
/var/cache/zypp/raw/Basesystem_Module_15_SP3_x86_64:SLE-Module-Basesystem15-SP3-Pool/repodata/repomd.xml.key
/var/cache/zypp/raw/Basesystem_Module_15_SP3_x86_64:SLE-Module-Basesystem15-SP3-Updates/repodata/repomd.xml.key
/var/cache/zypp/raw/Desktop_Applications_Module_15_SP3_x86_64:SLE-Module-Desktop-Applications15-SP3-Pool/repodata/repomd.xml.key
/var/cache/zypp/raw/Desktop_Applications_Module_15_SP3_x86_64:SLE-Module-Desktop-Applications15-SP3-Updates/repodata/repomd.xml.key
/var/cache/zypp/raw/Development_Tools_Module_15_SP3_x86_64:SLE-Module-DevTools15-SP3-Pool/repodata/repomd.xml.key
/var/cache/zypp/raw/Development_Tools_Module_15_SP3_x86_64:SLE-Module-DevTools15-SP3-Updates/repodata/repomd.xml.key
/var/cache/zypp/raw/SAP_Applications_Module_15_SP3_x86_64:SLE-Module-SAP-Applications15-SP3-Pool/repodata/repomd.xml.key
/var/cache/zypp/raw/SAP_Applications_Module_15_SP3_x86_64:SLE-Module-SAP-Applications15-SP3-Updates/repodata/repomd.xml.key
/var/cache/zypp/raw/Server_Applications_Module_15_SP3_x86_64:SLE-Module-Server-Applications15-SP3-Pool/repodata/repomd.xml.key
/var/cache/zypp/raw/Server_Applications_Module_15_SP3_x86_64:SLE-Module-Server-Applications15-SP3-Updates/repodata/repomd.xml.key
/var/cache/zypp/raw/SUSE_Linux_Enterprise_High_Availability_Extension_15_SP3_x86_64:SLE-Product-HA15-SP3-Pool/repodata/repomd.xml.key
/var/cache/zypp/raw/SUSE_Linux_Enterprise_High_Availability_Extension_15_SP3_x86_64:SLE-Product-HA15-SP3-Updates/repodata/repomd.xml.key
/var/cache/zypp/raw/SUSE_Linux_Enterprise_Server_for_SAP_Applications_15_SP3_x86_64:SLE-Product-SLES_SAP15-SP3-Pool/repodata/repomd.xml.key
/var/cache/zypp/raw/SUSE_Linux_Enterprise_Server_for_SAP_Applications_15_SP3_x86_64:SLE-Product-SLES_SAP15-SP3-Updates/repodata/repomd.xml.key

$ rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SUMMARY}\n' gpg-pubkey | grep -i 'suse package signing key' | wc -l
1

$ gpg -n -v /var/cache/zypp/raw/Basesystem_Module_15_SP3_x86_64:SLE-Module-Basesystem15-SP3-Updates/repodata/repomd.xml.key 2>/dev/null
pub   rsa2048 2013-01-31 [SC] [expires: 2028-10-02]
      FEAB502539D846DB2C0961CA70AF9E8139DB7C82
uid           SuSE Package Signing Key <build@suse.de>
sig        70AF9E8139DB7C82 2024-08-21   [selfsig]
```
