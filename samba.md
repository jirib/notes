# Samba cheatsheet

A text from `samba(7)`:

``` shell
The Samba software suite is a collection of programs that implements
the Server Message Block (commonly abbreviated as SMB) protocol
for UNIX systems and provides Active Directory services. The first
version of the SMB protocol is sometimes also referred to as the
Common Internet File System (CIFS). For a more thorough description,
see http://www.ubiqx.org/cifs/. Samba also implements the NetBIOS
protocol in nmbd.

samba(8)
The samba daemon provides the Active Directory services and file
and print services to SMB clients. The configuration file for
this daemon is described in smb.conf(5).

smbd(8)
The smbd daemon provides the file and print services to SMB
clients. The configuration file for this daemon is described
in smb.conf(5).

nmbd(8)
The nmbd daemon provides NetBIOS nameservice and browsing
support. The configuration file for this daemon is described
in smb.conf(5).

winbindd(8)
winbindd is a daemon that is used for integrating authentication
and the user database into unix.

smbclient(1)
The smbclient program implements a simple ftp-like client. This is
useful for accessing SMB shares on other compatible SMB servers,
and can also be used to allow a UNIX box to print to a printer
attached to any SMB server.

samba-tool(8)
The samba-tool is the main Samba Administration tool regarding
Active Directory services.

testparm(1)
The testparm utility is a simple syntax checker for Samba's
smb.conf(5) configuration file. In AD server mode samba-tool
testparm should be used though.

smbstatus(1)
The smbstatus tool provides access to information about the
current connections to smbd.

nmblookup(1)
The nmblookup tool allows NetBIOS name queries to be made.

smbpasswd(8)
The smbpasswd command is a tool for setting passwords on local
Samba but also on remote SMB servers.

smbcacls(1)
The smbcacls command is a tool to set ACL's on remote SMB servers.

smbtree(1)
The smbtree command is a text-based network neighborhood tool.

smbtar(1)
The smbtar can make backups of data directly from SMB servers.

smbspool(8)
smbspool is a helper utility for printing on printers connected
to SMB servers.

smbcontrol(1)
smbcontrol is a utility that can change the behaviour of running
samba, smbd, nmbd and winbindd daemons.

rpcclient(1)
rpcclient is a utility that can be used to execute RPC commands
on remote SMB servers.

pdbedit(8)
The pdbedit command can be used to maintain the local user database
on a Samba server.

net(8)
The net command is the main administration tool for Samba member
and standalone servers.

wbinfo(1)
wbinfo is a utility that retrieves and stores information related
to winbind.

profiles(1)
profiles is a command-line utility that can be used to replace
all occurrences of a certain SID with another SID.

log2pcap(1)
log2pcap is a utility for generating pcap trace files from Samba
log files.

vfstest(1)
vfstest is a utility that can be used to test vfs modules.

ntlm_auth(1)
ntlm_auth is a helper-utility for external programs wanting to
do NTLM-authentication.

smbcquotas(1)
smbcquotas is a tool to manage quotas on remote SMB servers.
```

Samba operational modes:

- AD member, `security = ads`
- *standalone*, just file and print services server
  - `security = user` with unspecified `server role`
  - `[security = AUTO]`, unspecified `server role`
  - unspecified `security` with `server role = STANDALONE`
- *DC*, domain controller
- `[security = AUTO]`, `server role = active directory domain controller`
- *PDC* aka *NT4 domain*, `security = User` and `domain logons = Yes`,
  `domain master = Yes`, `encrypt password = Yes`; plus `[netlogon]`
  shared must be available to all users

For logging, see [Configuring Logging on a Samba
Server](https://wiki.samba.org/index.php/Configuring_Logging_on_a_Samba_Server).

Note difference in domain and realm concepts. The correct user name formats are
`DOMAIN\user` or `user@REALM`.


## AD member role

``` shell
$ yast samba-client
```

``` shell
$ net ads --help # list of AD related commands

$ net ads info
LDAP server: 192.168.124.200
LDAP server name: w2k19.example.net
Realm: EXAMPLE.NET
Bind Path: dc=EXAMPLE,dc=NET
LDAP port: 389
Server time: Thu, 30 Dec 2021 15:14:01 CET
KDC server: 192.168.124.200
Server time offset: -1
Last machine account password change: Thu, 30 Dec 2021 13:31:05 CET

$ net ads testjoin
Join is OK

$ net ads user -U Administrator # list users
Enter Administrator's password:
Administrator
Guest
krbtgt
testovic
$ net ads user info testovic -U Administrator # user's details
net user info testovic -U Administrator
Enter Administrator's password:
Domain Users
Administrators
```


``` shell
$ wbinfo -u # checking AD users
HOME\administrator
HOME\guest
HOME\krbtgt
HOME\testovic

$ wbinfo -g # checking AD groups
HOME\domain computers
HOME\domain controllers
HOME\schema admins
HOME\enterprise admins
HOME\cert publishers
HOME\domain admins
HOME\domain users
HOME\domain guests
HOME\group policy creator owners
HOME\ras and ias servers
HOME\allowed rodc password replication group
HOME\denied rodc password replication group
HOME\read-only domain controllers
HOME\enterprise read-only domain controllers
HOME\cloneable domain controllers
HOME\protected users
HOME\key admins
HOME\enterprise key admins
HOME\dnsadmins
HOME\dnsupdateproxy

$ # wbinfo --authenticate 'HOME\testovic%linux' #
plaintext password authentication succeeded
challenge/response password authentication succeeded
```

Leaving an AD domain:

``` shell
$ net ads leave -U <user>%<password>
```


### AD member role: identity mapping

``` shell
$ man winbindd 2>/dev/null | \
  sed -n '/^NAME AND ID RESOLUTION/,/^[A-Z]/{/^CONFIG/q;p}' | \
  head -n -1 | fmt -w 80
NAME AND ID RESOLUTION
       Users and groups on a Windows NT server are assigned a security id
       (SID) which is globally unique when the user or group is created. To
       convert the Windows NT user or group into a unix user or group, a
       mapping between SIDs and unix user and group ids is required. This
       is one of the jobs that winbindd performs.

       As winbindd users and groups are resolved from a server, user and
       group ids are allocated from a specified range. This is done on
       a first come, first served basis, although all existing users and
       groups will be mapped as soon as a client performs a user or group
       enumeration command. The allocated unix ids are stored in a database
       and will be remembered.

       WARNING: The SID to unix id database is the only location where
       the user and group mappings are stored by winbindd. If this store
       is deleted or corrupted, there is no way for winbindd to determine
       which user and group ids correspond to Windows NT user and group rids.
```

SUSE maintains a document about pros/cons for various identity mapping, see
[General Information, Including Pros & Cons, And Examples, Of Various Identity
Mapping (idmap) Options](https://www.suse.com/support/kb/doc/?id=000017458).

``` shell
$ net ads dn 'CN=testovic,CN=Users,DC=example,DC=net' objectSID \
  -U Administrator
Enter Administrator's password:
Got 1 replies

objectSid: S-1-5-21-2185718108-4266305927-1067147705-1105

$ wbinfo -s S-1-5-21-2185718108-4266305927-1067147705-1105
EXAMPLENET\testovic 1
$ wbinfo -S S-1-5-21-2185718108-4266305927-1067147705-1105
10000

$ getent passwd EXAMPLENET\\testovic
testovic:*:10000:10000:testovic:/home/ad-testovic:/bin/sh
```

- idmap_ad
  ``` shell
  $ net ads dn 'CN=testovic,CN=Users,DC=example,DC=net' -U Administrator%<pw> | \
    tail -n +3 | head -n -1 | \
    grep -P '^((uid|gid)Number|unixHomeDirectory|loginShell):' | sort
  gidNumber: 10000
  loginShell: /bin/sh
  uidNumber: 10000
  unixHomeDirectory: /home/ad-testovic

  $ testparm -sv 2>/dev/null | grep -P '^\s+(idmap config|template|min domain)'
        min domain uid = 1000
        template homedir = /home/%D/%U
        template shell = /bin/bash
        idmap config examplenet : unix_primary_roup = yes
        idmap config examplenet : unix_nss_info = yes
        idmap config examplenet : schema_mode = rfc2307
        idmap config examplenet : range = 10000-99999
        idmap config examplenet : backend = ad
        idmap config * : range = 100000-200000
        idmap config * : backend = tdb
  ```

There could be various issues with users in AD member mode.

- if authentication (always against AD) succeeds, it can still fail because
  Samba needs to map and user (SID) to UID/GID.
  - returned UID/GID is below `min domain uid`, see
    [CVE-2020-25717.html](https://www.samba.org/samba/security/CVE-2020-25717.html).
  - deployments which depends on a fallback from 'DOMAIN\user' to just 'user',
    this fallback was removed as it is dangerous. See
    [CVE-2020-25717.html](https://www.samba.org/samba/security/CVE-2020-25717.html)
    or see [Samba issues after CVE-2020-25717
    fixes](https://www.suse.com/support/kb/doc/?id=000020533)

Note that `*` in `idmap config *` does not mean a general wildcard which could
be used with whatever idmap backend; this is a *default domain* which can be
used *only* with `tdb` or `autorid` backends, see [3.4.2. THE * DEFAULT
DOMAIN](https://access.redhat.com/documentation/zh-cn/red_hat_enterprise_linux/8/html/deploying_different_types_of_servers/con_the-asterisk-default-domain_assembly_understanding-and-configuring-samba-id-mapping).


### PDC aka NT4 domain

*WARNING*: Not finished!!!

See https://wiki.samba.org/index.php/Setting_up_Samba_as_an_NT4_PDC_(Quick_Start).

Some
[info](https://documentation.clearos.com/content:en_us:kb_adding_workstation_to_a_domain)
about newer Windows and joining to NT4
domains. [`nltest.exe`](https://ss64.com/nt/nltest.html) info about DC
operations.

``` shell
$ testparm -sv 2>&1 | grep -P '^\s*(encrypt passwords|security|domain (logon|master)|Server role)'
Server role: ROLE_DOMAIN_PDC
        domain logons = Yes
        domain master = Yes
        encrypt passwords = Yes
        security = USER
```

Usually such PDC would have LDAP backend for users...

``` shell
$ grep -Pv '^\s*($|#)' /etc/samba/smb.conf
[global]
        log level = 10
        netbios name = S153CL1
        workgroup = EXAMPLE
        security = User
        domain logons = Yes
        domain master = Yes
        local master = Yes
        preferred master = Yes
        passdb backend = ldapsam:ldaps://s153cl1.example.com
        encrypt passwords = Yes
        ldap admin dn = cn=Manager,dc=example,dc=com
        ldap debug level = 1
        ldap debug threshold = 10
        ldap delete dn = Yes
        ldap ssl = no
        ldap server require strong auth = Yes
        ldap group suffix = ou=groups
        ldap idmap suffix = ou=idmap
        ldap machine suffix = ou=computers
        ldap user suffix = ou=people
        ldap suffix = dc=example,dc=com
        idmap config * : backend = ldap
        idmap config * : range = 1000-999999
        idmap config * : ldap_url = ldaps://s153cl1.example.com/
        idmap config * : ldap_base_dn = ou=idmap,dc=example,dc=com
```

TLS cert of LDAP server must be in system trust store, otherwise
connection may fail. Note, that `tls *` `smb.conf(5)` options are
related to Samba 4 AD mode, ie. irrelevant for PDC with LDAP backend.

`ldap admin dn` password is not save in `smb.conf`, but it is saved in
`secrets.tdb` in Samba's _private dir`, security is file permissions based.

``` shell
$ smbpasswd -w <ldap admin dn password>
```

``` shell
$ tdbdump /var/lib/samba/private/secrets.tdb | grep -A 1 LDAP_BIND_PW
key(49) = "SECRETS/LDAP_BIND_PW/cn=Manager,dc=example,dc=com"
data(6) = "linux\00"

$ ls -l /var/lib/samba/private/secrets.tdb
-rw------- 1 root root 430080 Oct 19 23:46 /var/lib/samba/private/secrets.tdb
```

`winbindd`, when `idmap_ldap(8)` backend is used, uses its own secret to authenticate
to an LDAP server.


``` shell
$ testparm -sv 2>&1 | grep workgroup
        workgroup = EXAMPLE

$ testparm -sv 2>&1 | grep -P 'idmap config.*backend.*ldap'
        idmap config * : backend = ldap

# NOTE: net idmap set secret <DOMAIN> <secret>
#       but domain must match value in 'idmap config <domain> : backend = ldap'

$ net idmap set secret 'EXAMPLE' linux
The only currently supported backend are LDAP and rfc2307

$ net idmap set secret '*' linux
Secret stored

$ tdbdump /var/lib/samba/private/secrets.tdb | grep -A 1 -i idmap_ldap
key(57) = "SECRETS/GENERIC/IDMAP_LDAP_*/cn=Manager,dc=example,dc=com"
data(6) = "linux\00"
```

There must be several entries in LDAP for PDC/NT4 domain with ldapsam.

``` shell
# loaded Samba objectClasses
$ ldapsearch -LLL -H ldaps://s153cl1.example.com:636 -x -W \
  -D 'cn=Manager,dc=example,dc=com' -s base -b 'cn=subschema' \
  objectclasses | \
    grep -Po '^objectClasses: .*NAME '"'"'\K(\w+)(?=.*)' | grep samba | sort
Enter LDAP Password:
sambaConfig
sambaConfigOption
sambaDomain
sambaGroupMapping
sambaIdmapEntry
sambaSamAccount
sambaShare
sambaSidEntry
sambaTrustedDomain
sambaTrustedDomainPassword
sambaTrustPassword
sambaUnixIdPool
```

One way to populate LDAP for Samba is to use `smbldap-populate` from
[smbldap-tools](https://github.com/fumiyas/smbldap-tools). Note I had
to use this
[workaround](https://github.com/fumiyas/smbldap-tools/issues/2).

``` shell
$ systemctl is-active smb
active

$ net getlocalsid EXAMPLE
SID for domain EXAMPLE is: S-1-5-21-2679777877-1024446765-2520388554

$ grep -Pv '^\s*(#|$)' /usr/local/etc/smbldap-tools/smbldap{_bind,}.conf
/usr/local/etc/smbldap-tools/smbldap_bind.conf:slaveDN="cn=Manager,dc=example,dc=com"
/usr/local/etc/smbldap-tools/smbldap_bind.conf:slavePw="linux"
/usr/local/etc/smbldap-tools/smbldap_bind.conf:masterDN="cn=Manager,dc=example,dc=com"
/usr/local/etc/smbldap-tools/smbldap_bind.conf:masterPw="linux"
/usr/local/etc/smbldap-tools/smbldap.conf:SID="S-1-5-21-2679777877-1024446765-2520388554"
/usr/local/etc/smbldap-tools/smbldap.conf:sambaDomain="EXAMPLE"
/usr/local/etc/smbldap-tools/smbldap.conf:slaveLDAP="ldap://127.0.0.1/"
/usr/local/etc/smbldap-tools/smbldap.conf:masterLDAP="ldap://127.0.0.1/"
/usr/local/etc/smbldap-tools/smbldap.conf:ldapTLS="1"
/usr/local/etc/smbldap-tools/smbldap.conf:verify="none"
/usr/local/etc/smbldap-tools/smbldap.conf:cafile="/usr/local/etc/smbldap-tools/ca.pem"
/usr/local/etc/smbldap-tools/smbldap.conf:suffix="dc=example,dc=com"
/usr/local/etc/smbldap-tools/smbldap.conf:usersdn="ou=Users,${suffix}"
/usr/local/etc/smbldap-tools/smbldap.conf:computersdn="ou=Computers,${suffix}"
/usr/local/etc/smbldap-tools/smbldap.conf:groupsdn="ou=Groups,${suffix}"
/usr/local/etc/smbldap-tools/smbldap.conf:idmapdn="ou=Idmap,${suffix}"
/usr/local/etc/smbldap-tools/smbldap.conf:sambaUnixIdPooldn="sambaDomainName=${sambaDomain},${suffix}"
/usr/local/etc/smbldap-tools/smbldap.conf:scope="sub"
/usr/local/etc/smbldap-tools/smbldap.conf:password_hash="SSHA"
/usr/local/etc/smbldap-tools/smbldap.conf:password_crypt_salt_format="%s"
/usr/local/etc/smbldap-tools/smbldap.conf:userLoginShell="/bin/bash"
/usr/local/etc/smbldap-tools/smbldap.conf:userHome="/home/%U"
/usr/local/etc/smbldap-tools/smbldap.conf:userHomeDirectoryMode="700"
/usr/local/etc/smbldap-tools/smbldap.conf:userGecos="System User"
/usr/local/etc/smbldap-tools/smbldap.conf:defaultUserGid="513"
/usr/local/etc/smbldap-tools/smbldap.conf:defaultComputerGid="515"
/usr/local/etc/smbldap-tools/smbldap.conf:skeletonDir="/etc/skel"
/usr/local/etc/smbldap-tools/smbldap.conf:shadowAccount="1"
/usr/local/etc/smbldap-tools/smbldap.conf:defaultMaxPasswordAge="45"
/usr/local/etc/smbldap-tools/smbldap.conf:userSmbHome="\\S153CL1\%U"
/usr/local/etc/smbldap-tools/smbldap.conf:userProfile="\\S153CL1\profiles\%U"
/usr/local/etc/smbldap-tools/smbldap.conf:userHomeDrive="H:"
/usr/local/etc/smbldap-tools/smbldap.conf:userScript="logon.bat"
/usr/local/etc/smbldap-tools/smbldap.conf:mailDomain="example.com"
/usr/local/etc/smbldap-tools/smbldap.conf:lanmanPassword="0"
/usr/local/etc/smbldap-tools/smbldap.conf:with_smbpasswd="0"
/usr/local/etc/smbldap-tools/smbldap.conf:smbpasswd="/usr/bin/smbpasswd"
/usr/local/etc/smbldap-tools/smbldap.conf:with_slappasswd="0"
/usr/local/etc/smbldap-tools/smbldap.conf:slappasswd="/usr/sbin/slappasswd"

# note 'nis.schema' and that 'rfc2307bis.schema' is NOT present!

$ grep -P '^include .*schema' /etc/openldap/slapd.conf
include /etc/openldap/schema/core.schema
include /etc/openldap/schema/cosine.schema
include /etc/openldap/schema/nis.schema
include /etc/openldap/schema/inetorgperson.schema
include /etc/openldap/schema/yast.schema
include /usr/share/doc/packages/samba/examples/LDAP/samba.schema
include /etc/openldap/schema/ppolicy.schema

$ slapcat
dn: dc=example,dc=com
objectClass: dcObject
objectClass: organization
o: Example Corp.
dc: example
structuralObjectClass: organization
entryUUID: e55fe110-e33a-103c-8b11-df684872bf89
creatorsName: cn=Manager,dc=example,dc=com
createTimestamp: 20221018141417Z
entryCSN: 20221018141417.351360Z#000000#000#000000
modifiersName: cn=Manager,dc=example,dc=com
modifyTimestamp: 20221018141417Z

$ smbldap-populate -a Administrator -b guest
Populating LDAP directory for domain EXAMPLE (S-1-5-21-2679777877-1024446765-2520388554)
(using builtin directory structure)

entry dc=example,dc=com already exist.
adding new entry: ou=Users,dc=example,dc=com
adding new entry: ou=Groups,dc=example,dc=com
adding new entry: ou=Computers,dc=example,dc=com
adding new entry: ou=Idmap,dc=example,dc=com
adding new entry: sambaDomainName=EXAMPLE,dc=example,dc=com
adding new entry: uid=Administrator,ou=Users,dc=example,dc=com
adding new entry: uid=guest,ou=Users,dc=example,dc=com
adding new entry: cn=Domain Admins,ou=Groups,dc=example,dc=com
adding new entry: cn=Domain Users,ou=Groups,dc=example,dc=com
adding new entry: cn=Domain Guests,ou=Groups,dc=example,dc=com
adding new entry: cn=Domain Computers,ou=Groups,dc=example,dc=com
adding new entry: cn=Administrators,ou=Groups,dc=example,dc=com
adding new entry: cn=Account Operators,ou=Groups,dc=example,dc=com
adding new entry: cn=Print Operators,ou=Groups,dc=example,dc=com
adding new entry: cn=Backup Operators,ou=Groups,dc=example,dc=com
adding new entry: cn=Replicators,ou=Groups,dc=example,dc=com

Please provide a password for the domain Administrator:
Changing UNIX and samba passwords for Administrator
New password:
Retype new password:

$ slapcat  | grep ^dn
dn: dc=example,dc=com
dn: ou=Users,dc=example,dc=com
dn: ou=Groups,dc=example,dc=com
dn: ou=Computers,dc=example,dc=com
dn: ou=Idmap,dc=example,dc=com
dn: sambaDomainName=EXAMPLE,dc=example,dc=com
dn: uid=Administrator,ou=Users,dc=example,dc=com
dn: uid=guest,ou=Users,dc=example,dc=com
dn: cn=Domain Admins,ou=Groups,dc=example,dc=com
dn: cn=Domain Users,ou=Groups,dc=example,dc=com
dn: cn=Domain Guests,ou=Groups,dc=example,dc=com
dn: cn=Domain Computers,ou=Groups,dc=example,dc=com
dn: cn=Administrators,ou=Groups,dc=example,dc=com
dn: cn=Account Operators,ou=Groups,dc=example,dc=com
dn: cn=Print Operators,ou=Groups,dc=example,dc=com
dn: cn=Backup Operators,ou=Groups,dc=example,dc=com
dn: cn=Replicators,ou=Groups,dc=example,dc=com
```


``` shell
$ ldapsearch -LLL -H ldaps://s153cl1.example.com:636 -x -W -D 'cn=Manager,dc=example,dc=com' -b 'dc=example,dc=com' 'objectClass=sambaDomain'
Enter LDAP Password:
dn: sambaDomainName=EXAMPLE,dc=example,dc=com
sambaDomainName: EXAMPLE
sambaSID: S-1-5-21-2679777877-1024446765-2520388554
sambaAlgorithmicRidBase: 1000
objectClass: sambaDomain
sambaNextUserRid: 1000
sambaMinPwdLength: 5
sambaPwdHistoryLength: 0
sambaLogonToChgPwd: 0
sambaMaxPwdAge: -1
sambaMinPwdAge: 0
sambaLockoutDuration: 30
sambaLockoutObservationWindow: 30
sambaLockoutThreshold: 0
sambaForceLogoff: -1
sambaRefuseMachinePwdChange: 0
sambaNextRid: 1003
```

``` shell
$ net -d 0 getlocalsid
SID for domain S153CL1 is: S-1-5-21-986102549-73732553-4076470224

$ net -d 0 getdomainsid
SID for domain EXAMPLE is: S-1-5-21-2679777877-1024446765-2520388554


```

Users to Samba/LDAP are added with `smbpasswd`. _posixAccount_ based
user entry must exit - TODO: recheck! -; a user entry DN must be
'uid=<user>' and `ldap user suffix` (see `smb.conf(5)`). (Note, `ldap
filter` was deleted from Samba in 2005!). And example:

```
# an existing user entry
dn: uid=gwcarter,ou=people,dc=example,dc=com
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: top
objectClass: shadowAccount
cn: Gerald W. Carter
sn: Carter
mail: jerry@example.com
structuralObjectClass: inetOrgPerson
entryUUID: 3b7335b0-e341-103c-8b13-df684872bf89
creatorsName: cn=Manager,dc=example,dc=com
createTimestamp: 20221018145938Z
userPassword:: e1NTSEF9MnFodE5jSDIrZFE0dWcyTG9xRTVMU3RBN050M0VvOVY=
shadowLastChange: 11108
shadowMax: 99999
shadowWarning: 7
shadowFlag: 134539460
loginShell: /bin/bash
uidNumber: 1010
gidNumber: 1010
homeDirectory: /home/gwcarter
uid: gwcarter
entryCSN: 20221019213926.792794Z#000000#000#000000
modifiersName: cn=Manager,dc=example,dc=com
modifyTimestamp: 20221019213926Z
```

``` shell
$ smbpasswd -D 10 -a gwcarter
...
Finding user gwcarter
Trying _Get_Pwnam(), username as lowercase is gwcarter
Get_Pwnam_internals did find user [gwcarter]!
...
ldapsam_add_sam_account: User exists without samba attributes: adding them
[LDAP] ldap_get_dn
[LDAP] ldap_get_values
smbldap_make_mod: attribute |uid| not changed.
init_ldap_from_sam: Setting entry for user: gwcarter
[LDAP] ldap_get_values
smbldap_get_single_attribute: [sambaSID] = [<does not exist>]
smbldap_make_mod: adding attribute |sambaSID| value |S-1-5-21-2679777877-1024446765-2520388554-1001|
[LDAP] ldap_get_values
smbldap_get_single_attribute: [displayName] = [<does not exist>]
smbldap_make_mod: adding attribute |displayName| value |Gerald W. Carter|
[LDAP] ldap_get_values
smbldap_get_single_attribute: [sambaAcctFlags] = [<does not exist>]
smbldap_make_mod: adding attribute |sambaAcctFlags| value |[DU         ]|
smbldap_modify: dn => [uid=gwcarter,ou=people,dc=example,dc=com]
...
ldapsam_add_sam_account: added: uid == gwcarter in the LDAP database
[LDAP] ldap_msgfree
smbldap_search_ext: base => [dc=example,dc=com], filter => [(&(uid=gwcarter)(objectclass=sambaSamAccount))], scope => [2]
[LDAP] ldap_search_ext
[LDAP] put_filter: "(&(uid=gwcarter)(objectclass=sambaSamAccount))"
[LDAP] put_filter: AND
[LDAP] put_filter_list "(uid=gwcarter)(objectclass=sambaSamAccount)"
[LDAP] put_filter: "(uid=gwcarter)"
[LDAP] put_filter: simple
[LDAP] put_simple_filter: "uid=gwcarter"
[LDAP] put_filter: "(objectclass=sambaSamAccount)"
[LDAP] put_filter: simple
[LDAP] put_simple_filter: "objectclass=sambaSamAccount"
...
Finding user gwcarter
Trying _Get_Pwnam(), username as lowercase is gwcarter
Get_Pwnam_internals did find user [gwcarter]!
xid_to_sid: GID 1010 -> S-0-0 from cache
xid_to_sid: GID 1010 -> S-1-22-2-1010 fallback
smbldap_search_ext: base => [dc=example,dc=com], filter => [(&(objectClass=sambaGroupMapping)(gidNumber=1010))], scope => [2]
[LDAP] ldap_search_ext
[LDAP] put_filter: "(&(objectClass=sambaGroupMapping)(gidNumber=1010))"
[LDAP] put_filter: AND
[LDAP] put_filter_list "(objectClass=sambaGroupMapping)(gidNumber=1010)"
[LDAP] put_filter: "(objectClass=sambaGroupMapping)"
[LDAP] put_filter: simple
[LDAP] put_simple_filter: "objectClass=sambaGroupMapping"
[LDAP] put_filter: "(gidNumber=1010)"
[LDAP] put_filter: simple
[LDAP] put_simple_filter: "gidNumber=1010"
...
ldapsam_update_sam_account: successfully modified uid = gwcarter in the LDAP database
[LDAP] ldap_msgfree
Added user gwcarter.
```

The user entry got `sambaSID`, `sambaNTPassword`...

```
# modified user entry
dn: uid=gwcarter,ou=people,dc=example,dc=com
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: top
objectClass: shadowAccount
objectClass: sambaSamAccount
cn: Gerald W. Carter
sn: Carter
mail: jerry@example.com
structuralObjectClass: inetOrgPerson
entryUUID: 3b7335b0-e341-103c-8b13-df684872bf89
creatorsName: cn=Manager,dc=example,dc=com
createTimestamp: 20221018145938Z
userPassword:: e1NTSEF9MnFodE5jSDIrZFE0dWcyTG9xRTVMU3RBN050M0VvOVY=
shadowLastChange: 11108
shadowMax: 99999
shadowWarning: 7
shadowFlag: 134539460
loginShell: /bin/bash
uidNumber: 1010
gidNumber: 1010
homeDirectory: /home/gwcarter
uid: gwcarter
sambaSID: S-1-5-21-2679777877-1024446765-2520388554-1001
displayName: Gerald W. Carter
sambaNTPassword: F0873F3268072C7B1150B15670291137
sambaPasswordHistory: 000000000000000000000000000000000000000000000000000000
 0000000000
sambaPwdLastSet: 1666216348
sambaAcctFlags: [U          ]
entryCSN: 20221019215228.050371Z#000000#000#000000
modifiersName: cn=Manager,dc=example,dc=com
modifyTimestamp: 20221019215228Z
```

``` shell
$ pdbedit -d 0 -L
ldap_url_parse_ext(ldap://localhost/)
ldap_init: trying /etc/openldap/ldap.conf
ldap_init: using /etc/openldap/ldap.conf
ldap_init: HOME env is /root
ldap_init: trying /root/ldaprc
ldap_init: trying /root/.ldaprc
ldap_init: using /root/.ldaprc
ldap_init: trying ldaprc
ldap_init: LDAPCONF env is NULL
ldap_init: LDAPRC env is NULL
gwcarter:1010:Gerald W. Carter

$ wbinfo -u
gwcarter
```

NetBIOS name service is old DNS-like protocol, often related to
Microsoft implementation of NetBIOS Name Service called Windows
Internet Name Service (WINS).

``` shell
$ testparm -sv 2>&1 | grep -P '^\s*(wins|dns proxy)'
        dns proxy = Yes
        wins hook =
        wins proxy = No
        wins server = 192.168.122.11
        wins support = Yes
```

``` shell
$ ss -tunlp | grep -P 'nmbd'
udp    UNCONN   0        0          192.168.122.255:137           0.0.0.0:*      users:(("nmbd",pid=8694,fd=23))
udp    UNCONN   0        0           192.168.122.11:137           0.0.0.0:*      users:(("nmbd",pid=8694,fd=22))
udp    UNCONN   0        0          192.168.123.255:137           0.0.0.0:*      users:(("nmbd",pid=8694,fd=19))
udp    UNCONN   0        0           192.168.123.11:137           0.0.0.0:*      users:(("nmbd",pid=8694,fd=18))
udp    UNCONN   0        0                  0.0.0.0:137           0.0.0.0:*      users:(("nmbd",pid=8694,fd=16))
udp    UNCONN   0        0          192.168.122.255:138           0.0.0.0:*      users:(("nmbd",pid=8694,fd=25))
udp    UNCONN   0        0           192.168.122.11:138           0.0.0.0:*      users:(("nmbd",pid=8694,fd=24))
udp    UNCONN   0        0          192.168.123.255:138           0.0.0.0:*      users:(("nmbd",pid=8694,fd=21))
udp    UNCONN   0        0           192.168.123.11:138           0.0.0.0:*      users:(("nmbd",pid=8694,fd=20))
udp    UNCONN   0        0                  0.0.0.0:138           0.0.0.0:*      users:(("nmbd",pid=8694,fd=17))
```

``` shell
$ nmblookup -d 0 'EXAMPLE#1c' 'EXAMPLE#1b'
192.168.123.11 EXAMPLE<1c>
192.168.123.11 EXAMPLE<1b>

$ nmbstatus
Found 1 hosts. Collecting additional information. Please wait.
.
WORKGROUP       EXAMPLE
PDC     S153CL1
DMB     S153CL1
LMB     S153CL1
MEMBERS S153CL1
```

Creating 'Domain Admins' group, its RID is always 512!

``` shell
$ net getlocalsid EXAMPLE
SID for domain EXAMPLE is: S-1-5-21-2679777877-1024446765-2520388554

$ getent group domainadmins
domainadmins:*:100001:gwcarter

$ id gwcarter
uid=100000(gwcarter) gid=100000(domainusers) groups=100001(domainadmins),100000(domainusers)

$ net groupmap add sid=S-1-5-21-2679777877-1024446765-2520388554-512 ntgroup="Domain Admins" unixgroup=domainadmins
Successfully added group Domain Admins to the mapping db as a domain group
```

``` shell
$ wbinfo -u
gwcarter
$ wbinfo -g
domain admins
```

TODO: account with privileges to add computers.
      https://wiki.samba.org/index.php/Joining_a_Windows_Client_or_Server_to_a_Domain
      https://wiki.samba.org/index.php/Required_Settings_for_Samba_NT4_Domains (registry settings???)


## Samba shares

``` shell
$ smbclient -L //t14s -U guest%

        Sharename       Type      Comment
        ---------       ----      -------
        pub             Disk      public
        foo             Disk      foo
        IPC$            IPC       IPC Service (Samba 4.15.2-git.193.a4d6307f1fdSUSE-oS15.5-x86_64)
SMB1 disabled -- no workgroup available
```

What is this magic `IPC$` share? The `IPC$` share allows users to anonymously
fetch a list of shared resources from a server. It can be used as a point of
attack into a system.

> The IPC$ share is also known as a null session connection. By using this
> session, Windows lets anonymous users perform certain activities, such as
> enumerating the names of domain accounts and network shares.
>
> The IPC$ share is created by the Windows Server service. This special share
> exists to allow for subsequent named pipe connections to the server. The
> server's named pipes are created by built-in operating system components and
> by any applications or services that are installed on the system. When the
> named pipe is being created, the process specifies the security that is
> associated with the pipe, and then makes sure that access is only granted to
> the specified users or groups.
>
> -- [IPC$ share and null session behavior in > Windows](https://support.microsoft.com/en-us/kb/3034016)

Downloading [multiple](https://superuser.com/a/856640) files via
`mget`:

``` shell
$ smbclient //127.0.0.1/pub -Uroot%'' << EOM
> mask ""
> recurse on
> prompt off
> pwd
> cd foo\bar\"foo bar"
> mget *.csv
> quit
> EOM
Try "help" to get a list of possible commands.
Current directory is \\127.0.0.1\pub\
getting file \foo\bar\foo bar\test 123.csv of size 0 as test 123.csv (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```

## Samba TDB files

Samba project maintains [TDB
Locations](https://wiki.samba.org/index.php/TDB_Locations) page which tries to
explain meaning of `tdb` files. There's also another
[page](https://web.archive.org/web/20200220135846/http://pig.made-it.com/samba-tdb.html)
which describes if such files are temporary or permanent.


## Samba troubleshooting

A good way to troubleshoot is via `smbclient`

``` shell
$ smbclient //<server>/<share> password -W domain -U username << EOM
<commands...>
exit
EOM

# or

$ smbclient //<server>/<share> password -W domain -U username \
  -c '<commands...>;quit'
```

- authentication details (at lest `log level = 3`):
  - NTLM successful authentication:
    ```
    $ egrep -A 1 '\(auth_check_ntlm_password\)$' log.smbd
    [2022/01/07 10:49:20.333714,  3] ../../source3/auth/auth.c:201(auth_check_ntlm_password)
      check_ntlm_password:  Checking password for unmapped user [EXAMPLENET]\[testovic]@[S153ADMEM01] with the new password interface
    [2022/01/07 10:49:20.333727,  3] ../../source3/auth/auth.c:204(auth_check_ntlm_password)
      check_ntlm_password:  mapped user is: [EXAMPLENET]\[testovic]@[S153ADMEM01]
    [2022/01/07 10:49:20.341081,  3] ../../source3/auth/auth.c:268(auth_check_ntlm_password)
      auth_check_ntlm_password: winbind authentication for user [testovic] succeeded
    --
    [2022/01/07 10:49:20.341517,  2] ../../source3/auth/auth.c:329(auth_check_ntlm_password)
      check_ntlm_password:  authentication for user [testovic] -> [testovic] -> [EXAMPLENET\testovic] succeeded
    ```
  - NTLM unsuccessful authentication:
    ``` shell
    $ egrep -A 1 '\(auth_check_ntlm_password\)$' log.smbd
    [2022/01/07 10:52:26.471941,  3] ../../source3/auth/auth.c:201(auth_check_ntlm_password)
      check_ntlm_password:  Checking password for unmapped user [EXAMPLENET]\[testovic]@[S153ADMEM01] with the new password interface
    [2022/01/07 10:52:26.471954,  3] ../../source3/auth/auth.c:204(auth_check_ntlm_password)
      check_ntlm_password:  mapped user is: [EXAMPLENET]\[testovic]@[S153ADMEM01]
    [2022/01/07 10:52:26.480242,  2] ../../source3/auth/auth.c:347(auth_check_ntlm_password)
      check_ntlm_password:  Authentication for user [testovic] -> [testovic] FAILED with error NT_STATUS_WRONG_PASSWORD, authoritative=1
    ```
  - Kerberos successful authentication:
    ``` shell
    $ egrep -A 1 '\(auth.*pac\)$' log.smbd
    [2022/01/07 10:58:27.359780,  5] ../../source3/auth/auth_generic.c:168(auth3_generate_session_info_pac)
      check_ntlm_password:  PAM Account for user [EXAMPLENET\testovic] succeeded
    [2022/01/07 10:58:27.359789,  3] ../../source3/auth/auth_generic.c:171(auth3_generate_session_info_pac)
      Kerberos ticket principal name is [testovic@EXAMPLE.NET]
    --
    [2022/01/07 10:58:27.362180,  5] ../../source3/auth/auth_generic.c:252(auth3_generate_session_info_pac)
      ../../source3/auth/auth_generic.c:252OK: user: testovic domain: EXAMPLENET client: 192.168.124.35
    ```
- authorization details (at least `log level = 3`):
  - an example of being in `invalid users` list:
    ``` shell
    $ egrep -A 1 'service\.c:.*connection' log.smbd
    [2022/01/07 11:08:07.115208,  3] ../../source3/smbd/service.c:609(make_connection_snum)
      make_connection_snum: Connect path is '/tmp' for service [IPC$]
    --
    [2022/01/07 11:08:07.115339,  3] ../../source3/smbd/service.c:852(make_connection_snum)
      192.168.124.35 (ipv4:192.168.124.35:50306) connect to service IPC$ initially as user EXAMPLENET\testovic (uid=11105, gid=10513) (pid 11255)
    --
    [2022/01/07 11:08:07.116281,  1] ../../source3/smbd/service.c:366(create_connection_session_info)
      create_connection_session_info: user 'EXAMPLENET\testovic' (from session setup) not permitted to access this share (tmp)
    [2022/01/07 11:08:07.116303,  1] ../../source3/smbd/service.c:544(make_connection_snum)
      create_connection_session_info failed: NT_STATUS_ACCESS_DENIED
    ```
- kerberos PAC, a part of a Kerberos ticket, the so called Authorization Data.
  Some details at [Howto/Inspecting the PAC](https://www.freeipa.org/page/Howto/Inspecting_the_PAC),
  and https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962

  ``` shell
  $ grep -m 1 -A 30 'PAC_BUFFER' log.winbindd
              buffers: struct PAC_BUFFER
                  type                     : PAC_TYPE_LOGON_INFO (1)
                  _ndr_size                : 0x000001d0 (464)
                  info                     : *
                      info                     : union PAC_INFO(case 1)
                      logon_info: struct PAC_LOGON_INFO_CTR
                          info                     : *
                              info: struct PAC_LOGON_INFO
                                  info3: struct netr_SamInfo3
                                      base: struct netr_SamBaseInfo
                                          logon_time               : Fri Jan  7 10:56:53 AM 2022 CET
                                          logoff_time              : Thu Sep 14 04:48:05 AM 30828 CEST
                                          kickoff_time             : Thu Sep 14 04:48:05 AM 30828 CEST
                                          last_password_change     : Thu Dec 23 12:23:24 PM 2021 CET
                                          allow_password_change    : Fri Dec 24 12:23:24 PM 2021 CET
                                          force_password_change    : Thu Feb  3 12:23:24 PM 2022 CET
                                          account_name: struct lsa_String
                                              length                   : 0x0010 (16)
                                              size                     : 0x0010 (16)
                                              string                   : *
                                                  string                   : 'testovic'
                                          full_name: struct lsa_String
                                              length                   : 0x0010 (16)
                                              size                     : 0x0010 (16)
                                              string                   : *
                                                  string                   : 'testovic'
                                          logon_script: struct lsa_String
                                              length                   : 0x0000 (0)
                                              size                     : 0x0000 (0)
                                              string                   : *
                                                  string                   : ''
  ```

Or...

``` shell
$ net ads kerberos pac dump --option='realm = EXAMPLE.NET' \
  --option='kerberos method = system keytab' \
  -s /dev/null local_service=host/s125admem01.example.net@EXAMPLE.NET \
  -U testovic%Linux123! | grep sid
                                        domain_sid               : *
                                            domain_sid               : S-1-5-21-186059982-468505587-3623024618
                                    sidcount                 : 0x00000001 (1)
                                    sids                     : *
                                        sids: ARRAY(1)
                                            sids: struct netr_SidAttr
                                                sid                      : *
                                                    sid                      : S-1-18-1
                                    domain_sid               : NULL
                        sam_name_and_sid: struct PAC_UPN_DNS_INFO_SAM_NAME_AND_SID
                            objectsid_size           : 0x001c (28)
                            objectsid                : *
                                objectsid                : S-1-5-21-186059982-468505587-3623024618-1104
```

``` shell
$ net ads kerberos pac save filename=/tmp/out.pac \
  --option='realm = EXAMPLE.NET' \
  --option='kerberos method = system keytab' \
  -s /dev/null local_service=host/s125admem01.example.net@EXAMPLE.NET \
  -U testovic%Linux123!
```

`ndrdump` is part of `samba-test` package.

``` shell
$ ndrdump  --debug-stdout -d 10 krb5pac PAC_DATA struct /tmp/out.pac
INFO: Current debug levels:
  all: 10
  tdb: 10
  printdrivers: 10
  lanman: 10
  smb: 10
  rpc_parse: 10
  rpc_srv: 10
  rpc_cli: 10
  passdb: 10
  sam: 10
  auth: 10
  winbind: 10
  vfs: 10
  idmap: 10
  quota: 10
  acls: 10
  locking: 10
  msdfs: 10
  dmapi: 10
  registry: 10
  scavenger: 10
  dns: 10
  ldb: 10
  tevent: 10
  auth_audit: 10
  auth_json_audit: 10
  kerberos: 10
  drs_repl: 10
  smb2: 10
  smb2_credits: 10
  dsdb_audit: 10
  dsdb_json_audit: 10
  dsdb_password_audit: 10
  dsdb_password_json_audit: 10
  dsdb_transaction_audit: 10
  dsdb_transaction_json_audit: 10
  dsdb_group_audit: 10
  dsdb_group_json_audit: 10
lpcfg_load: refreshing parameters from /etc/samba/smb.conf
Processing section "[global]"
Processing section "[ipc$]"
WARNING: No path in service ipc$ - making it unavailable!
NOTE: Service ipc$ is flagged unavailable.
Processing section "[pub]"
Processing section "[homes]"
pm_process() returned Yes
pull returned Success
    PAC_DATA: struct PAC_DATA
        num_buffers              : 0x00000006 (6)
        version                  : 0x00000000 (0)
        buffers: ARRAY(6)
            buffers: struct PAC_BUFFER
                type                     : PAC_TYPE_LOGON_INFO (1)
                _ndr_size                : 0x000001d8 (472)
                info                     : *
                    info                     : union PAC_INFO(case 1)
                    logon_info: struct PAC_LOGON_INFO_CTR
                        info                     : *
                            info: struct PAC_LOGON_INFO
                                info3: struct netr_SamInfo3
                                    base: struct netr_SamBaseInfo
                                        logon_time               : Fri Mar  4 10:53:15 AM 2022 CET
                                        logoff_time              : Thu Sep 14 04:48:05 AM 30828 CEST
                                        kickoff_time             : Thu Sep 14 04:48:05 AM 30828 CEST
                                        last_password_change     : Thu Mar  3 01:52:24 PM 2022 CET
                                        allow_password_change    : Fri Mar  4 01:52:24 PM 2022 CET
                                        force_password_change    : Thu Sep 14 04:48:05 AM 30828 CEST
                                        account_name: struct lsa_String
                                            length                   : 0x0010 (16)
                                            size                     : 0x0010 (16)
                                            string                   : *
                                                string                   : 'testovic'
                                        full_name: struct lsa_String
                                            length                   : 0x0010 (16)
                                            size                     : 0x0010 (16)
                                            string                   : *
                                                string                   : 'testovic'
                                        logon_script: struct lsa_String
                                            length                   : 0x0000 (0)
                                            size                     : 0x0000 (0)
                                            string                   : *
                                                string                   : ''
                                        profile_path: struct lsa_String
                                            length                   : 0x0000 (0)
                                            size                     : 0x0000 (0)
                                            string                   : *
                                                string                   : ''
                                        home_directory: struct lsa_String
                                            length                   : 0x0000 (0)
                                            size                     : 0x0000 (0)
                                            string                   : *
                                                string                   : ''
                                        home_drive: struct lsa_String
                                            length                   : 0x0000 (0)
                                            size                     : 0x0000 (0)
                                            string                   : *
                                                string                   : ''
                                        logon_count              : 0x0026 (38)
                                        bad_password_count       : 0x0000 (0)
                                        rid                      : 0x00000450 (1104)
                                        primary_gid              : 0x00000201 (513)
                                        groups: struct samr_RidWithAttributeArray
                                            count                    : 0x00000002 (2)
                                            rids                     : *
                                                rids: ARRAY(2)
                                                    rids: struct samr_RidWithAttribute
                                                        rid                      : 0x00000201 (513)
                                                        attributes               : 0x00000007 (7)
                                                               1: SE_GROUP_MANDATORY
                                                               1: SE_GROUP_ENABLED_BY_DEFAULT
                                                               1: SE_GROUP_ENABLED
                                                               0: SE_GROUP_OWNER
                                                               0: SE_GROUP_USE_FOR_DENY_ONLY
                                                               0: SE_GROUP_INTEGRITY
                                                               0: SE_GROUP_INTEGRITY_ENABLED
                                                               0: SE_GROUP_RESOURCE
                                                            0x00: SE_GROUP_LOGON_ID         (0)
                                                    rids: struct samr_RidWithAttribute
                                                        rid                      : 0x00000461 (1121)
                                                        attributes               : 0x00000007 (7)
                                                               1: SE_GROUP_MANDATORY
                                                               1: SE_GROUP_ENABLED_BY_DEFAULT
                                                               1: SE_GROUP_ENABLED
                                                               0: SE_GROUP_OWNER
                                                               0: SE_GROUP_USE_FOR_DENY_ONLY
                                                               0: SE_GROUP_INTEGRITY
                                                               0: SE_GROUP_INTEGRITY_ENABLED
                                                               0: SE_GROUP_RESOURCE
                                                            0x00: SE_GROUP_LOGON_ID         (0)
                                        user_flags               : 0x00000020 (32)
                                               0: NETLOGON_GUEST
                                               0: NETLOGON_NOENCRYPTION
                                               0: NETLOGON_CACHED_ACCOUNT
                                               0: NETLOGON_USED_LM_PASSWORD
                                               1: NETLOGON_EXTRA_SIDS
                                               0: NETLOGON_SUBAUTH_SESSION_KEY
                                               0: NETLOGON_SERVER_TRUST_ACCOUNT
                                               0: NETLOGON_NTLMV2_ENABLED
                                               0: NETLOGON_RESOURCE_GROUPS
                                               0: NETLOGON_PROFILE_PATH_RETURNED
                                               0: NETLOGON_GRACE_LOGON
                                        key: struct netr_UserSessionKey
                                            key: ARRAY(16): <REDACTED SECRET VALUES>
                                        logon_server: struct lsa_StringLarge
                                            length                   : 0x000a (10)
                                            size                     : 0x000c (12)
                                            string                   : *
                                                string                   : 'W2K19'
                                        logon_domain: struct lsa_StringLarge
                                            length                   : 0x0014 (20)
                                            size                     : 0x0016 (22)
                                            string                   : *
                                                string                   : 'EXAMPLENET'
                                        domain_sid               : *
                                            domain_sid               : S-1-5-21-186059982-468505587-3623024618
                                        LMSessKey: struct netr_LMSessionKey
                                            key: ARRAY(8): <REDACTED SECRET VALUES>
                                        acct_flags               : 0x00000210 (528)
                                               0: ACB_DISABLED
                                               0: ACB_HOMDIRREQ
                                               0: ACB_PWNOTREQ
                                               0: ACB_TEMPDUP
                                               1: ACB_NORMAL
                                               0: ACB_MNS
                                               0: ACB_DOMTRUST
                                               0: ACB_WSTRUST
                                               0: ACB_SVRTRUST
                                               1: ACB_PWNOEXP
                                               0: ACB_AUTOLOCK
                                               0: ACB_ENC_TXT_PWD_ALLOWED
                                               0: ACB_SMARTCARD_REQUIRED
                                               0: ACB_TRUSTED_FOR_DELEGATION
                                               0: ACB_NOT_DELEGATED
                                               0: ACB_USE_DES_KEY_ONLY
                                               0: ACB_DONT_REQUIRE_PREAUTH
                                               0: ACB_PW_EXPIRED
                                               0: ACB_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
                                               0: ACB_NO_AUTH_DATA_REQD
                                               0: ACB_PARTIAL_SECRETS_ACCOUNT
                                               0: ACB_USE_AES_KEYS
                                        sub_auth_status          : 0x00000000 (0)
                                        last_successful_logon    : NTTIME(0)
                                        last_failed_logon        : NTTIME(0)
                                        failed_logon_count       : 0x00000000 (0)
                                        reserved                 : 0x00000000 (0)
                                    sidcount                 : 0x00000001 (1)
                                    sids                     : *
                                        sids: ARRAY(1)
                                            sids: struct netr_SidAttr
                                                sid                      : *
                                                    sid                      : S-1-18-1
                                                attributes               : 0x00000007 (7)
                                                       1: SE_GROUP_MANDATORY
                                                       1: SE_GROUP_ENABLED_BY_DEFAULT
                                                       1: SE_GROUP_ENABLED
                                                       0: SE_GROUP_OWNER
                                                       0: SE_GROUP_USE_FOR_DENY_ONLY
                                                       0: SE_GROUP_INTEGRITY
                                                       0: SE_GROUP_INTEGRITY_ENABLED
                                                       0: SE_GROUP_RESOURCE
                                                    0x00: SE_GROUP_LOGON_ID         (0)
                                resource_groups: struct PAC_DOMAIN_GROUP_MEMBERSHIP
                                    domain_sid               : NULL
                                    groups: struct samr_RidWithAttributeArray
                                        count                    : 0x00000000 (0)
                                        rids                     : NULL
                _pad                     : 0x00000000 (0)
            buffers: struct PAC_BUFFER
                type                     : PAC_TYPE_LOGON_NAME (10)
                _ndr_size                : 0x0000001a (26)
                info                     : *
                    info                     : union PAC_INFO(case 10)
                    logon_name: struct PAC_LOGON_NAME
                        logon_time               : Fri Mar  4 10:53:14 AM 2022 CET
                        size                     : 0x0010 (16)
                        account_name             : 'testovic'
                _pad                     : 0x00000000 (0)
            buffers: struct PAC_BUFFER
                type                     : PAC_TYPE_UPN_DNS_INFO (12)
                _ndr_size                : 0x00000088 (136)
                info                     : *
                    info                     : union PAC_INFO(case 12)
                    upn_dns_info: struct PAC_UPN_DNS_INFO
                        upn_name_size            : 0x0028 (40)
                        upn_name                 : *
                            upn_name                 : 'testovic@example.net'
                        dns_domain_name_size     : 0x0016 (22)
                        dns_domain_name          : *
                            dns_domain_name          : 'EXAMPLE.NET'
                        flags                    : 0x00000002 (2)
                               0: PAC_UPN_DNS_FLAG_CONSTRUCTED
                               1: PAC_UPN_DNS_FLAG_HAS_SAM_NAME_AND_SID
                        ex                       : union PAC_UPN_DNS_INFO_EX(case 2)
                        sam_name_and_sid: struct PAC_UPN_DNS_INFO_SAM_NAME_AND_SID
                            samaccountname_size      : 0x0010 (16)
                            samaccountname           : *
                                samaccountname           : 'testovic'
                            objectsid_size           : 0x001c (28)
                            objectsid                : *
                                objectsid                : S-1-5-21-186059982-468505587-3623024618-1104
                _pad                     : 0x00000000 (0)
            buffers: struct PAC_BUFFER
                type                     : PAC_TYPE_SRV_CHECKSUM (6)
                _ndr_size                : 0x00000010 (16)
                info                     : *
                    info                     : union PAC_INFO(case 6)
                    srv_cksum: struct PAC_SIGNATURE_DATA
                        type                     : 0x00000010 (16)
                        signature                : DATA_BLOB length=12
[0000] FC CE 05 91 FE 01 5D AC   89 84 C7 B1               ......]. ....
                _pad                     : 0x00000000 (0)
            buffers: struct PAC_BUFFER
                type                     : PAC_TYPE_KDC_CHECKSUM (7)
                _ndr_size                : 0x00000010 (16)
                info                     : *
                    info                     : union PAC_INFO(case 7)
                    kdc_cksum: struct PAC_SIGNATURE_DATA
                        type                     : 0x00000010 (16)
                        signature                : DATA_BLOB length=12
[0000] 13 C5 60 EE E7 2B 7B 89   8E AC 2D 7E               ..`..+{. ..-~
                _pad                     : 0x00000000 (0)
            buffers: struct PAC_BUFFER
                type                     : PAC_TYPE_TICKET_CHECKSUM (16)
                _ndr_size                : 0x00000010 (16)
                info                     : *
                    info                     : union PAC_INFO(case 16)
                    ticket_checksum: struct PAC_SIGNATURE_DATA
                        type                     : 0x00000010 (16)
                        signature                : DATA_BLOB length=12
[0000] 2C 63 A0 2C 44 FC 9A E8   4E 6B 3A 69               ,c.,D... Nk:i
                _pad                     : 0x00000000 (0)
dump OK
```

XXX: This seems to show additonal AD groups

The SID is the Windows security identifier, every AD user and group has one. It
has two parts, the domain SID and the RID. For example:

```
S-1-5-21-1231230493-411072730-1844936127-513
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ - is the domain part
                                         ^^^ - 513 is the RID
```

``` shell
$ ndrdump  --debug-stdout -d 10 krb5pac PAC_DATA struct /tmp/out.pac | \
  grep -m 1 -A 27 -P '^\s+groups: struct samr_RidWithAttributeArray$'
                                        groups: struct samr_RidWithAttributeArray
                                            count                    : 0x00000002 (2)
                                            rids                     : *
                                                rids: ARRAY(2)
                                                    rids: struct samr_RidWithAttribute
                                                        rid                      : 0x00000201 (513)
                                                        attributes               : 0x00000007 (7)
                                                               1: SE_GROUP_MANDATORY
                                                               1: SE_GROUP_ENABLED_BY_DEFAULT
                                                               1: SE_GROUP_ENABLED
                                                               0: SE_GROUP_OWNER
                                                               0: SE_GROUP_USE_FOR_DENY_ONLY
                                                               0: SE_GROUP_INTEGRITY
                                                               0: SE_GROUP_INTEGRITY_ENABLED
                                                               0: SE_GROUP_RESOURCE
                                                            0x00: SE_GROUP_LOGON_ID         (0)
                                                    rids: struct samr_RidWithAttribute
                                                        rid                      : 0x00000461 (1121)
                                                        attributes               : 0x00000007 (7)
                                                               1: SE_GROUP_MANDATORY
                                                               1: SE_GROUP_ENABLED_BY_DEFAULT
                                                               1: SE_GROUP_ENABLED
                                                               0: SE_GROUP_OWNER
                                                               0: SE_GROUP_USE_FOR_DENY_ONLY
                                                               0: SE_GROUP_INTEGRITY
                                                               0: SE_GROUP_INTEGRITY_ENABLED
                                                               0: SE_GROUP_RESOURCE
                                                            0x00: SE_GROUP_LOGON_ID         (0)
```

Another issue: Windows can't discover Samba server, see [https://wiki.archlinux.org/title/Samba#Windows_1709_or_up_does_not_discover_the_samba_server_in_Network_view](https://wiki.archlinux.org/title/Samba#Windows_10_1709_and_up_connectivity_problems_-_%22Windows_cannot_access%22_0x80004005)
  ``` shell
  $ systemctl is-active wsdd
  active
  $ testparm -sv 2>/dev/null | grep workgroup
        workgroup = WORKGROUP
  $ egrep -v '^ *(#|$)' /etc/sysconfig/wsdd
  WSDD_DOMAIN=""
  WSDD_WORKGROUP="WORKGROUP"
  WSDD_HOSTNAME=""
  WSDD_INTERFACES="wlan0"
  WSDD_ARGS="-4 -s -v"
  ```


## Samba usershares

It was via writing a "description" file to
`/var/lib/samba/usershares':

``` shell
$ ls -ld /var/lib/samba/usershares/
drwxrwx--T. 2 root sambashare 30 Apr 28 12:15 /var/lib/samba/usershares/
```

Hence, r/w for 'sambagroup' is needed.

``` shell
$ getent group sambashare
sambashare:x:990:jiri

$ net usershare add foobar /home/jiri/foobar "foobar"  nobody:R guest_ok=n

$ net usershare info foobar
[foobar]
path=/home/jiri/foobar
comment=foobar
usershare_acl=T14S\nobody:R,
guest_ok=n

$ cat /var/lib/samba/usershares/foobar
#VERSION 2
path=/home/jiri/foobar
comment=foobar
usershare_acl=S-1-5-21-477997971-2989031469-1205486838-501:R
guest_ok=n
sharename=foobar
```

And, again, usermapping must work. One could use 'Everyone:R' as ACL.
Since `guest_ok=n`, then a user must exists in Samba DB and must have
working mapping to a local user via `_Get_Pwnam()`; since I did not want
guests access, and since I did want to create a personalizes user access,
I used `username map` hack (which effectively means allowing access to
'nobody' if the password matches).


ACL is RFD (read, full, deny), see https://serverfault.com/a/474831/451558 .

``` shell
$ testparm -s 2>/dev/null | grep -P '^\s+username map'
        username map = /etc/samba/users.map

$ cat /etc/samba/users.map
nobody = friend
```

Reading `smb.conf(5)` says that for non-AD mode, this mapping is applied before
checking creds; thus, 'friend' is, in fact, user 'nobody' and hence her password
is 'nobody's' password.

``` shell
$ pdbedit -d 0 -L
nobody:65534:nobody

$ export PASSWD=<password>

# see 'friend' and 'nobody' are the same
$ smbclient -c 'ls; quit' //t14s/foo -U nobody | head -n2
  .                                   D        0  Fri Apr 26 06:34:09 2024
  ..                                  D        0  Fri Apr 26 06:34:09 2024
root@t14s:~# smbclient -c 'ls; quit' //t14s/foo -U friend | head -n2
  .                                   D        0  Fri Apr 26 06:34:09 2024
  ..                                  D        0  Fri Apr 26 06:34:09 2024

$ smbclient -c 'ls; quit' //t14s/foo -U nobody%"" | head -n2
session setup failed: NT_STATUS_LOGON_FAILURE

$ smbclient -c 'ls; quit' //t14s/foo -U friend"" | head -n2
session setup failed: NT_STATUS_LOGON_FAILURE
```

Yes, one just just say - use 'nobody' :-)


### Samba troubleshooting

