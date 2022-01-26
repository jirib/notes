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

### kerberos

#### client

``` shell
# one can use KRB5_CONFIG if editing /etc/krb5.conf is not wanted

$ echo $KRB5_CONFIG
/home/jiri/tmp/krb5.conf

$ cat $KRB5_CONFIG
[libdefaults]
        dns_canonicalize_hostname = false
        rdns = false
        default_realm = DOMAIN01.EXAMPLE.COM
        default_ccache_name = FILE:/home/jiri/tmp/krb5cc_%{uid}

[realms]
DOMAIN01.EXAMPLE.COM = {
          kdc = 192.168.122.200
          default_domain = domain01.example.com
          admin_server = 192.168.122.200
}

[domain_realm]
        .domain01.example.com = DOMAIN01.EXAMPLE.COM
```

``` shell
$ KRB5_TRACE=/dev/stdout kinit -V testovic@DOMAIN01.EXAMPLE.COM
Using default cache: /home/jiri/tmp/krb5cc_1000
Using principal: testovic@DOMAIN01.EXAMPLE.COM
[28873] 1639578371.989133: Getting initial credentials for testovic@DOMAIN01.EXAMPLE.COM
[28873] 1639578371.989134: Error loading plugin module pkinit: 2/unable to find plugin [/usr/lib64/krb5/plugins/preauth/pkinit.so]: No such file or directory
[28873] 1639578371.989135: Error loading plugin module spake: 2/unable to find plugin [/usr/lib64/krb5/plugins/preauth/spake.so]: No such file or directory
[28873] 1639578371.989137: Sending unauthenticated request
[28873] 1639578371.989138: Sending request (204 bytes) to DOMAIN01.EXAMPLE.COM
[28873] 1639578371.989139: Resolving hostname 192.168.122.200
[28873] 1639578371.989140: Sending initial UDP request to dgram 192.168.122.200:88
[28873] 1639578371.989141: Received answer (212 bytes) from dgram 192.168.122.200:88
[28873] 1639578371.989142: Sending DNS URI query for _kerberos.DOMAIN01.EXAMPLE.COM.
[28873] 1639578372.001285: No URI records found
[28873] 1639578372.001286: Sending DNS SRV query for _kerberos-master._udp.DOMAIN01.EXAMPLE.COM.
[28873] 1639578372.001287: Sending DNS SRV query for _kerberos-master._tcp.DOMAIN01.EXAMPLE.COM.
[28873] 1639578372.001288: No SRV records found
[28873] 1639578372.001289: Response was not from primary KDC
[28873] 1639578372.001290: Received error from KDC: -1765328359/Additional pre-authentication required
[28873] 1639578372.001293: Preauthenticating using KDC method data
[28873] 1639578372.001294: Processing preauth types: PA-PK-AS-REQ (16), PA-PK-AS-REP_OLD (15), PA-ETYPE-INFO2 (19), PA-ENC-TIMESTAMP (2)
[28873] 1639578372.001295: Selected etype info: etype aes256-cts, salt "DOMAIN01.EXAMPLE.COMtestovic", params ""
Password for testovic@DOMAIN01.EXAMPLE.COM: 
[28873] 1639578373.588128: AS key obtained for encrypted timestamp: aes256-cts/A5EF
[28873] 1639578373.588130: Encrypted timestamp (for 1639578372.716579): plain 301AA011180F32303231313231353134323631325AA10502030AEF23, encrypted C2E65EA174C5671956586E62E0D8852C64A3D089923E395EA36431E48BD0A379DF806EF09FA6F2E2543D7E139E22DCD6981258B8AAE4A168
[28873] 1639578373.588131: Preauth module encrypted_timestamp (2) (real) returned: 0/Success
[28873] 1639578373.588132: Produced preauth for next request: PA-ENC-TIMESTAMP (2)
[28873] 1639578373.588133: Sending request (284 bytes) to DOMAIN01.EXAMPLE.COM
[28873] 1639578373.588134: Resolving hostname 192.168.122.200
[28873] 1639578373.588135: Sending initial UDP request to dgram 192.168.122.200:88
[28873] 1639578373.588136: Received answer (112 bytes) from dgram 192.168.122.200:88
[28873] 1639578373.588137: Sending DNS URI query for _kerberos.DOMAIN01.EXAMPLE.COM.
[28873] 1639578373.588138: No URI records found
[28873] 1639578373.588139: Sending DNS SRV query for _kerberos-master._udp.DOMAIN01.EXAMPLE.COM.
[28873] 1639578373.588140: Sending DNS SRV query for _kerberos-master._tcp.DOMAIN01.EXAMPLE.COM.
[28873] 1639578373.588141: No SRV records found
[28873] 1639578373.588142: Response was not from primary KDC
[28873] 1639578373.588143: Received error from KDC: -1765328332/Response too big for UDP, retry with TCP
[28873] 1639578373.588144: Request or response is too big for UDP; retrying with TCP
[28873] 1639578373.588145: Sending request (284 bytes) to DOMAIN01.EXAMPLE.COM (tcp only)
[28873] 1639578373.588146: Resolving hostname 192.168.122.200
[28873] 1639578373.588147: Initiating TCP connection to stream 192.168.122.200:88
[28873] 1639578373.588148: Sending TCP request to stream 192.168.122.200:88
[28873] 1639578373.588149: Received answer (1603 bytes) from stream 192.168.122.200:88
[28873] 1639578373.588150: Terminating TCP connection to stream 192.168.122.200:88
[28873] 1639578373.588151: Sending DNS URI query for _kerberos.DOMAIN01.EXAMPLE.COM.
[28873] 1639578373.588152: No URI records found
[28873] 1639578373.588153: Sending DNS SRV query for _kerberos-master._tcp.DOMAIN01.EXAMPLE.COM.
[28873] 1639578373.588154: No SRV records found
[28873] 1639578373.588155: Response was not from primary KDC
[28873] 1639578373.588156: Processing preauth types: PA-ETYPE-INFO2 (19)
[28873] 1639578373.588157: Selected etype info: etype aes256-cts, salt "DOMAIN01.EXAMPLE.COMtestovic", params ""
[28873] 1639578373.588158: Produced preauth for next request: (empty)
[28873] 1639578373.588159: AS key determined by preauth: aes256-cts/A5EF
[28873] 1639578373.588160: Decrypted AS reply; session key is: aes256-cts/C121
[28873] 1639578373.588161: FAST negotiation: unavailable
[28873] 1639578373.588162: Initializing FILE:/home/jiri/tmp/krb5cc_1000 with default princ testovic@DOMAIN01.EXAMPLE.COM
[28873] 1639578373.588163: Storing testovic@DOMAIN01.EXAMPLE.COM -> krbtgt/DOMAIN01.EXAMPLE.COM@DOMAIN01.EXAMPLE.COM in FILE:/home/jiri/tmp/krb5cc_1000
[28873] 1639578373.588164: Storing config in FILE:/home/jiri/tmp/krb5cc_1000 for krbtgt/DOMAIN01.EXAMPLE.COM@DOMAIN01.EXAMPLE.COM: pa_type: 2
[28873] 1639578373.588165: Storing testovic@DOMAIN01.EXAMPLE.COM -> krb5_ccache_conf_data/pa_type/krbtgt\/DOMAIN01.EXAMPLE.COM\@DOMAIN01.EXAMPLE.COM@X-CACHECONF: in FILE:/home/jiri/tmp/krb5cc_1000
Authenticated to Kerberos v5

$ klist -5feaC
Ticket cache: FILE:/home/jiri/tmp/krb5cc_1000
Default principal: testovic@DOMAIN01.EXAMPLE.COM

Valid starting       Expires              Service principal
12/15/2021 15:26:12  12/16/2021 01:26:12  krbtgt/DOMAIN01.EXAMPLE.COM@DOMAIN01.EXAMPLE.COM
        renew until 12/16/2021 15:26:11, Flags: RIA
        Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96 
        Addresses: (none)
config: pa_type(krbtgt/DOMAIN01.EXAMPLE.COM@DOMAIN01.EXAMPLE.COM) = 2
        Addresses: (none)
```

#### server

When using kerberos with `sshd` on a machine conntected to AD/Samba/Winbind,
`yast samba-client` should take care of *ALMOST* all settings but there's a need
to *fix* `/etc/krb5.conf`; because a user uses *DOMAIN\username* when
authenticating to SSH daemon, but *kerberos* does not know anything about
*DOMAIN\\* part, thus there's need to strip it via `auth_to_local`.

```
# sshd

$ sshd -T | grep -Pi '^(gss|kerberos|password|chal|pam)'
kerberosauthentication no
kerberosorlocalpasswd yes
kerberosticketcleanup yes
gssapiauthentication yes
gssapikeyexchange no
gssapicleanupcredentials yes
gssapistrictacceptorcheck no
gssapistorecredentialsonrekey no
passwordauthentication no
challengeresponseauthentication yes

# modified krb5.conf, see comments inline

$ cat /etc/krb5.conf
[libdefaults]
        dns_canonicalize_hostname = false
        rdns = false
        default_realm = DOMAIN01.EXAMPLE.COM
        default_ccache_name = FILE:/tmp/krb5cc_%{uid}
        clockskew = 300

[realms]
        DOMAIN01.EXAMPLE.COM = {
                kdc = w2k19-ad-01.domain01.example.com
                default_domain = domain01.example.com
                admin_server = w2k19-ad-01.domain01.example.com

                # WARNING: auth_to_local must be manually added!
                # 
                auth_to_local = RULE:[1:DOMAIN01\$1]
                auth_to_local = DEFAULT
        }

[logging]
        kdc = FILE:/var/log/krb5/krb5kdc.log
        admin_server = FILE:/var/log/krb5/kadmind.log
        default = SYSLOG:NOTICE:DAEMON

[domain_realm]
        .domain01.example.com = DOMAIN01.EXAMPLE.COM

[appdefaults]
        pam = {
                ticket_lifetime = 1d
                renew_lifetime = 1d
                forwardable = true
                proxiable = false
                minimum_uid = 1
        }

# what does the manpage says?

$ man krb5.conf | col -b | \
  sed -n '/^ *auth_to_local *$/,/^ *auth_to_local_names/{/^ *auth_to_local_name/q;p}' | \
  fmt -w 80
       auth_to_local
              This tag allows you to set a general rule for mapping principal
              names to local user names.  It will be used if there is not
              an explicit mapping for the principal name that is being
              translated. The possible values are:

              RULE:exp
                     The local name will be formulated from exp.

                     The format for exp
                     is [n:string](regexp)s/pattern/replacement/g.
                     The integer n indicates how many components the
                     target principal should have.  If this matches,
                     then a string will be formed from string,  substi-
                     tuting  the  realm  of  the  principal for $0 and
                     the n'th component of the principal for $n (e.g.,
                     if the principal was johndoe/admin then [2:$2$1foo]
                     would result in the string adminjohndoefoo).  If this
                     string matches regexp, then the s//[g] substitution
                     command will be run over the string.  The optional g
                     will cause the substitution to be global over the string,
                     instead of replacing only the first match in the string.

              DEFAULT
                     The principal name will be used as the local user name.
                     If the principal has more than one component or is not
                     in the default realm, this rule is not applicable and
                     the conversion will fail.

              For example:

                 [realms]
                     ATHENA.MIT.EDU = {
                         auth_to_local = RULE:[2:$1](johndoe)s/^.*$/guest/
                         auth_to_local = RULE:[2:$1;$2](^.*;admin$)s/;admin$//
                         auth_to_local = RULE:[2:$2](^.*;root)s/^.*$/root/
                         auth_to_local = DEFAULT
                     }

              would result in any principal without root or admin as the
              second component to be translated with the default rule.
              A principal with a second component of admin will become its
              first component.  root will  be  used  as the local name for
              any principal with a second component of root.  The exception
              to these two rules are any principals johndoe/*, which will
              always get the local name guest.
```

##### troubleshooting

- `KRB5_TRACE=/dev/stdout` env var
- `No key table entry found matching host/s153sam01@`, consequence is the user
  cannot login.
  It seems related to not-having a FQDN in `hostnamectl --static`.
  1. `GSSAPIStrictAcceptorCheck = no` in `sshd_config`
  2. `ignore_acceptor_hostname = true` in `krb5.conf`
  3. correction of FQDN via `hostnamectl`
     ``` shell
     $ python3 -c 'import socket; print(socket.gethostname());'
     s153sam01
     $ hostnamectl set-hostname s153sam01.example.net
     $ python3 -c 'import socket; print(socket.gethostname());'
     s153sam01.example.net
     ```
  Details at https://web.mit.edu/kerberos/krb5-1.13/doc/admin/princ_dns.html .


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

- `sss_cache -E` invalidate all cached entries, with the exception of sudo rules
- `sss_cache -u <username>`, invalidate a specific user entries
- `systemctl stop sssd; rm -rf /var/lib/sss/db/*; systemctl restart sssd`

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
grub2-install -v <boot_device> # bios
grub2-install -v
```

#### grub2-mkconfig

`grub2-mkconfig` calls various helpers in the background, eg. `grub2-probe`.

``` shell
$ cryptsetup luksDump /dev/nvme0n1p2 | grep '^UUID:'
UUID:           67096f4a-842a-4b4f-b0b1-4338a120807c

$ pvs --noheading -o vg_uuid /dev/mapper/cr_nvme-SAMSUNG_MZALQ512HALU-000L1_S4YCNF0NC31508-part2 
  1ZCjy2-WL2Q-7fQH-l7OV-cLGE-f5x7-aS2Wvu

$ grub2-probe --device /dev/mapper/cr_nvme-SAMSUNG_MZALQ512HALU-000L1_S4YCNF0NC31508-part2 --target compatibility_hint
cryptouuid/67096f4a842a4b4fb0b14338a120807c
$ grub2-probe --device /dev/mapper/system-root --target compatibility_hint
lvmid/1ZCjy2-WL2Q-7fQH-l7OV-cLGE-f5x7-aS2Wvu/6giGUs-ljLS-fia6-mffa-khdn-BxrL-uIsmq6
$ grep -m1 -A1 'cryptomount' /boot/grub2/grub.cfg 
        cryptomount -u 67096f4a842a4b4fb0b14338a120807c
        set root='lvmid/1ZCjy2-WL2Q-7fQH-l7OV-cLGE-f5x7-aS2Wvu/6giGUs-ljLS-fia6-mffa-khdn-BxrL-uIsmq6'
```

#### pxe

``` shell
grub2-mknet -v --net-directory=/srv/tftpboot \
  --directory=/usr/share/grub2/<platform> \
  --subdir=grub2                             # installs into /srv/tftpboot/grub2
```

``` shell
timeout=60
default=0

menuentry local {
  insmod biosdisk
  set root=(hd0)
  chainloader +1
}

menuentry pxelinux {
  insmod pxechain
  pxechainloader (tftp)/pxelinux.0
```

#### serial console

for a bloody SOL (IPMI) which is *COM3* (ie. *ttyS2* - *0x3e8*)

``` shell
GRUB_TERMINAL="console serial"
GRUB_SERIAL_COMMAND="serial --port=0x3e8 --speed=115200"
# or via 'unit'
# GRUB_SERIAL_COMMAND="serial --unit=2 --speed=115200"
```

and run `grub2-mkconfig -o /boot/grub2/grub.cfg`.

#### shell commands

See [The list of command-line and menu entry commands
](https://www.gnu.org/software/grub/manual/grub/html_node/Command_002dline-and-menu-entry-commands.html#Command_002dline-and-menu-entry-commands).

``` shell
set # list all set variables
lsmod
insmod <module>
ls # list devices or files
echo $root
echo $prefix # generally ($root)/boot/grub2
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

- [GRUB Bootloader Enter Rescue
  Shell](https://www.suse.com/support/kb/doc/?id=000019654), there
  seem to be a limitation which causes GRUB2 fail if root VG's PVs are
  not between first 8 block devices of the system

### iPXE

#### dnsmasq

Not to end in a indefinite loop when loading iPXE (because iPXE
reloads itself), there's a need to distinuish between initial load of
iPXE from *legacy* PXE clients (inside network interface ROM) and from
iPXE itself. Official iPXE documentation states only a solution for
ISC DHCP, but here is how to achieve the same with `dnsmasq`:

``` shell
# sed -n '/^# Boot for iPXE/,/^ *$/{/^ *$/q; p}' /etc/dnsmasq.conf
# Boot for iPXE. The idea is to send two different
# filenames, the first loads iPXE, and the second tells iPXE what to
# load. The dhcp-match sets the ipxe tag for requests from iPXE.
#dhcp-boot=undionly.kpxe
#dhcp-match=set:ipxe,175 # iPXE sends a 175 option.
#dhcp-boot=tag:ipxe,http://boot.ipxe.org/demo/boot.php
```

A full example for libvirt network settings:

``` shell
<network xmlns:dnsmasq="http://libvirt.org/schemas/network/dnsmasq/1.0">
...
  <dnsmasq:options>
    <dnsmasq:option value="log-dhcp"/>
    <dnsmasq:option value="enable-tftp"/>
    <dnsmasq:option value="tftp-no-blocksize"/>
    <dnsmasq:option value="tftp-root=/srv/tftpboot"/>
    <dnsmasq:option value="dhcp-match=set:efi-x86_64,option:client-arch,7"/>
    <dnsmasq:option value="dhcp-match=set:i386-pc,option:client-arch,0"/>
    <dnsmasq:option value="dhcp-boot=tag:efi-x86_64,ipxe.efi"/>
    <dnsmasq:option value="dhcp-boot=tag:i386-pc,undionly.kpxe"/>
    <dnsmasq:option value="dhcp-match=set:ipxe,175"/>
    <dnsmasq:option value="dhcp-boot=tag:ipxe,tftp://192.168.122.1/menu.ipxe"/>
  </dnsmasq:options>
</network>
```

### pxelinux

when booting `pxelinux.0` from GRUB2 there's an issue with DHCP option
*210*, ie. there's an issue with *PathPrefix* when doing PXE, see
[Dynamic Host Configuration Protocol Options Used by PXELINUX
](https://datatracker.ietf.org/doc/html/rfc5071#section-1) for
explanation.

An example when booting *pxelinux* via *GRUB2*.

``` shell
net0: 52:54:00:f2:9a:2a using 82540em on 0000:00:03.0 (open)
  [Link:up, TX:0 TXE:0 RX:0 RXE:0]
Configuring (net0 52:54:00:f2:9a:2a)...... ok
net0: 192.168.122.57/255.255.255.0 gw 192.168.122.1
Next server: 192.168.122.1
Filename: i386-pc/core.0
tftp://192.168.122.1/i386-pc/core.0... ok
core.0 : 50538 bytes [PXE-NBP]
...
PXELINUX 3.86 2010-04-01  Copyright (C) 1994-2010 H. Peter Anvin et al
Found PXENV+ structure
PXE API version is 0201
!PXE entry point found (we hope) at 9C28:0160 via plan C
UNDI code segment at 9C28 len 0802ion...ok
UNDI data segment at 9CAC len 2D10
Getting cached packet 01 02 03
My IP address seems to be C0A87A39 192.168.122.57
ip=192.168.122.57:192.168.122.1:192.168.122.1:255.255.255.0
TFTP prefix: i386-pc/ource Network Boot Firmware -- http://ipxe.org
Trying to load: pxelinux.cfg/e4365a86-e13a-3944-a86a-ad09404793cdT
Trying to load: pxelinux.cfg/01-52-54-00-f2-9a-2a
Trying to load: pxelinux.cfg/C0A87A39 on 0000:00:03.0 (open)
Trying to load: pxelinux.cfg/C0A87A3
Trying to load: pxelinux.cfg/C0A87A)...... ok
Trying to load: pxelinux.cfg/C0A87 gw 192.168.122.1
Trying to load: pxelinux.cfg/C0A8
Trying to load: pxelinux.cfg/C0A
Trying to load: pxelinux.cfg/C0re.0... ok
Trying to load: pxelinux.cfg/C
Trying to load: pxelinux.cfg/default
Unable to locate configuration file

Boot failed: press a key to retry, or wait for reset...
```

See `TFTP prefix: i386-pc/` above!

To solve this issue you either can modify DHCP server (eg. [ISC
DHCPd](https://wiki.syslinux.org/wiki/index.php?title=PXELINUX#DHCP_Config_-_ISC_dhcpd_options))or
better modify `pxelinux.0` binary.

``` shell
# pwd
/tmp/syslinux-3.86/utils
# cp ../core/pxelinux.0{,orig}
# pxelinux-options --after path-prefix / ../core/pxelinux.0
# pxelinux-options --list ../core/pxelinux.0
-a path-prefix          '/'
```

And copy `pxelinux.0` to your TFTP directory.

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

- *promote* resource action - promotes a resource from a slave resource to a master one
- *demote* resource action - demotes a resource from a master resource to a slave one

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

corosync ports note, see also a general ports as defined in [RH
docs](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/high_availability_add-on_reference/s1-firewalls-haar#tb-portenable-HAAR)

``` shell
man corosync.conf | col -b | sed -n '/^ *mcastport/,/^ *$/{/^ *$/q; p}' | fmt -w72
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
$ crmadmin -N # show member nodes
member node: s153cl02 (1084783552)
member node: s153cl01 (1084783549)

$ crmadmin -D # show designated coordinator (DC)
Designated Controller is: s153cl01

$ crm_mon -1 # show cluster status
Cluster Summary:
  * Stack: corosync
  * Current DC: s153cl01 (version 2.0.5+20201202.ba59be712-4.13.1-2.0.5+20201202.ba59be712) - partition with quorum
  * Last updated: Tue Dec 21 17:08:34 2021
  * Last change:  Tue Dec 21 16:59:17 2021 by root via cibadmin on s153cl01
  * 2 nodes configured
  * 3 resource instances configured

              *** Resource management is DISABLED ***
  The cluster will not attempt to start, stop or recover services

Node List:
  * Online: [ s153cl01 s153cl02 ]

Active Resources:
  * Resource Group: g-Group1 (unmanaged):
    * p-vIP     (ocf::heartbeat:IPaddr2):        Started s153cl01 (unmanaged)
    * p-Dummy   (ocf::heartbeat:Dummy):  Started s153cl01 (unmanaged)

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
time=2021-09-05T20:
pattern='(SAPHana|sap|'
grep -P \
  "^${time}.* \w+ ${pattern:=(}corosync|attrd|crmd|cib|lrmd|pengine|stonith|controld|systemd)" \
  messages
```

``` shell
# pacemaker 2.x
time=2021-09-05T20:
pattern='(SAPHana|sap|'
grep -P \
  "^${time}.* \w+ ${pattern:=(}corosync|pacemaker-(attrd|based|controld|execd|schedulerd|fenced)|stonith|systemd)" \
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

### desktop files

To override *exec* like for an `.desktop` file.

``` shell
$ desktop-file-install --dir ~/.local/share/applications/ /usr/share/applications/remote-viewer.desktop
$ desktop-file-edit --set-key=Exec --set-value='myremote-viewer %u' ~/.local/share/applications/remote-viewer.desktop
```

and write your `myremote-viewer` wrapper (eg. to force some options).

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


#### cloning

cloning a huge repo could take ages because of its history, adding `--depth 1`
will copy only the latest revision of everything in the repository.

``` shell
$ git clone --depth 1 git@github.com:torvalds/linux.git
```

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

### json

A [playgroun](https://jqplay.org/) for `jq`.

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

#### dnsmasq as authoritative dns server

``` shell
$ grep -RHPv '^ *(#|$)' /etc/dnsmasq.{conf,d/*.conf} | \
  grep -Pv ':((enable-)?tftp|(log-)?dhcp)'
/etc/dnsmasq.conf:listen-address=192.168.122.1,192.168.123.1,192.168.124.1
/etc/dnsmasq.conf:except-interface=lo
/etc/dnsmasq.conf:bind-interfaces
/etc/dnsmasq.conf:domain-needed
/etc/dnsmasq.conf:bogus-priv
/etc/dnsmasq.conf:conf-dir=/etc/dnsmasq.d/,*.conf
/etc/dnsmasq.d/auth-dns.conf:auth-server=ns.example.com
/etc/dnsmasq.d/auth-dns.conf:host-record=ns.example.com,192.168.123.1
/etc/dnsmasq.d/auth-dns.conf:auth-soa=2021122203,jiri@example.com
/etc/dnsmasq.d/cl.example.com.conf:auth-zone=cl.example.com,192.168.123.0/24
/etc/dnsmasq.d/cl.example.com.conf:local=/cl.example.com/192.168.123.1
/etc/dnsmasq.d/cl.example.com.conf:host-record=s15301.cl.example.com,192.168.123.189
/etc/dnsmasq.d/cl.example.com.conf:host-record=s15302.cl.example.com,192.168.123.192
/etc/dnsmasq.d/example.net.conf:auth-zone=example.net,192.168.124.0/24
/etc/dnsmasq.d/example.net.conf:local=/example.net/192.168.124.1
/etc/dnsmasq.d/example.net.conf:host-record=w2k19.example.net,192.168.124.200
/etc/dnsmasq.d/trust-anchors.conf:trust-anchor=.,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
```

#### dnsmasq as dhcp server for multiple networks

``` shell
$ grep -RHPv '^ *(#|$)' /etc/dnsmasq.{conf,d/*.conf} | \
  grep -Pv ':(auth|local|host|(enable-)?tftp)'
/etc/dnsmasq.conf:listen-address=192.168.122.1,192.168.123.1,192.168.124.1
/etc/dnsmasq.conf:except-interface=lo
/etc/dnsmasq.conf:bind-interfaces
/etc/dnsmasq.conf:domain-needed
/etc/dnsmasq.conf:bogus-priv
/etc/dnsmasq.conf:log-dhcp
/etc/dnsmasq.conf:conf-dir=/etc/dnsmasq.d/,*.conf
/etc/dnsmasq.d/example.net.conf:dhcp-range=set:examplenet,192.168.124.10,192.168.124.199
/etc/dnsmasq.d/example.net.conf:dhcp-option=tag:examplenet,3,0.0.0.0
/etc/dnsmasq.d/example.net.conf:dhcp-option=tag:examplenet,6,0.0.0.0
/etc/dnsmasq.d/example.net.conf:dhcp-host=52:54:00:70:78:d5,192.168.124.200
/etc/dnsmasq.d/trust-anchors.conf:trust-anchor=.,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D

$ ip a s dev examplenet
34: examplenet: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 12:f2:2b:20:28:8f brd ff:ff:ff:ff:ff:ff
    inet 192.168.124.1/24 brd 192.168.124.255 scope global noprefixroute examplenet
       valid_lft forever preferred_lft forever
    inet6 fe80::692:abf4:ce1d:29fa/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever

```

#### dnsmasq as pxe/tftp

``` shell
$ grep -RHPv '^ *(#|$)' /etc/dnsmasq.{conf,d/*.conf} | \
  grep -P ':((enable-)?tftp|dhcp-(match|boot))'
/etc/dnsmasq.conf:enable-tftp
/etc/dnsmasq.conf:tftp-no-blocksize
/etc/dnsmasq.conf:tftp-root=/srv/tftpboot
/etc/dnsmasq.conf:dhcp-match=set:efi-x86_64,option:client-arch,7
/etc/dnsmasq.conf:dhcp-match=set:i386-pc,option:client-arch,0
/etc/dnsmasq.conf:dhcp-boot=tag:efi-x86_64,ipxe.efi
/etc/dnsmasq.conf:dhcp-boot=tag:i386-pc,undionly.kpxe
/etc/dnsmasq.conf:dhcp-match=set:ipxe,175
/etc/dnsmasq.conf:dhcp-boot=tag:ipxe,tftp://192.168.122.1/menu.ipxe
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

### SMB

#### CIFS (linux SMB) filesystem

``` shell
$ modinfo cifs| grep ^description | fmt -w80
description:    VFS to access SMB3 servers e.g. Samba, Macs, Azure and Windows
(and also older servers complying with the SNIA CIFS Specification)
```

When `mount.cifs` occurs there's need to map SIDs to UIDs and GIDs.

Since it is kernel what does mounting and filesystem management, it uses
kernel's key management facility (Linux key service) and finally there's a call
to userspace to get the data. This is done this via `request-key` callback which
consults `/etc/request-key.{d/*.conf,conf}`, that is it would ask `cifs.idmap`
utility depending on a plugin in `/etc/cifs-utils/idmap-plugin` (it is in fact a
symlink to a library) providing the data (usually via *winbind*), there's also a
plugin for
[SSSD](https://sssd.io/design-pages/integrate_sssd_with_cifs_client.html).

``` shell
$ls -l /etc/cifs-utils/idmap-plugin
lrwxrwxrwx 1 root root 35 Dec 27 16:11 /etc/cifs-utils/idmap-plugin -> /etc/alternatives/cifs-idmap-plugin

$ update-alternatives --display cifs-idmap-plugin
cifs-idmap-plugin - auto mode
  link best version is /usr/lib64/cifs-utils/idmapwb.so
  link currently points to /usr/lib64/cifs-utils/idmapwb.so
  link cifs-idmap-plugin is /etc/cifs-utils/idmap-plugin
/usr/lib64/cifs-utils/cifs_idmap_sss.so - priority 10
/usr/lib64/cifs-utils/idmapwb.so - priority 20

$ rpm -qf /usr/lib64/cifs-utils/cifs_idmap_sss.so
sssd-2.6.2-1.1.x86_6

# getcifsacl can be used to get SID->UID/GID mapping for objects on filesystem
$ rpm -ql cifs-utils | egrep 'bin/.+cifsacl'
/usr/bin/getcifsacl
/usr/bin/setcifsacl

```

``` shell
$ grep cifs.idma /proc/keys 
1b7de0ca I--Q---     1   6m 39010000     0     0 cifs.idma gs:S-1-22-2-0: 4
21191b10 I--Q---     1   6m 39010000     0     0 cifs.idma os:S-1-22-1-0: 4
365f605e I------     1 perm 1f030000     0     0 keyring   .cifs_idmap: 2

$ findmnt /mnt
TARGET SOURCE               FSTYPE OPTIONS
/mnt   //192.168.124.35/tmp cifs   rw,relatime,vers=3.1.1,cache=strict,username=testovic,domain=EXAMPLENET,uid=0,noforceuid,gid=0,noforcegid,addr=192.168.124.35,file_mode=0755,dir_mode=0755,soft,nounix,serverino,mapposix,cifsacl,rsize=4194304,wsize=4194304,bsize=1048576,echo_interval=60,actimeo=1

$ grep cifs.idma /proc/keys 
1b7de0ca I--Q---     1   5m 39010000     0     0 cifs.idma gs:S-1-22-2-0: 4
206e6ff3 I--Q---     1   9m 39010000     0     0 cifs.idma os:S-1-5-21-2185718108-4266305927-1067147705-1105: 4
211768c0 I--Q---     1   9m 39010000     0     0 cifs.idma gs:S-1-5-21-2185718108-4266305927-1067147705-513: 4
21191b10 I--Q---     1   5m 39010000     0     0 cifs.idma os:S-1-22-1-0: 4
365f605e I------     1 perm 1f030000     0     0 keyring   .cifs_idmap: 4

$ wbinfo -S S-1-5-21-2185718108-4266305927-1067147705-1105
11105
$ wbinfo -Y S-1-5-21-2185718108-4266305927-1067147705-513
10513
$ python3 -c 'import pwd; print(pwd.getpwuid(11105))'
pwd.struct_passwd(pw_name='EXAMPLENET\\testovic', pw_passwd='*', pw_uid=11105, pw_gid=10513, pw_gecos='', pw_dir='/home/testovic', pw_shell='/bin/bash')

$ python3 -c 'import grp; print(grp.getgrgid(10513))'
grp.struct_group(gr_name='EXAMPLENET\\domain users', gr_passwd='x', gr_gid=10513, gr_mem=[])

$ stat /mnt/fstab 
  File: /mnt/fstab
  Size: 1952            Blocks: 8          IO Block: 1048576 regular file
Device: 40h/64d Inode: 10985884002298803652  Links: 1
Access: (0744/-rwxr--r--)  Uid: (11105/EXAMPLENET\testovic)   Gid: (10513/EXAMPLENET\domain users)
Access: 2022-01-06 12:06:21.489089700 +0100
Modify: 2022-01-06 12:06:21.489089700 +0100
Change: 2022-01-06 12:06:21.489089700 +0100
 Birth: 2022-01-06 12:06:21.480949700 +0100
```


A way to get good troubleshooting info:

``` shell
_start=$(date +"%Y-%m-%d %H:%M:%S") # sets start time variable

echo 'module cifs +p' > /sys/kernel/debug/dynamic_debug/control
echo 'file fs/cifs/*.c +p' > /sys/kernel/debug/dynamic_debug/control
echo 1 > /proc/fs/cifs/cifsFYI
```

...then do an operation which tries to reproduce an issue, get the log and
disable debugging.

``` shell
journalctl --since "${_start}"

# turn off debugging
unset _start
echo 0 > /proc/fs/cifs/cifsFYI
echo 'file fs/cifs/*.c -p' > /sys/kernel/debug/dynamic_debug/control
echo 'module cifs -p' > /sys/kernel/debug/dynamic_debug/control
```
#### samba

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

For logging, see [Configuring Logging on a Samba
Server](https://wiki.samba.org/index.php/Configuring_Logging_on_a_Samba_Server).

##### ad member

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

###### identity mapping

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




##### issues

- [https://wiki.archlinux.org/title/Samba#Windows_1709_or_up_does_not_discover_the_samba_server_in_Network_view](https://wiki.archlinux.org/title/Samba#Windows_10_1709_and_up_connectivity_problems_-_%22Windows_cannot_access%22_0x80004005)
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



#### shares

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

#### troubleshooting

a good way to troubleshoot is via `smbclient`

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
  Some details at [Howto/Inspecting the PAC](https://www.freeipa.org/page/Howto/Inspecting_the_PAC).
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


### nfs

What NFS protocol version are support?

``` shell
# cat /proc/fs/nfsd/versions
-2 +3 +4 +4.1 +4.2
```

#### nfsv4

- *NFSv4* does NOT require `rpcbind`, no longer requirement of separate
  TCP callback connection (ie. server does not need to contact the
  client directly by itself); mounting and locking protocols are part
  of NFSv4
- in-kernel *nfsd* listening on 2049/{tcp,udp}
- **BUT** although nfsv4 does not require `rpcbind`, it requires
  internally communicating with `rpc.mountd`, see [How to run
  NFS4-only Server without rpcbind on SLES 12 or
  15](https://www.suse.com/support/kb/doc/?id=000019530) for details!.

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

for every < 4.0 nfs client `rpc.mountd` on nfs server keeps a record
in `/var/lib/nfs/rmtab`

``` shell
grep -RH '' /var/lib/nfs/rmtab
/var/lib/nfs/rmtab:10.0.0.2:/tmp:0x00000001
```

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

##### nfs server

A description of `/proc/net/rpc/nfsd` could be found at [nfsd stats
explained :
/proc/net/rpc/nfsd](https://web.archive.org/web/20210409075630/https://www.svennd.be/nfsd-stats-explained-procnetrpcnfsd/).

``` shell
grep -RH '^address: ' /proc/fs/nfsd/clients/*/info # list clients
cat /var/lib/nfs/rpc_pipefs/nfsd4_cb/clnt*/info    # more brief info

grep -RH '' /proc/fs/nfsd/ 2>/dev/null
```

##### nfs client

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

### ipmi

#### ipmitool

``` shell
lsmod | grep ipmi
ls -l /dev/ipmi0
modprobe ipmi_devintf

# static ip
ipmitool lan set 1 ipsrc static
ipmitool lan set 1 netmask 255.255.255.0
ipmitool lan set 1 arp respond on
ipmitool lan print 1

# dhcp ip
ipmitool lan set 1 ipsrc dhcp
ipmitool lan set 1 arp respond on
ipmitool mc reset cold
```

## kerberos

- *'$'* in principal name indicates machine account

``` shell
KRB5_TRACE=/dev/stdout kinit <args> # to get debug from any gssapi/krb library
                                    # calls
```

## kernel

### configuration

- `/proc/config.gz`

### crash

Kernel panic means a kernel crash which is controlled with following settings:

``` shell
kernel.sysrq = 184
kernel.hardlockup_panic = 1
kernel.hung_task_panic = 0
kernel.panic = 0
kernel.panic_on_io_nmi = 0
kernel.panic_on_oops = 1
kernel.panic_on_rcu_stall = 0
kernel.panic_on_unrecovered_nmi = 0
kernel.panic_on_warn = 0
kernel.softlockup_panic = 0
kernel.unknown_nmi_panic = 0
```

- *kernel.panic*: if there is a kernel panic the kernel will loop
  forever (no automatic reboot)
- *kernel.panic_on_oops'* kernel panics when an oops or BUG is
  encountered, thus it panics immediately on these kernel issues
- *kernel.hardlockup_panic*: kernel panics when a hard lockup is detected

But kernel can be crash also while sending a magic sysrq key, see
[sysrq
key](https://www.kernel.org/doc/html/latest/admin-guide/sysrq.html) in
Linux.

``` shell
kernel.sysrq = 184
```

*184* means  128+32+16+8 (that is: allow reboot/poweroff (128) plus
enable remount read-only (32) plus enable sync command (16) plus
enable debugging dumps of processes etc. (8), see above link for details.

## fadump

*fadump* (Firmware Assisted Dump) is a robus crash dump mechanism using Power
Systems unique firmware features; when the OS crashes or when invoked manually
via 'Dump' restart LPAR option from the HMC, Power firmware on POWER6 and newer
is informed about the crash, takes care of preserving the memory image at the
time of failure and reboot follows the normal booting process (non-kexec); the
boot loader loads the default kernel and initramfs. Like kdump, fadump also
exports the memory dump in ELF format. This enables the reuse of existing kdump
infrastructure for dump capture and filtering.

Details at [Firmware assisted dump support on PowerLinux
systems](https://web.archive.org/web/20211224222833/http://webcache.googleusercontent.com/search?q=cache%3Ay7qPCtzP6iYJ%3Ahttps%3A%2F%2Fwww.ibm.com%2Fsupport%2Fpages%2Ffirmware-assisted-dump-support-powerlinux-systems&lr=lang_cs%257Clang_sk%257Clang_ru&hl=cs&gl=cz&tbs=lr%3Alang_1cs%257Clang_1sk%257Clang_1ru&strip=1&vwsrc=0)
and [firmware-assisted-dump.txt](https://lwn.net/Articles/488132/).

### kdump

To have a kernel panic is useless if there would be no way to get
crashed kernel dump, system's/kernel's memory, for analysis. `kdump`
is a tool which with help of various functionalities in kernel allow
to obtain the dump.

To have
[kdump](https://www.kernel.org/doc/html/latest/admin-guide/kdump/kdump.html)
fully working following kernel configuration should be in place.

``` shell
$ rpm2cpio kernel-default-4.12.14-122.91.2.x86_64.rpm' 2>/dev/null | \
  cpio --to-stdout -i ./boot/config-4.12.14-122.91-default 2>/dev/null | \
  grep -E -e '^CONFIG_MAGIC_SYSRQ=' \
    -e '^CONFIG_(KEXEC|CRASH_DUMP|DEBUG_INFO|PROC_VMCORE|RELOCATABLE)='
CONFIG_KEXEC=y
CONFIG_CRASH_DUMP=y
CONFIG_RELOCATABLE=y
CONFIG_PROC_VMCORE=y
CONFIG_DEBUG_INFO=y
CONFIG_MAGIC_SYSRQ=y
```

When a system crash occurs, triggers `panic()`, `die()`, `die_nmi()`
and in the *sysrq* handler (ALT-SysRq-c) would via *kexec* load a
*capture* kernel (an additional kernel residing in a reserved memory
range that is inaccessible to the first kernel), this bypasses BIOS
and preserves the contets of the first kernel's memory that would
otherwise be lost.

``` shell
$ grep crashkernel proc.txt  | xargs -n 1
BOOT_IMAGE=/vmlinuz-4.12.14-122.91-default
root=/dev/mapper/rootvg-root_lv
resume=/dev/sdb1
splash=silent
quiet
showopts
crashkernel=175M,high
crashkernel=72M,low
```

The above *crashkernel* values define:

- *high* means memory reservation for all available memory
- *low* means memory reservation in the DMA32 zone, ie. for 32bit only devices

See [crashkernel
syntax](https://www.kernel.org/doc/html/latest/admin-guide/kdump/kdump.html#crashkernel-syntax)
or [Calculating crashkernel allocation
size](https://documentation.suse.com/sles/15-SP3/single-html/SLES-tuning/#sec-tuning-kexec-crashkernel).

The *crashkernel* loads its initramfs where kdump would inspect memory
image through `/proc/vmcore`. This exports the dump as an ELF-format
file.

Based on `kdump` configuration

``` shell
$ /usr/sbin/kdumptool dump_config
KDUMP_KERNELVER=
KDUMP_CPUS=1
KDUMP_COMMANDLINE=
KDUMP_COMMANDLINE_APPEND=
KEXEC_OPTIONS=
MAKEDUMPFILE_OPTIONS=
KDUMP_IMMEDIATE_REBOOT=yes
KDUMP_TRANSFER=
KDUMP_SAVEDIR=file:///var/crash
KDUMP_KEEP_OLD_DUMPS=5
KDUMP_FREE_DISK_SIZE=64
KDUMP_VERBOSE=3
KDUMP_DUMPLEVEL=0
KDUMP_DUMPFORMAT=compressed
KDUMP_CONTINUE_ON_ERROR=yes
KDUMP_REQUIRED_PROGRAMS=
KDUMP_PRESCRIPT=
KDUMP_POSTSCRIPT=
KDUMP_COPY_KERNEL=yes
KDUMPTOOL_FLAGS=
KDUMP_NETCONFIG=auto
KDUMP_NET_TIMEOUT=30
KDUMP_SMTP_SERVER=
KDUMP_SMTP_USER=
KDUMP_SMTP_PASSWORD=
KDUMP_NOTIFICATION_TO=
KDUMP_NOTIFICATION_CC=
KDUMP_HOST_KEY=
KDUMP_SSH_IDENTITY=
```

`kdump` would save first kernel's memory for later analysis. Here
`kdump` would auto-detect right kernel version, find right initrd, use
*KDUMP_DUMPLEVEL* to know if to strip pages that may not be necessary
for analysis, ... and finally *KDUMP_SAVEDIR* as destination for the
dump. See `man 5 kdump` for details.

### modules

kernel modules are usually loaded by `udev` based *uevent*, see [udev](#udev).

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

## mail

### imap

#### mbsync / migrating mail from imap server to another

```
$ cat > ~/.mbsyncrc-migration <<EOF
IMAPAccount original
Host original.example.com
User foo@original.example.com
Pass <password>
SSLType IMAPS
SSLVersions TLSv1.2
CertificateFile /etc/ssl/ca-bundle.pem

IMAPAccount new
Host new.example.com
User foo@new.example.com
Pass <password>
SSLType IMAPS
SSLVersions TLSv1.2
CertificateFile /etc/ssl/ca-bundle.pem

IMAPStore original
Account original

IMAPStore new
Account new

Channel mirror
Far :original:
Near :new:
Patterns *
Sync Pull # to sync to new
Create Near # create missing mailboxes on new
EOF
```

`mbsync -V mirror`.

### neomutt / mutt

Limiting messages in index (list of mails), for full list of patterns see
https://neomutt.org/guide/advancedusage#3-1-%C2%A0pattern-modifier .

"simulating" a thread view via
[message-id](https://web.archive.org/web/20211216172803/https://www.hostknox.com/tutorials/email/headers)
and reference ids; basically every mail has message-id and references refer to
related ids of a thread.

```
l: ~i HE1P191MB002657DBE4B2A65657D7FFD6E9550@HE1P191MB0026.EURP191.PROD.OUTLOOK.COM | ~x HE1P191MB002657DBE4B2A65657D7FFD6E9550@HE1P191MB0026.EURP191.PROD.OUTLOOK.COM
```

### notmuch

``` shell
$ whatis notmuch
notmuch (1)          - thread-based email index, search, and tagging
```
Basically `notmuch` creates a virtual view on your mails, based on tagging,
while keeping the mail messages as they are on the filesystem. A `notmuch`
frontend like `neomutt` can thus view this *view* as a virtual mailbox, which
could simulate Gmail-like experience (ie. seeing your sent replies next to the
original mail etc...).

``` shell
$ notmuch search folder:/example\.com/
thread:0000000000000158 21 mins. ago [1/1(2)] info@example.com; test (sent example)
thread:0000000000000002  November 15 [1/1] info@example.com; my cool subject
thread:0000000000000003  November 15 [1/1] Jiri B; test (inbox example)
thread:0000000000000001  November 15 [1/1] cPanel on example.com; [example.com] Client configuration settings for “info@example.com”. (attachment inbox example)

$ notmuch search --output files folder:/example\.com/
/home/jiri/.mail/example.com/Inbox/cur/1639677793.23980_1.t14s,U=2:2,S
/home/jiri/.mail/example.com/Sent/cur/1639677742.R15663579783284099041.t14s,U=2:2,S
/home/jiri/.mail/example.com/Sent/cur/1639235128.31076_2.t14s,U=1:2,S
/home/jiri/.mail/example.com/Trash/cur/1639235129.31076_3.t14s,U=1:2,S
/home/jiri/.mail/example.com/Inbox/cur/1639235126.31076_1.t14s,U=1:2,S
```

`notmuch` could have hooks

``` shell
$ cat $(notmuch config get database.hook_dir)/pre-new
#!/bin/bash

mbsync -Va

$ cat $(notmuch config get database.hook_dir)/post-new
#!/bin/bash

# retag all "new" messages "inbox" and "unread"
notmuch tag +inbox +unread -new -- tag:new

# tag all messages in 'Sent' folder as send
notmuch tag -new -inbox +sent -- path:/Sent/

# projects
notmuch tag +example.com path:/example.com/
notmuch tag +example.org path:/example.org/
```


## networking

### bonding

#### theory

#### ARP monitoring

:FIXME:

Slave devices *MII Status* is not showing the "real MII" status, but
it does print an internal flag representing the internal state of the
device inside the bond.

*going down* means *BOND_LINK_FAIL*, *down* means
*BOND_LINK_DOWN*... See
[`bond_main.c`](https://elixir.bootlin.com/linux/v5.3.18/source/drivers/net/bonding/bond_main.c#L399).

If a non-active slave does not see ARP traffic which it supposed to
see (if `arp_validate=all`)

``` shell
$ curl -s 'https://www.kernel.org/doc/Documentation/networking/bonding.txt' | \
  sed -rn '/^[[:blank:]]+For an active slave/,/^[[:blank:]]*$/p'
        For an active slave, the validation checks ARP replies to confirm
        that they were generated by an arp_ip_target.  Since backup slaves
        do not typically receive these replies, the validation performed
        for backup slaves is on the broadcast ARP request sent out via the
        active slave.  It is possible that some switch or network
        configurations may result in situations wherein the backup slaves
        do not receive the ARP requests; in such a situation, validation
        of backup slaves must be disabled.
```

Then next step in troubleshooting should be to check with
`tshark`/`tcpdump` if backup slave sees relevant ARP traffic.  Or
configure `arp_validation=active`.

#### setup

##### iproute2 way

``` shell
$ ethtool -P eth0
Permanent address: 8c:8c:aa:d7:0c:33
$ ethtool -P eth2
Permanent address: 48:2a:e3:9a:78:85

$ ip link add bond0 type bond miimon 100 mode active-backup
$ ip link set eth0 master bond0

[277801.073581] Generic FE-GE Realtek PHY r8169-0-200:00: attached PHY driver (mii_bus:phy_addr=r8169-0-200:00, irq=MAC)
[277801.201647] r8169 0000:02:00.0 eth0: Link is Down
[277801.202203] bond0: (slave eth0): Enslaving as a backup interface with a down link
[277803.991225] r8169 0000:02:00.0 eth0: Link is Up - 1Gbps/Full - flow control off

$ ip link set eth2 master bond0

[277844.295426] bond0: (slave eth2): Enslaving as a backup interface with a down link
[277844.314935] r8152 5-1.1:1.0 eth2: carrier on

$ ip link show bond0
22: bond0: <BROADCAST,MULTICAST,MASTER> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether 6e:b9:1a:80:5b:ea brd ff:ff:ff:ff:ff:ff

$ ip link set bond0

[278012.113499] bond0: (slave eth0): link status definitely up, 1000 Mbps full duplex
[278012.113554] bond0: (slave eth0): making interface the new active one
[278012.113795] bond0: active interface up!
[278012.251127] bond0: (slave eth2): link status definitely up, 1000 Mbps full duplex

$ ip -s -d link show bond0
24: bond0: <BROADCAST,MULTICAST,MASTER,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 6e:b9:1a:80:5b:ea brd ff:ff:ff:ff:ff:ff promiscuity 0 minmtu 68 maxmtu 65535
    bond mode active-backup active_slave eth0 miimon 100 updelay 0 downdelay 0 peer_notify_delay 0 use_carrier 1 arp_interval 0 arp_validate none arp_all_targets any primary_reselect always fail_over_mac none xmit_hash_policy layer2 resend_igmp 1 num_grat_arp 1 all_slaves_active 0 min_links 0 lp_interval 1 packets_per_slave 1 lacp_rate slow ad_select stable tlb_dynamic_lb 1 addrgenmode eui64 numtxqueues 16 numrxqueues 16 gso_max_size 16354 gso_max_segs 64
    RX:  bytes packets errors dropped  missed   mcast
         20036      71      0       0       0       7
    TX:  bytes packets errors dropped carrier collsns
          6634      32      0       0       0       0

$ grep -RH '' /sys/class/net/bond0/bonding/{active_slave,miimon,mode,use_carrier,mii_status,slaves}
/sys/class/net/bond0/bonding/active_slave:eth0
/sys/class/net/bond0/bonding/miimon:100
/sys/class/net/bond0/bonding/mode:active-backup 1
/sys/class/net/bond0/bonding/use_carrier:1
/sys/class/net/bond0/bonding/mii_status:up
/sys/class/net/bond0/bonding/slaves:eth0 eth2

# setting port down on the switch

[278452.479531] r8169 0000:02:00.0 eth0: Link is Down
[278452.561728] bond0: (slave eth0): link status definitely down, disabling slave
[278452.561743] bond0: (slave eth2): making interface the new active one

# tshark -i any -n -f "arp" -O arp
...
Capturing on 'any'
Frame 1: 44 bytes on wire (352 bits), 44 bytes captured (352 bits) on interface any, id 0
Linux cooked capture v1
Address Resolution Protocol (ARP Announcement)
    Hardware type: Ethernet (1)
    Protocol type: IPv4 (0x0800)
    Hardware size: 6
    Protocol size: 4
    Opcode: request (1)
    [Is gratuitous: True]
    [Is announcement: True]
    Sender MAC address: 6e:b9:1a:80:5b:ea
    Sender IP address: 192.168.1.199
    Target MAC address: 00:00:00:00:00:00
    Target IP address: 192.168.1.199

Frame 2: 44 bytes on wire (352 bits), 44 bytes captured (352 bits) on interface any, id 0
Linux cooked capture v1
Address Resolution Protocol (ARP Announcement)
    Hardware type: Ethernet (1)
    Protocol type: IPv4 (0x0800)
    Hardware size: 6
    Protocol size: 4
    Opcode: request (1)
    [Is gratuitous: True]
    [Is announcement: True]
    Sender MAC address: 6e:b9:1a:80:5b:ea
    Sender IP address: 192.168.1.199
    Target MAC address: 00:00:00:00:00:00
    Target IP address: 192.168.1.199
...

# switch dynamic (mac) address table is updated and points 6e:b9:1a:80:5b:ea
# to new active iface/port

$ ip -s -d link show bond0
24: bond0: <BROADCAST,MULTICAST,MASTER,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 6e:b9:1a:80:5b:ea brd ff:ff:ff:ff:ff:ff promiscuity 0 minmtu 68 maxmtu 65535
    bond mode active-backup active_slave eth2 miimon 100 updelay 0 downdelay 0 peer_notify_delay 0 use_carrier 1 arp_interval 0 arp_validate none arp_all_targets any primary_reselect always fail_over_mac none xmit_hash_policy layer2 resend_igmp 1 num_grat_arp 1 all_slaves_active 0 min_links 0 lp_interval 1 packets_per_slave 1 lacp_rate slow ad_select stable tlb_dynamic_lb 1 addrgenmode eui64 numtxqueues 16 numrxqueues 16 gso_max_size 16354 gso_max_segs 64
    RX:  bytes packets errors dropped  missed   mcast
       1011042    1319      0       0       0      14
    TX:  bytes packets errors dropped carrier collsns
        141339    1115      0       0       0       0
```

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

#### troubleshooting

We can fake an issue of a network card with removing it from devices in *sysfs*.

``` shell
$ find /sys -name *eth0
/sys/devices/pci0000:00/0000:00:15.0/0000:03:00.0/net/eth0
/sys/devices/virtual/net/bond0/lower_eth0
/sys/class/net/eth0

$ echo 1 > /sys/devices/pci000:00/000:00:15.0/remove

# to rediscover

$ echo 1 > /sys/bus/pci/rescan
```
### capturing network trace

#### getting only part of pcap file

Sometimes *pcap* files could be huge, so one would need to get only part of the trace.

[`trigcap`](https://github.com/M0Rf30/xplico/tree/master/system/trigcap)
seems handy tool to get parts of pcap file.

``` shell
$ trigcap -o 710868.pcap -f 1637473815_DRPLHNPRDB02.pcap -t 710868 -b 0 -a 0
trigcap v1.1.0
Part of Xplico Internet Traffic Decoder (NFAT).
See http://www.xplico.org for more information.

Copyright 2007-2011 Gianluca Costa & Andrea de Franceschi and contributors.
This is free software; see the source for copying conditions. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

Trigger packet: 710868
Total packet: 0
Start packet: 710868
Stop packet: 710868

$ tshark -r 710868.pcap -Y 'lacp.version' -n -O lacp
Frame 1: 126 bytes on wire (1008 bits), 126 bytes captured (1008 bits)
Linux cooked capture v1
Slow Protocols
Link Aggregation Control Protocol
    LACP Version: 0x01
    TLV Type: Actor Information (0x01)
    TLV Length: 0x14
    Actor System Priority: 65535
    Actor System ID: 00:90:fa:eb:88:be
    Actor Key: 15
    Actor Port Priority: 255
    Actor Port: 1
    Actor State: 0x4d, LACP Activity, Aggregation, Synchronization, Defaulted
        .... ...1 = LACP Activity: Active
        .... ..0. = LACP Timeout: Long Timeout
        .... .1.. = Aggregation: Aggregatable
        .... 1... = Synchronization: In Sync
        ...0 .... = Collecting: Disabled
        ..0. .... = Distributing: Disabled
        .1.. .... = Defaulted: Yes
        0... .... = Expired: No
    [Actor State Flags: *F**SG*A]
    Reserved: 000000
    TLV Type: Partner Information (0x02)
    TLV Length: 0x14
    Partner System Priority: 65535
    Partner System: 00:00:00:00:00:00
    Partner Key: 1
    Partner Port Priority: 255
    Partner Port: 1
    Partner State: 0x01, LACP Activity
        .... ...1 = LACP Activity: Active
        .... ..0. = LACP Timeout: Long Timeout
        .... .0.. = Aggregation: Individual
        .... 0... = Synchronization: Out of Sync
        ...0 .... = Collecting: Disabled
        ..0. .... = Distributing: Disabled
        .0.. .... = Defaulted: No
        0... .... = Expired: No
    [Partner State Flags: *******A]
    Reserved: 000000
    TLV Type: Collector Information (0x03)
    TLV Length: 0x10
    Collector Max Delay: 0
    Reserved: 000000000000000000000000
    TLV Type: Terminator (0x00)
    TLV Length: 0x00
    Pad: 000000000000000000000000000000000000000000000000000000000000000000000000…
```

#### modifying network trace

one way to modify a network trace is to use
[`tcprewrite`](https://tcpreplay.appneta.com/wiki/tcprewrite#randomizing-ip-addresses).

``` shell
tshark -r /tmp/out.pcap
    1   0.000000     10.0.0.1 → 10.0.0.2     SSH 102 Client: Encrypted packet (len=36)
    2   0.000865     10.0.0.2 → 10.0.0.1     SSH 102 Server: Encrypted packet (len=36)
    3   0.000932     10.0.0.1 → 10.0.0.2     TCP 66 32968 → 22 [ACK] Seq=37 Ack=37 Win=501 Len=0 TSval=3160104543 TSecr=796686743
    4   0.103967     10.0.0.1 → 10.0.0.2     SSH 102 Client: Encrypted packet (len=36)
    5   0.104995     10.0.0.2 → 10.0.0.1     SSH 102 Server: Encrypted packet (len=36)
    6   0.105063     10.0.0.1 → 10.0.0.2     TCP 66 32968 → 22 [ACK] Seq=73 Ack=73 Win=501 Len=0 TSval=3160104647 TSecr=796686847
    7   0.264235     10.0.0.1 → 10.0.0.2     SSH 102 Client: Encrypted packet (len=36)
    8   0.265317     10.0.0.2 → 10.0.0.1     SSH 102 Server: Encrypted packet (len=36)
    9   0.265431     10.0.0.1 → 10.0.0.2     TCP 66 32968 → 22 [ACK] Seq=109 Ack=109 Win=501 Len=0 TSval=3160104808 TSecr=796687007
   10   0.268828     10.0.0.2 → 10.0.0.1     SSH 374 Server: Encrypted packet (len=308)
   11   0.268910     10.0.0.1 → 10.0.0.2     TCP 66 32968 → 22 [ACK] Seq=109 Ack=417 Win=501 Len=0 TSval=3160104811 TSecr=796687011
   12   0.269223     10.0.0.2 → 10.0.0.1     SSH 126 Server: Encrypted packet (len=60)
   13   0.269268     10.0.0.1 → 10.0.0.2     TCP 66 32968 → 22 [ACK] Seq=109 Ack=477 Win=501 Len=0 TSval=3160104812 TSecr=796687011

tcprewrite --seed=423 --infile=/tmp/out.pcap --outfile=/tmp/out-new.pcap
tshark -r /tmp/out-new.pcap
    1   0.000000 58.69.105.23 → 58.69.105.18 SSH 102 Client: Encrypted packet (len=36)
    2   0.000865 58.69.105.18 → 58.69.105.23 SSH 102 Server: Encrypted packet (len=36)
    3   0.000932 58.69.105.23 → 58.69.105.18 TCP 66 32968 → 22 [ACK] Seq=37 Ack=37 Win=501 Len=0 TSval=3160104543 TSecr=796686743
    4   0.103967 58.69.105.23 → 58.69.105.18 SSH 102 Client: Encrypted packet (len=36)
    5   0.104995 58.69.105.18 → 58.69.105.23 SSH 102 Server: Encrypted packet (len=36)
    6   0.105063 58.69.105.23 → 58.69.105.18 TCP 66 32968 → 22 [ACK] Seq=73 Ack=73 Win=501 Len=0 TSval=3160104647 TSecr=796686847
    7   0.264235 58.69.105.23 → 58.69.105.18 SSH 102 Client: Encrypted packet (len=36)
    8   0.265317 58.69.105.18 → 58.69.105.23 SSH 102 Server: Encrypted packet (len=36)
    9   0.265431 58.69.105.23 → 58.69.105.18 TCP 66 32968 → 22 [ACK] Seq=109 Ack=109 Win=501 Len=0 TSval=3160104808 TSecr=796687007
   10   0.268828 58.69.105.18 → 58.69.105.23 SSH 374 Server: Encrypted packet (len=308)
   11   0.268910 58.69.105.23 → 58.69.105.18 TCP 66 32968 → 22 [ACK] Seq=109 Ack=417 Win=501 Len=0 TSval=3160104811 TSecr=796687011
   12   0.269223 58.69.105.18 → 58.69.105.23 SSH 126 Server: Encrypted packet (len=60)
   13   0.269268 58.69.105.23 → 58.69.105.18 TCP 66 32968 → 22 [ACK] Seq=109 Ack=477 Win=501 Len=0 TSval=3160104812 TSecr=796687011
```

#### tcpdump

See [A tcpdump tutorial with
examples...](https://web.archive.org/web/20210826070406/https://danielmiessler.com/study/tcpdump/)
for some cool examples.

#### tshark / wireshark

##### lacp

LLDP can be used to get announcements from a switch about 802.3ad, see below part from LLDP part obtained with `tshark`:

``` shell
    Ieee 802.3 - Link Aggregation
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1001 = TLV Length: 9
        Organization Unique Code: 00:12:0f (Ieee 802.3)
        IEEE 802.3 Subtype: Link Aggregation (0x03)
            [Expert Info (Warning/Protocol): TLV has been deprecated]
                [TLV has been deprecated]
                [Severity level: Warning]
                [Group: Protocol]
        Aggregation Status: 0x03
            .... ...1 = Aggregation Capability: Yes
            .... ..1. = Aggregation Status: Enabled
        Aggregated Port Id: 1007
```

Which seems to correspond to:

``` shell
$ sed -n '/^802\.3ad/,/^ *$/p' /proc/net/bonding/bond0
802.3ad info
LACP rate: slow
Min links: 0
Aggregator selection policy (ad_select): stable
System priority: 65535
System MAC address: 90:e2:ba:04:28:c0
Active Aggregator Info:
        Aggregator ID: 1
        Number of ports: 1
        Actor Key: 9
        Partner Key: 1007
        Partner Mac Address: 64:d8:14:5e:57:f9

$ for i in eth1 eth3 ; do \
  echo $i ; \
  sed -n '/Slave Interface: '"$i"'$/,/^ *$/p' /proc/net/bonding/bond0 | \
  sed -n '/^details partner lacp pdu:/,$p'; done
eth1
details partner lacp pdu:
    system priority: 1
    system mac address: 64:d8:14:5e:57:f9
    oper key: 1007
    port priority: 1
    port number: 58
    port state: 61

eth3
details partner lacp pdu:
    system priority: 1
    system mac address: 64:d8:14:5e:57:f9
    oper key: 1007
    port priority: 1
    port number: 57
    port state: 61
```

Thus we see '1007' in LLDP (*Aggregated Port Id*) and '1007' in both
*Partner Key* and *oper key* in each slave block.

LACP allows negotiation between peers of bundling of links, see
[LACP](https://en.wikipedia.org/wiki/Link_aggregation#Link_Aggregation_Control_Protocol). That
means that LACP packets are sent to multicast group MAC address
01:80:C2:00:00:02.

``` shell
$ tshark -i eth1 -c 5 -t ad -n -f 'ether proto 0x8809' -Y 'lacp.version'
Running as user "root" and group "root". This could be dangerous.
Capturing on 'eth1'
    1 2021-11-23 16:04:13.620451556 64:d8:14:5e:58:03 → 01:80:c2:00:00:02 LACP 124 v1 ACTOR 64:d8:14:5e:57:f9 P: 58 K: 1007 *F***G*A PARTNER 00:00:00:00:00:00 P: 0 K: 0 *F**SG**
    2 2021-11-23 16:04:13.855216497 90:e2:ba:04:28:c0 → 01:80:c2:00:00:02 LACP 124 v1 ACTOR 90:e2:ba:04:28:c0 P: 1 K: 9 ****SG*A PARTNER 64:d8:14:5e:57:f9 P: 58 K: 1007 *F***G*A
    3 2021-11-23 16:04:16.039213579 90:e2:ba:04:28:c0 → 01:80:c2:00:00:02 LACP 124 v1 ACTOR 90:e2:ba:04:28:c0 P: 1 K: 9 ****SG*A PARTNER 64:d8:14:5e:57:f9 P: 58 K: 1007 *F***G*A
    4 2021-11-23 16:04:43.620073586 64:d8:14:5e:58:03 → 01:80:c2:00:00:02 LACP 124 v1 ACTOR 64:d8:14:5e:57:f9 P: 58 K: 1007 *****G*A PARTNER 90:e2:ba:04:28:c0 P: 1 K: 9 ****SG*A
    5 2021-11-23 16:04:47.239214048 90:e2:ba:04:28:c0 → 01:80:c2:00:00:02 LACP 124 v1 ACTOR 90:e2:ba:04:28:c0 P: 1 K: 9 ****SG*A PARTNER 64:d8:14:5e:57:f9 P: 58 K: 1007 *****G*A
5 packets captured
```

- *64:d8:14:5e:58:03* seems to correspond to switch LACP packets (they use same prefix)
  ``` shell
  $ grep -i 'Partner Mac Address' /proc/net/bonding/bond0
        Partner Mac Address: 64:d8:14:5e:57:f9
  ```
- *90:e2:ba:04:28:c0* corresponds to bonding device MAC address
  ``` shell
  $ ip link show bond0
  15: bond0: <BROADCAST,MULTICAST,MASTER,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 90:e2:ba:04:28:c0 brd ff:ff:ff:ff:ff:ff
  $  grep 'System MAC address:' /proc/net/bonding/bond0
  System MAC address: 90:e2:ba:04:28:c0
  ```

LACP from the server:

``` shell
$ tshark -i eth1 -c 1 -t ad -n -f 'ether proto 0x8809 and ether src 90:e2:ba:04:28:c0' -Y 'lacp.version' -O lacp
Running as user "root" and group "root". This could be dangerous.
Capturing on 'eth1'
Frame 1: 124 bytes on wire (992 bits), 124 bytes captured (992 bits) on interface eth1, id 0
Ethernet II, Src: 90:e2:ba:04:28:c0, Dst: 01:80:c2:00:00:02
Slow Protocols
Link Aggregation Control Protocol
    LACP Version: 0x01
    TLV Type: Actor Information (0x01)
    TLV Length: 0x14
    Actor System Priority: 65535
    Actor System ID: 90:e2:ba:04:28:c0
    Actor Key: 9
    Actor Port Priority: 255
    Actor Port: 1
    Actor State: 0x3d, LACP Activity, Aggregation, Synchronization, Collecting, Distributing
        .... ...1 = LACP Activity: Active
        .... ..0. = LACP Timeout: Long Timeout
        .... .1.. = Aggregation: Aggregatable
        .... 1... = Synchronization: In Sync
        ...1 .... = Collecting: Enabled
        ..1. .... = Distributing: Enabled
        .0.. .... = Defaulted: No
        0... .... = Expired: No
    [Actor State Flags: **DCSG*A]
    Reserved: 000000
    TLV Type: Partner Information (0x02)
    TLV Length: 0x14
    Partner System Priority: 1
    Partner System: 64:d8:14:5e:57:f9
    Partner Key: 1007
    Partner Port Priority: 1
    Partner Port: 58
    Partner State: 0x3d, LACP Activity, Aggregation, Synchronization, Collecting, Distributing
        .... ...1 = LACP Activity: Active
        .... ..0. = LACP Timeout: Long Timeout
        .... .1.. = Aggregation: Aggregatable
        .... 1... = Synchronization: In Sync
        ...1 .... = Collecting: Enabled
        ..1. .... = Distributing: Enabled
        .0.. .... = Defaulted: No
        0... .... = Expired: No
    [Partner State Flags: **DCSG*A]
    Reserved: 000000
    TLV Type: Collector Information (0x03)
    TLV Length: 0x10
    Collector Max Delay: 0
    Reserved: 000000000000000000000000
    TLV Type: Terminator (0x00)
    TLV Length: 0x00
    Pad: 000000000000000000000000000000000000000000000000000000000000000000000000…

1 packet captured
```

LACP from the switch (capturing LACP with *64:d8:14* MAC addr prefix):

``` shell

$ tshark -i eth1 -c 1 -t ad -n -f 'ether proto 0x8809 and ((ether[0:4] & 0xffffff00 = 0x64d81400) or (ether[6:4] & 0xffffff00 = 0x64d81400))' -Y 'lacp.version' -O lacp
Running as user "root" and group "root". This could be dangerous.
Capturing on 'eth1'
Frame 1: 124 bytes on wire (992 bits), 124 bytes captured (992 bits) on interface eth1, id 0
Ethernet II, Src: 64:d8:14:5e:58:03, Dst: 01:80:c2:00:00:02
Slow Protocols
Link Aggregation Control Protocol
    LACP Version: 0x01
    TLV Type: Actor Information (0x01)
    TLV Length: 0x14
    Actor System Priority: 1
    Actor System ID: 64:d8:14:5e:57:f9
    Actor Key: 1007
    Actor Port Priority: 1
    Actor Port: 58
    Actor State: 0x3d, LACP Activity, Aggregation, Synchronization, Collecting, Distributing
        .... ...1 = LACP Activity: Active
        .... ..0. = LACP Timeout: Long Timeout
        .... .1.. = Aggregation: Aggregatable
        .... 1... = Synchronization: In Sync
        ...1 .... = Collecting: Enabled
        ..1. .... = Distributing: Enabled
        .0.. .... = Defaulted: No
        0... .... = Expired: No
    [Actor State Flags: **DCSG*A]
    Reserved: 000000
    TLV Type: Partner Information (0x02)
    TLV Length: 0x14
    Partner System Priority: 65535
    Partner System: 90:e2:ba:04:28:c0
    Partner Key: 9
    Partner Port Priority: 255
    Partner Port: 1
    Partner State: 0x3d, LACP Activity, Aggregation, Synchronization, Collecting, Distributing
        .... ...1 = LACP Activity: Active
        .... ..0. = LACP Timeout: Long Timeout
        .... .1.. = Aggregation: Aggregatable
        .... 1... = Synchronization: In Sync
        ...1 .... = Collecting: Enabled
        ..1. .... = Distributing: Enabled
        .0.. .... = Defaulted: No
        0... .... = Expired: No
    [Partner State Flags: **DCSG*A]
    Reserved: 000000
    TLV Type: Collector Information (0x03)
    TLV Length: 0x10
    Collector Max Delay: 0
    Reserved: 000000000000000000000000
    TLV Type: Terminator (0x00)
    TLV Length: 0x00
    Pad: 000000000000000000000000000000000000000000000000000000000000000000000000…

1 packet captured
```

##### lldp / cdp

Depending on what is enabled for LLDP, you can see something like:

``` shell
$ tshark -i eth1 -c 1 -n -f "ether proto 0x88cc" -Y lldp -O lldp
Running as user "root" and group "root". This could be dangerous.
Capturing on 'eth1'
Frame 1: 164 bytes on wire (1312 bits), 164 bytes captured (1312 bits) on interface eth1, id 0
Ethernet II, Src: 64:d8:14:5e:58:03, Dst: 01:80:c2:00:00:0e
Link Layer Discovery Protocol
    Chassis Subtype = MAC address, Id: 64:d8:14:5e:57:f9
        0000 001. .... .... = TLV Type: Chassis Id (1)
        .... ...0 0000 0111 = TLV Length: 7
        Chassis Id Subtype: MAC address (4)
        Chassis Id: 64:d8:14:5e:57:f9
    Port Subtype = Interface name, Id: gi10
        0000 010. .... .... = TLV Type: Port Id (2)
        .... ...0 0000 0101 = TLV Length: 5
        Port Id Subtype: Interface name (5)
        Port Id: gi10
    Time To Live = 120 sec
        0000 011. .... .... = TLV Type: Time to Live (3)
        .... ...0 0000 0010 = TLV Length: 2
        Seconds: 120
    Ieee 802.3 - MAC/PHY Configuration/Status
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1001 = TLV Length: 9
        Organization Unique Code: 00:12:0f (Ieee 802.3)
        IEEE 802.3 Subtype: MAC/PHY Configuration/Status (0x01)
        Auto-Negotiation Support/Status: 0x03
            .... ...1 = Auto-Negotiation: Supported
            .... ..1. = Auto-Negotiation: Enabled
        PMD Auto-Negotiation Advertised Capability: 0x2401
            .... .... .... ...1 = 1000BASE-T (full duplex mode): Capable
            .... .... .... ..0. = 1000BASE-T (half duplex mode): Not capable
            .... .... .... .0.. = 1000BASE-X (-LX, -SX, -CX full duplex mode): Not capable
            .... .... .... 0... = 1000BASE-X (-LX, -SX, -CX half duplex mode): Not capable
            .... .... ...0 .... = Asymmetric and Symmetric PAUSE (for full-duplex links): Not capable
            .... .... ..0. .... = Symmetric PAUSE (for full-duplex links): Not capable
            .... .... .0.. .... = Asymmetric PAUSE (for full-duplex links): Not capable
            .... .... 0... .... = PAUSE (for full-duplex links): Not capable
            .... ...0 .... .... = 100BASE-T2 (full duplex mode): Not capable
            .... ..0. .... .... = 100BASE-T2 (half duplex mode): Not capable
            .... .1.. .... .... = 100BASE-TX (full duplex mode): Capable
            .... 0... .... .... = 100BASE-TX (half duplex mode): Not capable
            ...0 .... .... .... = 100BASE-T4: Not capable
            ..1. .... .... .... = 10BASE-T (full duplex mode): Capable
            .0.. .... .... .... = 10BASE-T (half duplex mode): Not capable
            0... .... .... .... = Other or unknown: Not capable
        Same in inverse (wrong) bitorder
            0... .... .... .... = 1000BASE-T (full duplex mode): Not capable
            .0.. .... .... .... = 1000BASE-T (half duplex mode): Not capable
            ..1. .... .... .... = 1000BASE-X (-LX, -SX, -CX full duplex mode): Capable
            ...0 .... .... .... = 1000BASE-X (-LX, -SX, -CX half duplex mode): Not capable
            .... 0... .... .... = Asymmetric and Symmetric PAUSE (for full-duplex links): Not capable
            .... .1.. .... .... = Symmetric PAUSE (for full-duplex links): Capable
            .... ..0. .... .... = Asymmetric PAUSE (for full-duplex links): Not capable
            .... ...0 .... .... = PAUSE (for full-duplex links): Not capable
            .... .... 0... .... = 100BASE-T2 (full duplex mode): Not capable
            .... .... .0.. .... = 100BASE-T2 (half duplex mode): Not capable
            .... .... ..0. .... = 100BASE-TX (full duplex mode): Not capable
            .... .... ...0 .... = 100BASE-TX (half duplex mode): Not capable
            .... .... .... 0... = 100BASE-T4: Not capable
            .... .... .... .0.. = 10BASE-T (full duplex mode): Not capable
            .... .... .... ..0. = 10BASE-T (half duplex mode): Not capable
            .... .... .... ...1 = Other or unknown: Capable
        Operational MAU Type: 1000BaseTFD - Four-pair Category 5 UTP, full duplex mode (0x001e)
    Ieee 802.3 - Link Aggregation
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1001 = TLV Length: 9
        Organization Unique Code: 00:12:0f (Ieee 802.3)
        IEEE 802.3 Subtype: Link Aggregation (0x03)
            [Expert Info (Warning/Protocol): TLV has been deprecated]
                [TLV has been deprecated]
                [Severity level: Warning]
                [Group: Protocol]
        Aggregation Status: 0x03
            .... ...1 = Aggregation Capability: Yes
            .... ..1. = Aggregation Status: Enabled
        Aggregated Port Id: 1007
    Ieee 802.3 - Maximum Frame Size
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 0110 = TLV Length: 6
        Organization Unique Code: 00:12:0f (Ieee 802.3)
        IEEE 802.3 Subtype: Maximum Frame Size (0x04)
        Maximum Frame Size: 1522
    Port Description = gigabitethernet10
        0000 100. .... .... = TLV Type: Port Description (4)
        .... ...0 0001 0001 = TLV Length: 17
        Port Description: gigabitethernet10
    System Name = switch01
        0000 101. .... .... = TLV Type: System Name (5)
        .... ...0 0000 1000 = TLV Length: 8
        System Name: switch01
    System Description = SG300-20 20-Port Gigabit Managed Switch
        0000 110. .... .... = TLV Type: System Description (6)
        .... ...0 0010 0111 = TLV Length: 39
        System Description: SG300-20 20-Port Gigabit Managed Switch
    Capabilities
        0000 111. .... .... = TLV Type: System Capabilities (7)
        .... ...0 0000 0100 = TLV Length: 4
        Capabilities: 0x0004
            .... .... .... ...0 = Other: Not capable
            .... .... .... ..0. = Repeater: Not capable
            .... .... .... .1.. = Bridge: Capable
            .... .... .... 0... = WLAN access point: Not capable
            .... .... ...0 .... = Router: Not capable
            .... .... ..0. .... = Telephone: Not capable
            .... .... .0.. .... = DOCSIS cable device: Not capable
            .... .... 0... .... = Station only: Not capable
        Enabled Capabilities: 0x0004
            .... .... .... ...0 = Other: Not capable
            .... .... .... ..0. = Repeater: Not capable
            .... .... .... .1.. = Bridge: Capable
            .... .... .... 0... = WLAN access point: Not capable
            .... .... ...0 .... = Router: Not capable
            .... .... ..0. .... = Telephone: Not capable
            .... .... .0.. .... = DOCSIS cable device: Not capable
            .... .... 0... .... = Station only: Not capable
    Management Address
        0001 000. .... .... = TLV Type: Management Address (8)
        .... ...0 0000 1100 = TLV Length: 12
        Address String Length: 5
        Address Subtype: IPv4 (1)
        Management Address: 192.168.1.254
        Interface Subtype: ifIndex (2)
        Interface Number: 300000
        OID String Length: 0
    IEEE - Port VLAN ID
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 0110 = TLV Length: 6
        Organization Unique Code: 00:80:c2 (IEEE)
        IEEE 802.1 Subtype: Port VLAN ID (0x01)
        Port VLAN Identifier: 1 (0x0001)
    End of LLDPDU
        0000 000. .... .... = TLV Type: End of LLDPDU (0)
        .... ...0 0000 0000 = TLV Length: 0
```

### firewall

#### firewalld

``` shell
# would ping (icmp echoreq) work?

$ firewall-cmd --list-all | grep -P '^\s+(target|icmp)'
  target: default
  icmp-block-inversion: no
  icmp-blocks: 

$ nft list chain inet firewalld filter_IN_public | grep -i icmp
                meta l4proto { icmp, ipv6-icmp } accept

# how is that possible? 'default' target still allows some traffic

$ man firewall-cmd | sed -n '/--set-target=/,/2\./{/2\./q;p}' | fmt -w 80
       --permanent [--zone=zone] [--policy=policy] --set-target=zone
           Set the target.

           For zones target is one of: default, ACCEPT, DROP, REJECT

           For policies target is one of: CONTINUE, ACCEPT, DROP, REJECT

           default is similar to REJECT, but has special meaning in the
           following scenarios:

            1. ICMP explicitly allowed

               At the end of the zone's ruleset ICMP packets are explicitly
               allowed.
```

#### nftables

``` shell
# let's show how firewalld translates to nftables

$ firewall-cmd --list-all
public (active)
  target: default
  icmp-block-inversion: no
  interfaces: eth0
  sources: 
  services: dhcpv6-client ssh
  ports: 
  protocols: 
  forward: no
  masquerade: no
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules:

$ nft list tables
table inet firewalld
table ip firewalld
table ip6 firewalld

$ nft list table inet firewalld | grep 'chain .*IN_public_allow'
        chain filter_IN_public_allow {

$ nft list chain inet firewalld filter_IN_public_allow
table inet firewalld {
        chain filter_IN_public_allow {
                tcp dport 22 ct state { new, untracked } accept
                ip6 daddr fe80::/64 udp dport 546 ct state { new, untracked } accept
        }
}
```


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

### curl

Using `curl` to *SFTP* via *SOCKS5* proxy using ssh key:

``` shell
$ curl -v -n --socks5-hostname 127.0.0.1:1080 \
  -u root: sftp://192.168.122.1/root/TESTFILE 2>&1 | (head -n 11; echo ...; tail -n 7)
*   Trying 127.0.0.1...
* TCP_NODELAY set
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0* SOCKS5 communication to 192.168.122.1:22
* SOCKS5 request granted.
* Connected to 127.0.0.1 (127.0.0.1) port 1080 (#0)
* User: root
* Authentication using SSH public key file
* Authentication using SSH public key file
* Authentication using SSH public key file
...
* completed keyboard interactive authentication
* Authentication complete
{ [9 bytes data]
100     9  100     9    0     0     34      0 --:--:-- --:--:-- --:--:--    34
100     9  100     9    0     0     34      0 --:--:-- --:--:-- --:--:--    34
* Connection #0 to host 127.0.0.1 left intact
TESTFILE
```

Using `curl` to *SFTP* via *SOCKS5* proxy using interactive password
authentication:

``` shell
$ echo 'machine 192.168.122.1 login root password <password>' > ~/.netrc
$ chmod 600 ~/.netrc

$ curl -v -n --socks5-hostname 127.0.0.1:1080 \
  -u root: sftp://192.168.122.1/root/TESTFILE 2>&1 | (head -n 11; echo ...; tail -n 7)
*   Trying 127.0.0.1...
* TCP_NODELAY set
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0* SOCKS5 communication to 192.168.122.1:22
* SOCKS5 request granted.
* Connected to 127.0.0.1 (127.0.0.1) port 1080 (#0)
* User: root
* Authentication using SSH public key file
* Authentication using SSH public key file
* Authentication using SSH public key file
...
* completed keyboard interactive authentication
* Authentication complete
{ [9 bytes data]
100     9  100     9    0     0     34      0 --:--:-- --:--:-- --:--:--    34
100     9  100     9    0     0     34      0 --:--:-- --:--:-- --:--:--    34
* Connection #0 to host 127.0.0.1 left intact
TESTFILE
```

### net-tools

#### netstat

``` shell
$ netstat -i
Kernel Interface table
Iface             MTU    RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR Flg
eth0             1500        0      0      0 0             0      0      0      0 BMU
eth2             1500     9391      0      0 0          4100      0      0      0 BMRU
lo              65536   148688      0      0 0        148688      0      0      0 LRU
virbr0           1500        0      0      0 0             0      0      0      0 BMU
virbr1           1500        0      0      0 0             0      0      0      0 BMU
virbr2           1500        0      0      0 0             0      0      0      0 BMU
vpn0             1406    27893      0      0 0         24691      0      0      0 MOPRU
wlan0            1500  5482131      0      0 0       1911465      0      0      0 BMRU
```

> The MTU and Met fields show the current MTU and metric value for
> that interface. The RX and TX columns show how many packets have
> been received or transmitted error free (RX-OK/TX-OK), damaged
> (RX-ERR/TX-ERR), how many were dropped (RX-DRP/TX-DRP), and how many
> were lost because of an overrun (RX-OVR/TX-OVR).
> https://tldp.org/LDP/nag/node76.html

### traceroute

`traceroute` works via setting TTL (Time-To-Live/Hop-Limit for IPv6) for IPv4
package to a specific number. Each device on the path decreases this number,
when the number is 0 then the packet is returned.

``` shell
$ ip route show default 0.0.0.0/0
default via 192.168.1.1 dev wlan0 proto dhcp metric 600

$ traceroute 192.168.1.1

# here we can see traceroute set TTL to 1, thus it was returned

$ tshark -i wlan0 -n -c 1 -f "dst host 192.168.1.1 && udp && not port 53" -O ip
Running as user "root" and group "root". This could be dangerous.
Capturing on 'wlan0'
Frame 1: 74 bytes on wire (592 bits), 74 bytes captured (592 bits) on interface wlan0, id 0
Ethernet II, Src: 70:9c:d1:bd:4c:0a, Dst: 94:e3:ee:4b:ee:b5
Internet Protocol Version 4, Src: 192.168.1.5, Dst: 192.168.1.1
    0100 .... = Version: 4
    .... 0101 = Header Length: 20 bytes (5)
    Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
        0000 00.. = Differentiated Services Codepoint: Default (0)
        .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)
    Total Length: 60
    Identification: 0xf7f4 (63476)
    Flags: 0x00
        0... .... = Reserved bit: Not set
        .0.. .... = Don't fragment: Not set
        ..0. .... = More fragments: Not set
    Fragment Offset: 0
    Time to Live: 1
        [Expert Info (Note/Sequence): "Time To Live" only 1]
            ["Time To Live" only 1]
            [Severity level: Note]
            [Group: Sequence]
    Protocol: UDP (17)
    Header Checksum: 0x3e66 [validation disabled]
    [Header checksum status: Unverified]
    Source Address: 192.168.1.5
    Destination Address: 192.168.1.1
User Datagram Protocol, Src Port: 55664, Dst Port: 33434
Data (32 bytes)

1 packet captured
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

See [List of partition identifiers for PCs](https://www.win.tue.nl/~aeb/partitions/partition_types-1.html).

*GPT* - GRUB booting from GPT requires *BIOS boot partition* (ef02) on
BIOS systems or *EFI system partition* (ef00) on EFI systems.

``` shell
cat /sys/block/<dev>/queue/hw_sector_size
cat /sys/block/<dev>/{queue/{scheduler,add_random,rq_affinity},device/timeout} # some tunning values
```

querying disk/hardware details...

``` shell
# _path='/sys/devices/pci0000:00/0000:00:03.0/0000:08:00.1/host8/rport-8:0-22/target8:0:22/8:0:22:2/block/sdal'
# _path=$(echo ${_path} | sed 's,/,\\/,g;s,\.,\\.,g')
# sed -n '/^ *Class Device path = "'"${_path}"'"/,/^ *Class Device =/{/^ *Class Device =/q;p}' sysfs.txt  | egrep -v '^([[:upper:]]| *$)'
  Class Device path = "/sys/devices/pci0000:00/0000:00:03.0/0000:08:00.1/host8/rport-8:0-22/target8:0:22/8:0:22:2/block/sdal"
    alignment_offset    = "0"
    capability          = "50"
    dev                 = "66:80"
    discard_alignment   = "0"
    events_async        =
    events_poll_msecs   = "-1"
    events              =
    ext_range           = "256"
    hidden              = "0"
    inflight            = "       0        0"
    make-it-fail        = "0"
    range               = "16"
    removable           = "0"
    ro                  = "0"
    size                = "64424509440"
    stat                = "   26559        0 26916981    35056     9006        0 18283202  1467096        0    92208  1549904"
    uevent              = "MAJOR=66
    Device = "8:0:22:2"
    Device path = "/sys/devices/pci0000:00/0000:00:03.0/0000:08:00.1/host8/rport-8:0-22/target8:0:22/8:0:22:2"
      access_state        = "active/optimized"
      blacklist           =
      delete              = <store method only>
      device_blocked      = "0"
      device_busy         = "0"
      dh_state            = "alua"
      eh_timeout          = "10"
      evt_capacity_change_reported= "0"
      evt_inquiry_change_reported= "0"
      evt_lun_change_reported= "0"
      evt_media_change    = "0"
      evt_mode_parameter_change_reported= "0"
      evt_soft_threshold_reached= "0"
      inquiry             =
      iocounterbits       = "32"
      iodone_cnt          = "0x8b4e"
      ioerr_cnt           = "0x1"
      iorequest_cnt       = "0x8b4e"
      modalias            = "scsi:t-0x00"
      model               = "MSA 2050 SAN    "
      preferred_path      = "1"
      queue_depth         = "16"
      queue_ramp_up_period= "120000"
      queue_type          = "simple"
      rescan              = <store method only>
      rev                 = "V270"
      scsi_level          = "7"
      state               = "running"
      timeout             = "30"
      type                = "0"
      uevent              = "DEVTYPE=scsi_device
      vendor              = "HPE     "
      vpd_pg80            =
      vpd_pg83            =
      wwid                = "naa.600c0ff00050dfdcaffd435e01000000"
```

### bcache

[bcache](https://www.kernel.org/doc/html/latest/admin-guide/bcache.html)
allows you to cache on faster block devices for slower ones.

linux distros using udev use udev rules to probe and register bcache devices, ie. they check for devices with *ID_FS_TYPE=bcache*:

``` shell
# find /usr/lib/{dracut,udev} -type f | grep bcache
/usr/lib/dracut/modules.d/90bcache/module-setup.sh
/usr/lib/udev/rules.d/69-bcache.rules
/usr/lib/udev/bcache-export-cached
/usr/lib/udev/bcache-register
/usr/lib/udev/probe-bcache

# udevadm info -q property /dev/loop0 | grep ^ID_FS_TYPE= # test loop0 device
ID_FS_TYPE=bcache
```

### fc / fibre channel

- *WWPN*, *World Wide Port Name*, assignement to a port in a Fibre Channel
  fabric (network), a kind of like a MAC address in Ethernet.
  ``` shell
  # grep -H '' /sys/class/scsi_host/host*/device/fc_host/host*/port_name
  /sys/class/scsi_host/host12/device/fc_host/host12/port_name:0x21000024ff7d6a17
  /sys/class/scsi_host/host1/device/fc_host/host1/port_name:0x21000024ff7d6a16

  # systool -c fc_host -A port_name
  Class = "fc_host"

    Class Device = "host1"
      port_name           = "0x21000024ff7d6a16"

      Device = "host1"


    Class Device = "host12"
      port_name           = "0x21000024ff7d6a17"

      Device = "host12"
  ```

:construction: under construction!

``` shell
# lspci | grep Fibre
82:00.0 Fibre Channel: QLogic Corp. ISP2532-based 8Gb Fibre Channel to PCI Express HBA (rev 02)
82:00.1 Fibre Channel: QLogic Corp. ISP2532-based 8Gb Fibre Channel to PCI Express HBA (rev 02)
```

- *fc_host* directory content refers to HBAs, ie. in this case to both QLE2562 HBAs
- *fc_remote_ports* directory content refers to remote storage controller ports
- *fc_transport* directory ... ??

``` shell
# ls -1 /sys/class/fc_{host,remote_ports,transport}
/sys/class/fc_host:
host1
host12

/sys/class/fc_remote_ports:
rport-1:0-2
rport-1:0-20
rport-1:0-27
rport-1:0-28
rport-1:0-3
rport-1:0-30
rport-1:0-31
rport-1:0-38
rport-1:0-4
rport-1:0-46
rport-1:0-47
rport-1:0-5
rport-1:0-60
rport-1:0-61
rport-1:0-63
rport-1:0-64
rport-1:0-65

/sys/class/fc_transport:
target1:0:0
target1:0:3
```

`fc_host` directory

``` shell
# ls -l /sys/class/fc_host/
total 0
lrwxrwxrwx 1 root root 0 Sep  2 10:48 host1 -> ../../devices/pci0000:80/0000:80:03.0/0000:82:00.0/host1/fc_host/host1
lrwxrwxrwx 1 root root 0 Sep  2 10:48 host12 -> ../../devices/pci0000:80/0000:80:03.0/0000:82:00.1/host12/fc_host/host12

# lspci | egrep '82:00.[01]'
82:00.0 Fibre Channel: QLogic Corp. ISP2532-based 8Gb Fibre Channel to PCI Express HBA (rev 02)
82:00.1 Fibre Channel: QLogic Corp. ISP2532-based 8Gb Fibre Channel to PCI Express HBA (rev 02)

# lspci -v -s 82:00.0 | grep -i Kernel
        Kernel driver in use: qla2xxx
        Kernel modules: qla2xxx
```

`fc_remote_ports` directory

``` shell
# ls -l /sys/class/fc_remote_ports/ | grep -Po ' \K(rport-.*)'
rport-1:0-2 -> ../../devices/pci0000:80/0000:80:03.0/0000:82:00.0/host1/rport-1:0-2/fc_remote_ports/rport-1:0-2
rport-1:0-20 -> ../../devices/pci0000:80/0000:80:03.0/0000:82:00.0/host1/rport-1:0-20/fc_remote_ports/rport-1:0-20
rport-1:0-27 -> ../../devices/pci0000:80/0000:80:03.0/0000:82:00.0/host1/rport-1:0-27/fc_remote_ports/rport-1:0-27
rport-1:0-28 -> ../../devices/pci0000:80/0000:80:03.0/0000:82:00.0/host1/rport-1:0-28/fc_remote_ports/rport-1:0-28
rport-1:0-3 -> ../../devices/pci0000:80/0000:80:03.0/0000:82:00.0/host1/rport-1:0-3/fc_remote_ports/rport-1:0-3
rport-1:0-30 -> ../../devices/pci0000:80/0000:80:03.0/0000:82:00.0/host1/rport-1:0-30/fc_remote_ports/rport-1:0-30
rport-1:0-31 -> ../../devices/pci0000:80/0000:80:03.0/0000:82:00.0/host1/rport-1:0-31/fc_remote_ports/rport-1:0-31
rport-1:0-38 -> ../../devices/pci0000:80/0000:80:03.0/0000:82:00.0/host1/rport-1:0-38/fc_remote_ports/rport-1:0-38
rport-1:0-4 -> ../../devices/pci0000:80/0000:80:03.0/0000:82:00.0/host1/rport-1:0-4/fc_remote_ports/rport-1:0-4
rport-1:0-46 -> ../../devices/pci0000:80/0000:80:03.0/0000:82:00.0/host1/rport-1:0-46/fc_remote_ports/rport-1:0-46
rport-1:0-47 -> ../../devices/pci0000:80/0000:80:03.0/0000:82:00.0/host1/rport-1:0-47/fc_remote_ports/rport-1:0-47
rport-1:0-5 -> ../../devices/pci0000:80/0000:80:03.0/0000:82:00.0/host1/rport-1:0-5/fc_remote_ports/rport-1:0-5
rport-1:0-60 -> ../../devices/pci0000:80/0000:80:03.0/0000:82:00.0/host1/rport-1:0-60/fc_remote_ports/rport-1:0-60
rport-1:0-61 -> ../../devices/pci0000:80/0000:80:03.0/0000:82:00.0/host1/rport-1:0-61/fc_remote_ports/rport-1:0-61
rport-1:0-63 -> ../../devices/pci0000:80/0000:80:03.0/0000:82:00.0/host1/rport-1:0-63/fc_remote_ports/rport-1:0-63
rport-1:0-64 -> ../../devices/pci0000:80/0000:80:03.0/0000:82:00.0/host1/rport-1:0-64/fc_remote_ports/rport-1:0-64

# cat /sys/class/fc_remote_ports/rport-1\:0-2/{port_{id,name,state},roles}
0xdd0800
0x220000d023049aaa
Online
FCP Target

# node_name - WWNN of the remote port (target port).
# port_name - WWPN of remote port.
# port_id - Destination ID of remote port.
# port_state - State of remote port.
# roles - Role of remote port (usually FCP target).
# scsi_target_id - Linux SCSI ID of remote port.
# supported_classes - Supported classes of service.

# grep -H '' /sys/class/fc_remote_ports/rport-1\:0-2/* 2>/dev/null
/sys/class/fc_remote_ports/rport-1:0-2/dev_loss_tmo:150
/sys/class/fc_remote_ports/rport-1:0-2/fast_io_fail_tmo:5
/sys/class/fc_remote_ports/rport-1:0-2/node_name:0x200000d023049aaa
/sys/class/fc_remote_ports/rport-1:0-2/port_id:0xdd0800
/sys/class/fc_remote_ports/rport-1:0-2/port_name:0x220000d023049aaa
/sys/class/fc_remote_ports/rport-1:0-2/port_state:Online
/sys/class/fc_remote_ports/rport-1:0-2/roles:FCP Target
/sys/class/fc_remote_ports/rport-1:0-2/scsi_target_id:0
/sys/class/fc_remote_ports/rport-1:0-2/supported_classes:Class 3
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

See [LIO Admin Manual](http://www.linux-iscsi.org/Doc/LIO%20Admin%20Manual.pdf).

usually there's a service restoring configuration for in-kernel LIO
target

``` shell
# SUSE
[[ -e /etc/sysconfig/target ]] && egrep -v '^(\s*[;#]| *$)' /etc/sysconfig/target

$ systemctl --no-pager show -p ExecStart -p EnvironmentFiles \
  -p Environment target
ExecStart={ path=/usr/bin/targetctl ; argv[]=/usr/bin/targetctl restore $CONFIG_FILE ; ignore_errors=no ; start_time=[n/1] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
Environment=CONFIG_FILE=/etc/target/saveconfig.json
EnvironmentFiles=/etc/sysconfig/target (ignore_errors=yes)
```

non-interactive way of `targetcli` management

``` shell
$ targetcli <path> <command> [<args>]
```

``` shell
# default configuration with no customization
$ grep -RH '' /sys/kernel/config/target/iscsi
/sys/kernel/config/target/iscsi/discovery_auth/enforce_discovery_auth:0
/sys/kernel/config/target/iscsi/discovery_auth/password_mutual:NULL
/sys/kernel/config/target/iscsi/discovery_auth/userid_mutual:NULL
/sys/kernel/config/target/iscsi/discovery_auth/authenticate_target:0
/sys/kernel/config/target/iscsi/discovery_auth/password:NULL
/sys/kernel/config/target/iscsi/discovery_auth/userid:NULL
/sys/kernel/config/target/iscsi/lio_version:Datera Inc. iSCSI Target v4.1.0

$ targetcli ls /
o- / ......................................................................................................................... [...]
  o- backstores .............................................................................................................. [...]
  | o- block .................................................................................................. [Storage Objects: 0]
  | o- fileio ................................................................................................. [Storage Objects: 0]
  | o- pscsi .................................................................................................. [Storage Objects: 0]
  | o- ramdisk ................................................................................................ [Storage Objects: 0]
  | o- rbd .................................................................................................... [Storage Objects: 0]
  o- iscsi ............................................................................................................ [Targets: 0]
  o- loopback ......................................................................................................... [Targets: 0]
  o- vhost ............................................................................................................ [Targets: 0]
  o- xen-pvscsi ....................................................................................................... [Targets: 0]
localhost:~ # targetcli ls /iscsi
o- iscsi .............................................................................................................. [Targets: 0]

$ targetcli /iscsi get discovery_auth
DISCOVERY_AUTH CONFIG GROUP
===========================
enable=False
------------
The enable discovery_auth parameter.

mutual_password=
----------------
The mutual_password discovery_auth parameter.

mutual_userid=
--------------
The mutual_userid discovery_auth parameter.

password=
---------
The password discovery_auth parameter.

userid=
-------
The userid discovery_auth parameter.
```

A quick setup:

``` shell
$ targetcli /backstores/fileio create test01 /iscsi/test01.raw 1G
Created fileio test01 with size 1073741824

$ targetcli /iscsi create
Created target iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.19d749eec97b.
Created TPG 1.

$ targetcli /iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.19d749eec97b/tpg1/portals create
Using default IP port 3260
Binding to INADDR_ANY (0.0.0.0)
Created network portal 0.0.0.0:3260.

$ targetcli /iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.19d749eec97b/tpg1/luns create /backstores/fileio/test01
Created LUN 0.

$ targetcli saveconfig
Last 10 configs saved in /etc/target/backup/.
Configuration saved to /etc/target/saveconfig.json

$ syspath=/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664\:sn.68237979a01d/tpgt_1/
$ for i in acls attrib auth; do
  grep -RH '' $syspath/$i | sort ; done
/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.68237979a01d/tpgt_1/attrib/authentication:0
/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.68237979a01d/tpgt_1/attrib/cache_dynamic_acls:0
/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.68237979a01d/tpgt_1/attrib/default_cmdsn_depth:64
/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.68237979a01d/tpgt_1/attrib/default_erl:0
/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.68237979a01d/tpgt_1/attrib/demo_mode_discovery:1
/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.68237979a01d/tpgt_1/attrib/demo_mode_write_protect:1
/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.68237979a01d/tpgt_1/attrib/fabric_prot_type:0
/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.68237979a01d/tpgt_1/attrib/generate_node_acls:0
/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.68237979a01d/tpgt_1/attrib/login_keys_workaround:1
/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.68237979a01d/tpgt_1/attrib/login_timeout:15
/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.68237979a01d/tpgt_1/attrib/netif_timeout:2
/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.68237979a01d/tpgt_1/attrib/prod_mode_write_protect:0
/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.68237979a01d/tpgt_1/attrib/t10_pi:0
/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.68237979a01d/tpgt_1/attrib/tpg_enabled_sendtargets:1
/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.68237979a01d/tpgt_1/auth/authenticate_target:0
/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.68237979a01d/tpgt_1/auth/password:
/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.68237979a01d/tpgt_1/auth/password_mutual:
/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.68237979a01d/tpgt_1/auth/userid:
/sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.localhost.x8664:sn.68237979a01d/tpgt_1/auth/userid_mutual:
```

##### acls / permissions

:construction: this part is under construction!!!

couple of things influence what an initiator can do/see:

- the `discovery_auth` paramenter in op-level iscsi configuration node
  (ie. `/iscsi`), if not empty requires authenticated initiators for
  discovery
- the `authentication` TPG paramenter, which defines *normal*
  authentication (*userid*, *password*, *mutual_userid*,
  *mutual_password*)
- the `generate_node_acls` attribute sets if *dynamic* ACLs are used,
  ie. they are created *on-fly* in TPG, or are defined in ACL
  nodes. WARNING: LIO can use one or the other!
- the `demo_mode_discovery` TPG attribute, which defines if an unknown initiator can discover, *1* enables it
- the `auto_add_mapped_luns` global configuration parameter, which
  influences if TPG luns are automatically added into an ACL for an
  initiator

###### demo mode

> *Demo Mode*: Means disabling authentification for an iSCSI Endpoint,
> i.e. its ACLs are diabled. Demo Mode grants read-only access to all
> iSCSI Initiators that attempt to connect to that specific Endpoint.

``` shell
# targetcli /iscsi/<target>/tpg1 set attribute authentication=0 \
  demo_mode_discovery=1 demo_mode_write_protect=0 generate_node_acls=1 \
  cache_dynamic_acls=1
```


``` shell
targetcli /iscsi/<target>/tpg1 get attribute | egrep '^(demo|generate|auth)'
authentication=1
demo_mode_discovery=1
demo_mode_write_protect=1
generate_node_acls=0
```

##### debugging

``` shell
# grep -Po '^(drivers/target/iscsi[^:]+)(?=.*)' /sys/kernel/debug/dynamic_debug/control | sort -u
drivers/target/iscsi/iscsi_target_auth.c
drivers/target/iscsi/iscsi_target.c
drivers/target/iscsi/iscsi_target_configfs.c
drivers/target/iscsi/iscsi_target_device.c
drivers/target/iscsi/iscsi_target_erl0.c
drivers/target/iscsi/iscsi_target_erl1.c
drivers/target/iscsi/iscsi_target_erl2.c
drivers/target/iscsi/iscsi_target_login.c
drivers/target/iscsi/iscsi_target_nego.c
drivers/target/iscsi/iscsi_target_nodeattrib.c
drivers/target/iscsi/iscsi_target_parameters.c
drivers/target/iscsi/iscsi_target_seq_pdu_list.c
drivers/target/iscsi/iscsi_target_tmr.c
drivers/target/iscsi/iscsi_target_tpg.c
drivers/target/iscsi/iscsi_target_transport.c
drivers/target/iscsi/iscsi_target_util.c
# echo 'file drivers/target/iscsi/iscsi_target_login.c +p' > /sys/kernel/debug/dynamic_debug/control
```

###### discovery authentication

``` shell
Aug 30 13:47:15 sixers kernel: Added timeout timer to iSCSI login request for 15 seconds.
Aug 30 13:47:15 sixers kernel: Moving to TARG_CONN_STATE_XPT_UP.
Aug 30 13:47:15 sixers kernel: Got Login Command, Flags 0x87, ITT: 0x2d185e45, CmdSN: 0xe65d0c32, ExpStatSN: 0x01000000, CID: 0, Length: 382
Aug 30 13:47:15 sixers kernel: Received iSCSI login request from 10.156.232.145:60226 on iSCSI/TCP Network Portal 10.156.232.145:3260
Aug 30 13:47:15 sixers kernel: Moving to TARG_CONN_STATE_IN_LOGIN.
Aug 30 13:47:15 sixers kernel: Initiator is requesting CSG: 1, has not been successfully authenticated, and the Target is enforcing iSCSI Authentication, login failed.
Aug 30 13:47:15 sixers kernel: iSCSI Login negotiation failed.
Aug 30 13:47:15 sixers kernel: Moving to TARG_CONN_STATE_FREE.
```

###### no authentication but still no ACL for the initiator

normal logging for an unsuccessful initiator login

``` shell
# iscsi-ls -i iqn.2021-08.com.suse:testovic -s iscsi://10.156.232.145
Target:iqn.2021-08.com.suse.scz.sup.sixers:vmware Portal:10.156.232.145:3260,1
iscsi_connect failed. Failed to log in to target. Status: Authorization failure(514)
```

``` shell
Aug 30 10:24:50 sixers kernel: iSCSI Initiator Node: iqn.2021-08.com.suse:testovic is not authorized to access iSCSI target portal group: 1.
Aug 30 10:24:50 sixers kernel: iSCSI Login negotiation failed.
```

with additional debugging

``` shell
# echo 'file drivers/target/iscsi/iscsi_target_login.c +p' > /sys/kernel/debug/dynamic_debug/control
Aug 30 10:27:06 sixers kernel: Added timeout timer to iSCSI login request for 15 seconds.
Aug 30 10:27:06 sixers kernel: Moving to TARG_CONN_STATE_XPT_UP.
Aug 30 10:27:06 sixers kernel: Got Login Command, Flags 0x87, ITT: 0x373ccd0b, CmdSN: 0x8a58a748, ExpStatSN: 0x01000000, CID: 0, Length: 382
Aug 30 10:27:06 sixers kernel: Received iSCSI login request from 10.156.232.145:59622 on iSCSI/TCP Network Portal 10.156.232.145:3260
Aug 30 10:27:06 sixers kernel: Moving to TARG_CONN_STATE_IN_LOGIN.
Aug 30 10:27:06 sixers kernel: Moving to TARG_CONN_STATE_LOGGED_IN.
Aug 30 10:27:06 sixers kernel: Moving to TARG_SESS_STATE_LOGGED_IN.
Aug 30 10:27:06 sixers kernel: iSCSI Login successful on CID: 0 from 10.156.232.145:59622 to 10.156.232.145:3260,1
Aug 30 10:27:06 sixers kernel: Incremented iSCSI Connection count to 1 from node: iqn.2021-08.com.suse:testovic
Aug 30 10:27:06 sixers kernel: Established iSCSI session from node: iqn.2021-08.com.suse:testovic
Aug 30 10:27:06 sixers kernel: Incremented number of active iSCSI sessions to 1 on iSCSI Target Portal Group: 1
Aug 30 10:27:06 sixers kernel: Moving to TARG_CONN_STATE_FREE.
Aug 30 10:27:06 sixers kernel: Added timeout timer to iSCSI login request for 15 seconds.
Aug 30 10:27:06 sixers kernel: Moving to TARG_CONN_STATE_XPT_UP.
Aug 30 10:27:06 sixers kernel: Got Login Command, Flags 0x87, ITT: 0x3f0a270a, CmdSN: 0xdff6cc46, ExpStatSN: 0x01000000, CID: 0, Length: 433
Aug 30 10:27:06 sixers kernel: Received iSCSI login request from 10.156.232.145:59624 on iSCSI/TCP Network Portal 10.156.232.145:3260
Aug 30 10:27:06 sixers kernel: Moving to TARG_CONN_STATE_IN_LOGIN.
Aug 30 10:27:06 sixers kernel: iSCSI Initiator Node: iqn.2021-08.com.suse:testovic is not authorized to access iSCSI target portal group: 1.
Aug 30 10:27:06 sixers kernel: iSCSI Login negotiation failed.
Aug 30 10:27:06 sixers kernel: Moving to TARG_CONN_STATE_FREE.
```

###### not expected CHAP negotiation

an initiator tries to authenticate but no ACL exists for the initiator

``` shell
Aug 30 13:56:48 sixers kernel: CHAP user or password not set for Initiator ACL
Aug 30 13:56:48 sixers kernel: Security negotiation failed.
Aug 30 13:56:48 sixers kernel: iSCSI Login negotiation failed.
```

##### setup

via interactive `targetcli` built-in shell

``` shell
targetcli /iscsi/ create [<target_name>]                            # create target,
                                                                    # returns target name if not defined
targetcli /iscsi/<target_name>/tpg1/portals/ create [<ip>] [<port>] # create target and optionally bind to
                                                                    # specific IP and port
targetcli /iscsi/<target_name>/tpg1/luns create <backing_object> \
  [<lun_number>]                                                    # add lun to target portal group
```

or directly from shell (eg. BASH)...

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

### mdraid

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

An example of mdadm's mail:

``` shell
From root@localhost  Fri May 21 13:24:51 2021
Return-Path: <root@localhost>
X-Original-To: root@localhost
Delivered-To: root@localhost
Received: by localhost (Postfix, from userid 0)
        id DC9AA3BDD; Fri, 21 May 2021 13:24:51 +0200 (CEST)
From: mdadm monitoring <root@localhost>
To: root@localhost
Subject: DegradedArray event on /dev/md127:server1
Message-Id: <20210521112451.DC9AA3BDD@localhost>
Date: Fri, 21 May 2021 13:24:51 +0200 (CEST)
Status: RO

This is an automatically generated mail message from mdadm
running on server1

A DegradedArray event had been detected on md device /dev/md127.

Faithfully yours, etc.

P.S. The /proc/mdstat file currently contains the following:

Personalities : [raid1]
md127 : active raid1 sdb2[0]
      732433216 blocks super 1.2 [2/1] [U_]
      bitmap: 6/6 pages [24KB], 65536KB chunk

unused devices: <none>
```

### multipath

if multipath support is required during boot (ie. booting from multipath SAN)
it is in SLES present as *dracut* module (*multipath*) which puts into initramfs
multipath-tools binaries, libs, configuration and udev/systemd files. See
[Troubleshooting boot issues (multipath with lvm)](
  https://www.suse.com/support/kb/doc/?id=000019115).

- *priority group*, paths (transport interconnects) are grouped into
  an **ordered** list of Priority Groups. Inside a priority group paths
  are selected based on a path selector, when one path fails, the next
  one in the priority group is tried, when all paths in the priority
  group fail, next priority group is tried
- *path selector*
- *failed path*, a path that generated an error, path selector passes over it
- *dead path*
- *map*
- *multipath*
- *multipathd*, an user-space daemon responsible for monitoring paths that have
  failed and reinstating them should they come back



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

`multipathd` also allows an interactive shell, some examples

``` shell
# multipathd show paths
hcil    dev dev_t pri dm_st  chk_st dev_st  next_check
1:0:0:0 sda 8:0   50  active ready  running XXXX...... 8/20
1:0:3:0 sdb 8:16  50  active ready  running X......... 2/20

# multipathd show paths format '%w %i %d %D %t %o %T %s %c %p %S %z %N %n %R %r %a'
uuid                              hcil    dev dev_t dm_st  dev_st  chk_st vend/prod/rev      checker pri size  serial                 host WWNN          target WWNN        host WWPN          target WWPN        host adapter
3600d023100049aaa714c80f5169c0158 1:0:0:0 sda 8:0   active running ready  IFT,DS 1000 Series tur     50  1000G 049AAA714C80F5169C0158 0x20000024ff7d6a16 0x200000d023049aaa 0x21000024ff7d6a16 0x220000d023049aaa 0000:80:03.0
3600d023100049aaa714c80f5169c0158 1:0:3:0 sdb 8:16  active running ready  IFT,DS 1000 Series tur     50  1000G 049AAA714C80F5169C0158 0x20000024ff7d6a16 0x200000d023049aaa 0x21000024ff7d6a16 0x210000d023049aaa 0000:80:03.0

# multipathd show devices
available block devices:
    sda devnode whitelisted, monitored
    sdb devnode whitelisted, monitored
    sdc devnode whitelisted, unmonitored
    dm-0 devnode blacklisted, unmonitored
    dm-1 devnode blacklisted, unmonitored
    dm-2 devnode blacklisted, unmonitored
    dm-3 devnode blacklisted, unmonitored
    dm-4 devnode blacklisted, unmonitored
    dm-5 devnode blacklisted, unmonitored
    dm-6 devnode blacklisted, unmonitored
    dm-7 devnode blacklisted, unmonitored
    dm-8 devnode blacklisted, unmonitored
    dm-9 devnode blacklisted, unmonitored
    dm-10 devnode blacklisted, unmonitored
    dm-11 devnode blacklisted, unmonitored
    dm-12 devnode blacklisted, unmonitored
    dm-13 devnode blacklisted, unmonitored
    dm-14 devnode blacklisted, unmonitored
    dm-15 devnode blacklisted, unmonitored
    dm-16 devnode blacklisted, unmonitored
    dm-17 devnode blacklisted, unmonitored
    dm-18 devnode blacklisted, unmonitored
    dm-19 devnode blacklisted, unmonitored
    dm-20 devnode blacklisted, unmonitored
    dm-21 devnode blacklisted, unmonitored
    dm-22 devnode blacklisted, unmonitored
    dm-23 devnode blacklisted, unmonitored
    dm-24 devnode blacklisted, unmonitored
    dm-25 devnode blacklisted, unmonitored
```

> The high-level management of dm-multipath devices is done in user
> space. This applies to `no_path_retry` for example. Device mapper
> only knows queueing state (`queue_if_no_path`) or non-queueing
> state. `no_path_retry` is a concept of multipathd, which counts
> seconds after the last path goes offline, and switches to
> non-queueing mode after the specified time (`no_path_retry *
> polling_interval`). Thus, what you see in `multipath -ll` output is
> indeed effective - it shows how the kernel is configured. If all
> paths went down in your sample above, the kernel would start
> queueing, until multipathd tells it to stop by clearing the
> `queue_if_no_path` flag.
>
> -- <cite>[[RFE] Could we see multipath options somewhere in
> /sys?](https://github.com/opensvc/multipath-tools/issues/11#issuecomment-903664928)</cite>

``` shell
# multipath -t | grep polling_interval
        polling_interval 5
        max_polling_interval 20
# multipathd show paths
hcil    dev dev_t pri dm_st  chk_st dev_st  next_check
1:0:0:0 sda 8:0   50  active ready  running X......... 2/20
1:0:3:0 sdb 8:16  50  active ready  running XXXXXXX... 15/20
```

Thus the above shows the paths are checked every 20 secs where the
check is not executed at same point of time.

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

Red Hat [Configuring device mapper
multipath](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html-single/configuring_device_mapper_multipath/index)
guide is great place for additional info!

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

#### raid

``` shell

```

##### raid1

``` shell
$ lvcreate --type raid1 -m 1 -l 100%FREE -n raid-1 test

$ lvs test/raid-1
  LV     VG   Attr       LSize    Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
  raid-1 test rwi-a-r--- 1008.00m                                    100.00

$ lvdisplay vgdbJJP00_01/lvJJP_ora
  LV Path                /dev/vgdbJJP00_01/lvJJP_ora
  LV Name                lvJJP_ora
  VG Name                vgdbJJP00_01
  LV UUID                i3qrhA-JJbq-D9X5-Guiv-dP7a-rZ8G-FIyMu9
  LV Write Access        read/write
  LV Creation host, time uttsapjjpdb00, 2021-09-13 15:40:24 +0100
  LV Status              available
  # open                 1
  LV Size                45.00 GiB
  Current LE             2880
  Mirrored volumes       2
  Segments               1
  Allocation             inherit
  Read ahead sectors     auto
  - currently set to     1024
  Block device           254:39

$ dmsetup table | grep 'test-raid--1'
test-raid--1: 0 2064384 raid raid1 3 0 region_size 4096 2 254:5 254:6 254:7 254:8
                             ^^ type
                                   ^^ no. of params
                                     ^^ chunk size
                                       ^^ region size <number>
                                                        ^^ no. of devices
test-raid--1_rimage_0: 0 2064384 linear 259:4 10240
test-raid--1_rimage_1: 0 2064384 linear 259:6 10240
test-raid--1_rmeta_0: 0 8192 linear 259:4 2048
test-raid--1_rmeta_1: 0 8192 linear 259:6 2048
```

Description for `dmsetup table` output for *raid1* is at
[device-mapper/dm-raid.txt](https://www.kernel.org/doc/Documentation/device-mapper/dm-raid.txt).

Checking data coherency in a RAID logical volume:

``` shell
$ lvchange -v --syncaction check test/raid-1

$ journal -f
...
Oct 27 12:41:51 t14s kernel: md: data-check of RAID array mdX
Oct 27 12:41:57 t14s kernel: md: mdX: data-check done.
Oct 27 12:41:57 t14s lvm[13194]: raid1 array, test-raid--1, is now in-sync.
...

$ lvs -o +raid_sync_action,raid_mismatch_count test/raid-1
  LV     VG   Attr       LSize    Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert SyncAction Mismatches
  raid-1 test rwi-a-r--- 1008.00m
```

Partial failure:

``` shell
$ lvs -o +raid_sync_action,raid_mismatch_count test/raid-1
  WARNING: Couldn't find device with uuid 3vLD5P-5gQO-U9MS-EgD0-uax3-jhQz-7SRUUI.
  WARNING: VG test is missing PV 3vLD5P-5gQO-U9MS-EgD0-uax3-jhQz-7SRUUI (last written to /dev/loop1p2).
  LV     VG   Attr       LSize    Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert SyncAction Mismatches
  raid-1 test rwi-aor-p- 1008.00m                                    100.00           idle                0

```

See 'p' as 9th bit of lv_attrs.

#### thinpool

``` shell
lvcreate -L <size> -T -n <name> <vg> # create a thin pool

```

#### troubleshooting

`pvcreate` does not seem to work on a raw disk... because there's a partition table!

``` shell
# pvcreate -v /dev/sdc
  Device /dev/sdc excluded by a filter.
```

``` shell
pvcreate -vvv /dev/sdc
```

``` shell
# pvcreate -vvv /dev/sdc 2>&1 | grep /dev/sdc
        Parsing: pvcreate -vvv /dev/sdc
        Processing command: pvcreate -vvv /dev/sdc
        Found dev 8:32 /dev/sdc - new.
        Opened /dev/sdc RO O_DIRECT
      /dev/sdc: size is 1953525168 sectors
        Closed /dev/sdc
        filter partitioned deferred /dev/sdc
        filter signature deferred /dev/sdc
        filter md deferred /dev/sdc
        filter cache deferred /dev/sdc
        Processing data from device /dev/sdc 8:32 fd 12 block 0x55a5b984fef0
        Scan filtering /dev/sdc
      /dev/sdc: using cached size 1953525168 sectors
        /dev/sdc: Skipping: Partition table signature found
        filter caching bad /dev/sdc
      /dev/sdc: Not processing filtered
        /dev/sdc: filter cache skipping (cached bad)
        /dev/sdc: filter cache skipping (cached bad)
  Device /dev/sdc excluded by a filter.
        Completed: pvcreate -vvv /dev/sdc
# fdisk -l /dev/sdc
Disk /dev/sdc: 931.51 GiB, 1000204886016 bytes, 1953525168 sectors
Disk model: ST1000VN000-1HJ1
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 4096 bytes
I/O size (minimum/optimal): 4096 bytes / 4096 bytes
Disklabel type: gpt
Disk identifier: 77396D23-9BA8-4A41-B730-FE71A498156B
# dd if=/dev/zero of=/dev/sdc bs=512 count=1
# pvcreate /dev/sdc
  Physical volume "/dev/sdc" successfully created.
```

`pvmove` allows to move PE (physical extents) to new PV while allowing
to define spefic LV or PE map. It could be handy to use `pvchange
[-x|--allocatable] [y|n]` to allow/disallow new allocation of PEs on a
specific PV (eg. during storage migration).

renaming a VG with same name as already existing one

``` shell
vgs
  WARNING: VG name system is used by VGs rWunAT-oHmL-t3iV-6O2y-mbVT-LUfm-5UzHom and 1ZCjy2-WL2Q-7fQH-l7OV-cLGE-f5x7-aS2Wvu.
  Fix duplicate VG names with vgrename uuid, a device filter, or system IDs.
  VG     #PV #LV #SN Attr   VSize   VFree
  system   1   2   0 wz--n- 596.16g     0
  system   1   4   0 wz--n- 476.45g 12.73g


pvs -o +pv_uuid
  WARNING: VG name system is used by VGs rWunAT-oHmL-t3iV-6O2y-mbVT-LUfm-5UzHom and 1ZCjy2-WL2Q-7fQH-l7OV-cLGE-f5x7-aS2Wvu.
  Fix duplicate VG names with vgrename uuid, a device filter, or system IDs.
  PV                                                                  VG     Fmt  Attr PSize   PFree  PV UUID
  /dev/mapper/cr_nvme-SAMSUNG_MZALQ512HALU-000L1_S4YCNF0NC31508-part2 system lvm2 a--  476.45g 12.73g i21uoW-rc6C-F9R9-6S59-Vb83-FtRC-3zhuL5
  /dev/sda2                                                           system lvm2 a--  596.16g     0  9v5GpR-WYDt-2JNj-xQTZ-cntr-Of4M-Zj7HNb

vgs -o +vg_uuid,pv_uuid
  WARNING: VG name system is used by VGs rWunAT-oHmL-t3iV-6O2y-mbVT-LUfm-5UzHom and 1ZCjy2-WL2Q-7fQH-l7OV-cLGE-f5x7-aS2Wvu.
  Fix duplicate VG names with vgrename uuid, a device filter, or system IDs.
  VG     #PV #LV #SN Attr   VSize   VFree  VG UUID                                PV UUID
  system   1   2   0 wz--n- 596.16g     0  rWunAT-oHmL-t3iV-6O2y-mbVT-LUfm-5UzHom 9v5GpR-WYDt-2JNj-xQTZ-cntr-Of4M-Zj7HNb
  system   1   4   0 wz--n- 476.45g 12.73g 1ZCjy2-WL2Q-7fQH-l7OV-cLGE-f5x7-aS2Wvu i21uoW-rc6C-F9R9-6S59-Vb83-FtRC-3zhuL5

vgrename -v rWunAT-oHmL-t3iV-6O2y-mbVT-LUfm-5UzHom temp
  WARNING: VG name system is used by VGs rWunAT-oHmL-t3iV-6O2y-mbVT-LUfm-5UzHom and 1ZCjy2-WL2Q-7fQH-l7OV-cLGE-f5x7-aS2Wvu.
  Fix duplicate VG names with vgrename uuid, a device filter, or system IDs.
  Processing VG system because of matching UUID rWunAT-oHmL-t3iV-6O2y-mbVT-LUfm-5UzHom
    Writing out updated volume group
    Archiving volume group "system" metadata (seqno 3).
    Renaming "/dev/system" to "/dev/temp"
    Creating volume group backup "/etc/lvm/backup/temp" (seqno 4).
  Volume group "rWunAT-oHmL-t3iV-6O2y-mbVT-LUfm-5UzHom" successfully renamed to "temp"
```

### scsi

:construction: work in progress!

- *initiator*, adapter of a computer, *HBA*, *client* in SCSI mode paradigm
- *HBA*, *host bus adapter*, adapter of a computer being the initiator
- *target*, controller, *server* in SCSI mode paradigm
- *logical unit*, *LU*, a logical unit within the target
- *logical unit number* (*lun* - lowercase!), LU number, number of a logical
  unit within target - with target ID
- *ACSL*, an address of device consisting of adapter ID, adapter channel,
  target ID, logical unit number
  ``` shell
  # lsscsi -c # same as `cat /proc/scsi/scsi'
  Attached devices:
  Host: scsi0 Channel: 00 Target: 00 Lun: 00
    Vendor: ASR8805  Model: LogicalDrv 0     Rev: V1.0
    Type:   Direct-Access                    ANSI SCSI revision: 02
  Host: scsi0 Channel: 01 Target: 00 Lun: 00
    Vendor: ATA      Model: SAMSUNG MZ7KM480 Rev: 104Q
    Type:   Direct-Access                    ANSI SCSI revision: 06
  Host: scsi0 Channel: 01 Target: 01 Lun: 00
    Vendor: ATA      Model: SAMSUNG MZ7KM480 Rev: 104Q
    Type:   Direct-Access                    ANSI SCSI revision: 06
  Host: scsi0 Channel: 03 Target: 00 Lun: 00
    Vendor: ADAPTEC  Model: Virtual SGPIO    Rev:    1
    Type:   Enclosure                        ANSI SCSI revision: 05
  Host: scsi1 Channel: 00 Target: 00 Lun: 00
    Vendor: IFT      Model: DS 1000 Series   Rev: 555Q
    Type:   Direct-Access                    ANSI SCSI revision: 05
  Host: scsi1 Channel: 00 Target: 00 Lun: 05
    Vendor: IFT      Model: DS 1000 Series   Rev: 555Q
    Type:   Enclosure                        ANSI SCSI revision: 05
  Host: scsi1 Channel: 00 Target: 03 Lun: 00
    Vendor: IFT      Model: DS 1000 Series   Rev: 555Q
    Type:   Direct-Access                    ANSI SCSI revision: 05
  Host: scsi1 Channel: 00 Target: 03 Lun: 05
    Vendor: IFT      Model: DS 1000 Series   Rev: 555Q
    Type:   Enclosure                        ANSI SCSI revision: 05
  ```
- *LUN* (uppercase!), LU name, is an alias for disk LU, or logical disk on SAN
  ``` shell
  # lsscsi -U 1:0:*:0
  [1:0:0:0]    disk    600d023100049aaa714c80f5169c0158  /dev/sda
  [1:0:3:0]    disk    600d023100049aaa714c80f5169c0158  /dev/sdb
  ```

#### SCSI reservations and SCSI persistent reservations

good overview is at [What are SCSI Reservations and SCSI Persistent Reservations?
](https://kb.netapp.com/Advice_and_Troubleshooting/Data_Storage_Software/ONTAP_OS/What_are_SCSI_Reservations_and_SCSI_Persistent_Reservations).

##### general intro

- *SCSI* reservation is used to control access to a shared SCSI device
- initiator sets the reservation
- part of SCSI protocols
- *SCSI-2* Reservation, *original* and deprecated reservation mechanism using
  SCSI Reserve/SCSI Release command; :warning: SCSI bus reset would cause the
  reservation to be released; plus it does **NOT** support multipaths, works
  with a single path to a LUN
- *SCSI-3 Persistent Reservation* is a modern approach to reservations and
  **persists** even if the SCSI bus is reset for error recovery plus it
  supports reservation over multiple paths from host to disk

##### scsi-3 persistent reservations

- SCSI-3 Persistent Reservations uses a concept of registration and reservation.
  Systems that participate, register a key, each system registers its own key.
  Only registered systems can establish a reservation.
- Persistent Reservations means ... With
  this method, blocking write access is as simple as removing registration from a device. A system wishing to eject another system may register, clear or preempt the other registered initiators. This method effectively avoids the split-brain condition.
-
the below issue seems to point to SCSI-3 persist reservation, see RH
discussion [`kernel: sd 1:0:0:0: reservation
conflict`](https://access.redhat.com/discussions/2931811). some notes
also at [How can I view, create, and remove SCSI persistent
reservations and keys. from redhat
](https://dhelios.blogspot.com/2015/04/how-can-i-view-create-and-remove-scsi.html).

``` shell
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: reservation conflict
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: [sdx] tag#785 FAILED Result: hostbyte=DID_OK driverbyte=DRIVER_OK
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: [sdx] tag#785 CDB: Write(10) 2a 00 25 80 88 08 00 00 08 00
Aug 26 13:31:03 somehost kernel: sd 1:0:11:0: reservation conflict
Aug 26 13:31:03 somehost kernel: sd 1:0:11:0: [sdl] tag#1004 FAILED Result: hostbyte=DID_OK driverbyte=DRIVER_OK
Aug 26 13:31:03 somehost kernel: sd 1:0:11:0: [sdl] tag#1004 CDB: Write(10) 2a 00 00 00 08 08 00 00 08 00
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: reservation conflict
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: [sdx] tag#203 FAILED Result: hostbyte=DID_OK driverbyte=DRIVER_OK
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: [sdx] tag#203 CDB: Write(10) 2a 00 25 80 88 08 00 00 08 00
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: reservation conflict
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: [sdx] tag#204 FAILED Result: hostbyte=DID_OK driverbyte=DRIVER_OK
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: [sdx] tag#204 CDB: Write(10) 2a 00 25 80 88 00 00 00 01 00
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: reservation conflict
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: [sdx] tag#617 FAILED Result: hostbyte=DID_OK driverbyte=DRIVER_OK
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: [sdx] tag#617 CDB: Write(10) 2a 00 25 80 88 08 00 00 08 00
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: reservation conflict
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: [sdx] tag#618 FAILED Result: hostbyte=DID_OK driverbyte=DRIVER_OK
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: [sdx] tag#618 CDB: Write(10) 2a 00 25 80 88 00 00 00 01 00
Aug 26 13:31:03 somehost kernel: sd 1:0:11:0: reservation conflict
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: reservation conflict
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: reservation conflict
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: reservation conflict
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: reservation conflict
Aug 26 13:31:03 somehost kernel: sd 2:0:11:0: reservation conflict
```

``` shell
# sg_persist -n -v -y -i -k /dev/sdb
    Persistent Reservation In cmd: 5e 00 00 00 00 00 00 20 00 00
  PR generation=0x0, there are NO registered reservation keys
# sg_persist -n -v -y -i -r /dev/sdb
    Persistent Reservation In cmd: 5e 01 00 00 00 00 00 20 00 00
  PR generation=0x0, there is NO reservation held

# and with registration

# sg_persist -n -in -v -y -r /dev/sdc
    Persistent Reservation In cmd: 5e 01 00 00 00 00 00 20 00 00
  PR generation=0x3, Reservation follows:
    Key=0x123aaa
    scope: LU_SCOPE,  type: Write Exclusive, registrants only
# sg_persist -n -in -v -y -k /dev/sdc
    Persistent Reservation In cmd: 5e 00 00 00 00 00 00 20 00 00
  PR generation=0x3, 1 registered reservation key follows:
    0x123aaa
```

following test script is taken from RH [bugzilla](https://bugzilla.redhat.com/show_bug.cgi?id=1464908#c22)

``` shell
#! /bin/sh
sg_persist --no-inquiry -v --out --register-ignore --param-sark 123aaa "$@"
sg_persist --no-inquiry --in -k "$@"
sg_persist --no-inquiry -v --out --reserve --param-rk 123aaa --prout-type 5 "$@"
sg_persist --no-inquiry --in -r "$@"
sg_persist --no-inquiry -v --out --release --param-rk 123aaa --prout-type 5 "$@"
sg_persist --no-inquiry --in -r "$@"
sg_persist --no-inquiry -v --out --register --param-rk 123aaa --prout-type 5 "$@"
sg_persist --no-inquiry --in -k "$@"
```

``` shell
# running script above with a scsi disk

/tmp/in /dev/sdc
    Persistent Reservation Out cmd: 5f 06 00 00 00 00 00 00 18 00
PR out: command (Register and ignore existing key) successful
  PR generation=0x4, 1 registered reservation key follows:
    0x123aaa
    Persistent Reservation Out cmd: 5f 01 05 00 00 00 00 00 18 00
PR out: command (Reserve) successful
  PR generation=0x4, Reservation follows:
    Key=0x123aaa
    scope: LU_SCOPE,  type: Write Exclusive, registrants only
    Persistent Reservation Out cmd: 5f 02 05 00 00 00 00 00 18 00
PR out: command (Release) successful
  PR generation=0x4, there is NO reservation held
    Persistent Reservation Out cmd: 5f 00 05 00 00 00 00 00 18 00
PR out: command (Register) successful
  PR generation=0x4, there are NO registered reservation keys
```

### tapes

[*mhvtl*](http://sites.google.com/site/linuxvtl2/), A Virtual Tape & Library
system, could be used as tape library virtualization.

On OpenSUSE TW *mhvtl* consists of:

- `mhvtl-load-modules.service` systemd unit which loads `mhvtl` kernel module
  and also acts as a pseudo HBA
  ``` shell
  $ lsscsi -C | grep mhvtl
  [1]    mhvtl

  $ lsscsi -ig 1
  [1:0:0:0]    mediumx STK      SL150            0164  /dev/sch0  -  /dev/sg1 
  [1:0:1:0]    tape    HP       Ultrium 6-SCSI   0164  /dev/st0   -  /dev/sg2 
  [1:0:2:0]    tape    HP       Ultrium 6-SCSI   0164  /dev/st1   -  /dev/sg3 
  ```
- systemd units and generator to make the VTL itself work:
  ``` shell
  $ rpm -ql mhvtl | grep -P 'systemd/system(-generators/|/(\.target|vtl))'
  /usr/lib/systemd/system-generators/mhvtl-device-conf-generator
  /usr/lib/systemd/system/vtllibrary@.service
  /usr/lib/systemd/system/vtltape@.service
  ```

  The generator creates individual vtlibrary and vtltape instances parsing
  `/etc/mhvtl/device.conf`:
  ``` shell
  $ systemctl --plain list-dependencies mhvtl.target
  mhvtl.target
    mhvtl-load-modules.service
    vtllibrary@10.service
    vtltape@11.service
    vtltape@12.service
  ```

Each library defined in `/etc/mhvtl/device.conf` has a corresponding
`/etc/mhvtl/library_contents.<id>`.

An example:

``` shell
$ grep -Pv '^\s*(#|$)' /etc/mhvtl/device.conf
VERSION: 5
Library: 10 CHANNEL: 00 TARGET: 00 LUN: 00
 Vendor identification: STK
 Product identification: SL150
 NAA:  50:01:04:f0:00:dd:90:af
 Home directory: /var/lib/mhvtl
 PERSIST: False
 Backoff: 400
Drive: 11 CHANNEL: 00 TARGET: 01 LUN: 00
 Library ID: 10 Slot: 01
 Vendor identification: HP
 Product identification: Ultrium 6-SCSI
 NAA: 10:22:33:44:ab:00:01:00
 Compression: factor 1 enabled 1
 Compression type: lzo
 Backoff: 400
Drive: 12 CHANNEL: 00 TARGET: 02 LUN: 00
 Library ID: 10 Slot: 02
 Vendor identification: HP
 Product identification: Ultrium 6-SCSI
 NAA: 10:22:33:44:ab:00:02:00
 Compression: factor 1 enabled 1
 Compression type: lzo
 Backoff: 400

$ grep -Pv '^\s*(#|$)' /etc/mhvtl/library_contents.10
VERSION: 2
Drive 1: XYZZY_A1
Drive 2: XYZZY_A2
Picker 1:
MAP 1:
Slot 1: E01001L8
Slot 2: E01002L8
Slot 3: E01003L8
Slot 4: E01004L8
Slot 5: E01005L8
Slot 6: E01006L8
Slot 7: E01007L8
Slot 8: E01008L8
```

Some operations:

``` shell
$ mtx -f /dev/sch0 inquiry
Product Type: Medium Changer
Vendor ID: 'STK     '
Product ID: 'SL150           '
Revision: '0164'
Attached Changer API: No

$ mtx -f /dev/sch0 status
  Storage Changer /dev/sch0:2 Drives, 9 Slots ( 1 Import/Export )
Data Transfer Element 0:Empty
Data Transfer Element 1:Empty
      Storage Element 1:Full :VolumeTag=E01001L8                            
      Storage Element 2:Full :VolumeTag=E01002L8                            
      Storage Element 3:Full :VolumeTag=E01003L8                            
      Storage Element 4:Full :VolumeTag=E01004L8                            
      Storage Element 5:Full :VolumeTag=E01005L8                            
      Storage Element 6:Full :VolumeTag=E01006L8                            
      Storage Element 7:Full :VolumeTag=E01007L8                            
      Storage Element 8:Full :VolumeTag=E01008L8                            
      Storage Element 9 IMPORT/EXPORT:Empty
```

### udev

As for rules processing order, see

``` shell
$ man udev | sed -n '/RULES FILES/,/^ *Opera/{/^ *Oper/q;p}' | fmt -w 80
RULES FILES
       The udev rules are read from the files located in the system rules
       directories /usr/lib/udev/rules.d and /usr/local/lib/udev/rules.d,
       the volatile runtime directory /run/udev/rules.d and the local
       administration directory /etc/udev/rules.d. All rules files are
       collectively sorted and processed in lexical order, regardless of the
       directories in which they live. However, files with identical filenames
       replace each other. Files in /etc/ have the highest priority, files in
       /run/ take precedence over files with the same name under /usr/. This
       can be used to override a system-supplied rules file with a local file
       if needed; a symlink in /etc/ with the same name as a rules file in
       /usr/lib/, pointing to /dev/null, disables the rules file entirely. Rule
       files must have the extension .rules; other extensions are ignored.

       Every line in the rules file contains at least one key-value
       pair. Except for empty lines or lines beginning with "#", which are
       ignored. There are two kinds of keys: match and assignment. If all
       match keys match against their values, the rule gets applied and the
       assignment keys get the specified values assigned.

       A matching rule may rename a network interface, add symlinks pointing
       to the device node, or run a specified program as part of the event
       handling.

       A rule consists of a comma-separated list of one or more
       key-operator-value expressions. Each expression has a distinct effect,
       depending on the key and operator used.
```

``` shell
$ udevadm info --attribute-walk \
  --path=$(udevadm info --query=path --name=/dev/watchdog1) | \
  sed -n '/^ *looking at device/,/^ *$/{/^ *$/q;p}'           # getting info
  looking at device '/devices/pci0000:00/0000:00:1f.0/iTCO_wdt.1.auto/watchdog/watchdog1':
    KERNEL=="watchdog1"
    SUBSYSTEM=="watchdog"
    DRIVER==""
    ATTR{bootstatus}=="0"
    ATTR{identity}=="iTCO_wdt"
    ATTR{nowayout}=="0"
    ATTR{power/async}=="disabled"
    ATTR{power/control}=="auto"
    ATTR{power/runtime_active_kids}=="0"
    ATTR{power/runtime_active_time}=="0"
    ATTR{power/runtime_enabled}=="disabled"
    ATTR{power/runtime_status}=="unsupported"
    ATTR{power/runtime_suspended_time}=="0"
    ATTR{power/runtime_usage}=="0"
    ATTR{state}=="inactive"
    ATTR{status}=="0x100"
    ATTR{timeleft}=="4"
    ATTR{timeout}=="5"

$ cat /etc/udev/rules.d/99-sbd-watchdog.rules 
SUBSYSTEM=="watchdog", ATTRS{identity}=="iTCO_wdt", SYMLINK+="iTCO_wdt"

$ ls -l /dev/{watchdog*,iTCO_wdt}
lrwxrwxrwx 1 root root      9 Dec 21 15:57 /dev/iTCO_wdt -> watchdog1
crw------- 1 root root 248, 1 Dec 21 15:57 /dev/watchdog1

$ udevadm info -q property -n <dev> # info about a device
```

#### modules loading

> The default rules provided with Udev will cause udevd to call out to
> /sbin/modprobe with the contents of the MODALIAS uevent environment variable
> (which should be the same as the contents of the modalias file in sysfs), thus
> loading all modules whose aliases match this string after wildcard expansion."
> -- [Overview of Device and Module
> Handling](https://web.archive.org/web/20190921024300/https://www.linuxfromscratch.org/lfs/view/development/chapter07/udev.html)

``` shell
$ ethtool -i wlan0
driver: iwlwifi
version: 5.15.11-2.g730a488-default
firmware-version: 63.c04f3485.0 cc-a0-63.ucode
expansion-rom-version:
bus-info: 0000:03:00.0
supports-statistics: yes
supports-test: no
supports-eeprom-access: no
supports-register-dump: no
supports-priv-flags: no

$ lspci -nnvs 03:00.0
03:00.0 Network controller [0280]: Intel Corporation Wi-Fi 6 AX200 [8086:2723] (rev 1a)
        Subsystem: Intel Corporation Device [8086:0080]
        Physical Slot: 0
        Flags: bus master, fast devsel, latency 0, IRQ 84, IOMMU group 12
        Memory at fd600000 (64-bit, non-prefetchable) [size=16K]
        Capabilities: [c8] Power Management version 3
        Capabilities: [d0] MSI: Enable- Count=1/1 Maskable- 64bit+
        Capabilities: [40] Express Endpoint, MSI 00
        Capabilities: [80] MSI-X: Enable+ Count=16 Masked-
        Capabilities: [100] Advanced Error Reporting
        Capabilities: [14c] Latency Tolerance Reporting
        Capabilities: [154] L1 PM Substates
        Kernel driver in use: iwlwifi
        Kernel modules: iwlwifi

# no explicitly enabled

$ grep -IRc iwlwifi /etc/modules-load.d/ /proc/cmdline
/proc/cmdline:0

$ grep -RH '' /sys/bus/pci/devices/0000\:03\:00.0/{modalias,vendor,device,uevent}
/sys/bus/pci/devices/0000:03:00.0/modalias:pci:v00008086d00002723sv00008086sd00000080bc02sc80i00
/sys/bus/pci/devices/0000:03:00.0/vendor:0x8086
/sys/bus/pci/devices/0000:03:00.0/device:0x2723
/sys/bus/pci/devices/0000:03:00.0/uevent:DRIVER=iwlwifi
/sys/bus/pci/devices/0000:03:00.0/uevent:PCI_CLASS=28000
/sys/bus/pci/devices/0000:03:00.0/uevent:PCI_ID=8086:2723
/sys/bus/pci/devices/0000:03:00.0/uevent:PCI_SUBSYS_ID=8086:0080
/sys/bus/pci/devices/0000:03:00.0/uevent:PCI_SLOT_NAME=0000:03:00.0
/sys/bus/pci/devices/0000:03:00.0/uevent:MODALIAS=pci:v00008086d00002723sv00008086sd00000080bc02sc80i00

# an attempt to see how udev could load it

$ awk '/^alias pci:/ && $NF == "iwlwifi" { print NR,$2,$NF }' \
  /lib/modules/`uname -r`/modules.alias | \
  while read no alias drv; do
    [[ $(cat /sys/bus/pci/devices/0000\:03\:00.0/modalias) == ${alias} ]] \
      && echo matched: ${no} ${alias} ${drv} 
  done
matched: 8515 pci:v00008086d00002723sv*sd*bc*sc*i* iwlwifi
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

#### desktop stuff

``` shell
mkdir /etc/systemd/logind.conf.d
echo 'HandleLidSwitch=ignore' >> \
  /etc/systemd/logind.conf.d/lid.conf
systemctl restart systemd-logind # does not work on SUSE
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
* `systemd.device_wants_unit=off`     # on SUSE
* `systemd.mask=dev-system-swap.swap` # on SUSE
* `systemctl list-units --type=swap`
* `systemd-escape -p --suffix=swap /dev/system/swap` # returns 'dev-system-swap.swap'

#### tips

systemd units allow variety of conditions you can test, see
[systemd.unit](https://www.freedesktop.org/software/systemd/man/systemd.unit.html#Conditions%20and%20Asserts).

``` shell
[Unit]
ConditionPathExists=/path/to/needed_file
```

#### troubleshooting

- emergency shell - systemd after `pivot_root`
- `systemd.log_level=debug systemd.log_target=console systemd.log_location=true systemd.show_status=true`
- `systemd-analyze set-log-level <level>` - change logging level
- `systemctl show -p LogLevel` - get current logging level
- `kill -SIGRTMIN+22 1` - sets systemd loglevel to debug, see `systemd(1)`
- `kill -SIGRTMIN+23 1` - sets systemd loglevel back to info

If *SIGRTMIN+22/23* does not exist, just use number, ie. *SIGRTMIN* =
*34* plus required number.

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

## distributions

### RHEL

#### sosreport

- `sos_commands/systemd/journalctl_--list-boots`
- `sos_commands/block/lsblk{,_-f_-a_-l}`
- `etc/fstab`
- `{free,proc/meminfo}`

### SLES

#### installation

*linuxrc* is *init* instead of *systemd*

#### networking

classical static networking

``` shell
# route iface specification should either be valid or could not be defined
echo 'default <ip> - -' > /etc/sysconfig/network/routes

cat > /etc/sysconfig/network/ifcfg-eth0 <<EOF
IPADDR='<ip/mask>'
BOOTPROTO='static'
STARTMODE='auto'
EOF
```

static route on a DHCP managed iface needs also a definition for the
gateway itself, see [Q: Why wicked does not set my (default) static
route?](https://github.com/openSUSE/wicked/wiki/FAQ#q-why-wicked-does-not-set-my-default-static-route)

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

#### SUSE customer center (SCC)

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


### sealing / templating

*TODO*: NetworkManager networking style; validate dbus/machine-id

``` shell
# generic
rm /etc/machine-id # machine-id in /var/lib/dbus is symlink
rm /etc/ssh/{ssh_host*,moduli}
rm /etc/udev/rules.d/*-persistent-*.rules

<editor> /etc/default/grub # path to block device

# suse specific
rm /etc/zypp/credentials.d/SCCcredentials
rm /etc/zypp/services.d/*
rm /var/lib/wicked/{duid,iaid,lease-eth0-dhcp-ipv4}.xml

<editor> /etc/default/grub_installdevice # path to block device
<editor> /etc/sysconfig/network/if{cfg,route}-eth0
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
$ zypper lr # list repos
$ zypper lr -d <repo> # details about a repo
$ zypper mr -e <repo>
$ zypper mr -e --all # enable all repos

# install from disabled repository
$ zypper -v --plus-content SUSE-PackageHub-15-SP3-Backports-Pool install tmate
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
# zypper rm -u <package> # removes package and all deps
# zypper se -x --provides /usr/bin/gnat # search package owning path
# zypper se -x --provides 'libssl.so.1.1(OPENSSL_1_1_1)(64bit)'
Loading repository data...
Reading installed packages...

S | Name          | Summary                                     | Type
--+---------------+---------------------------------------------+--------
i | libopenssl1_1 | Secure Sockets and Transport Layer Security | package
```

##### patches

``` shell
zypper lp
zypper pchk
zypper patch # updates only affected/vulnerable packages
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

#### troubleshooting

WIP!!!

1. find `Receive print job for <printer>` in `messages`
2. get job ID related to above `Receive...` line (for job id)
3. see `Closing connection` for `cups-lpd` PID spawned for the above `Receive...` line
4. find `POST /jobs/<job> HTTP/1.1` in `error_log` (for client number)
5. get client ID from above `POST...` `error_log` line
6. find `[Job <job>] argv[2]=` line in `error_log` line (for user)
7. get `argv[2]` value from above line

``` shell
#!/bin/bash

MESSAGES=$1
ERRORLOG=$2
TIME=$3
PRINTER=$4

get_jobid() {
    local _out
    local _lineno
    local _pid
    local _jobid

    # get Recieve print job line
   _out=$(grep -n "${TIME}.*Receive print job for ${PRINTER}" "${MESSAGES}")
   [[ -z "${_out}" ]] && exit 1

   # get Receive print job line number
   _lineno="${_out%%:*}"
   (( ${_lineno} )) || exit 1

   # get cups-lpd pid
   _pid=$(grep -Po 'cups-lpd\[\K(\d+)(?=.*)' <<< "${_out}")
   (( ${_pid} )) || exit 1

   # get job id
   while read line; do
       # skin unrelated files
       if [[ ! "${line}" =~ ${_time}.*\ cups-lpd\[${_pid}\] ]]; then
	   continue
       elif ! (( ${_jobid} )); then
	   _jobid=$(grep -Po "cups-lpd\[${_pid}\]: Print file \- job ID = \K(\d+)(?=.*)" <<< "${line}")
       else
	   break
       fi
   # read since matched Receive print job line till end...
   done < <(sed -n ${_lineno}',$p' "${MESSAGES}")
   echo ${_pid} ${_jobid}
}

get_jobdet() {
    local _jobid=$1

    local _client
    local _user

    _client=$(grep -Po '\[Client \K(\d+)(?=\] POST /jobs/'${_jobid}' HTTP/1\.1)' ${ERRORLOG})
    (( ${_client} )) || exit 1

   while read line; do
       # not interested in CGI lines
       [[ "${line}" =~ \[CGI\] ]] && continue

       # not interested in different clients
       [[ "${line}" =~ \[Client && ! "${line}" =~ ${_client} ]] && continue

	# not interested in different job ids
       [[ "${line}" =~ (\[Job|Send-Document) && ! "${line}" =~ ${_jobid} ]] && continue

       # not interested in different printers
       [[ "${line}" =~ (Create\-Job|Get\-Printer\-Attributes) && ! "${line}" =~ ${PRINTER} ]] && continue

       # D [09/Nov/2021:10:58:19 +0100] [Job 3623832] argv[2]="BOHRO"
       if [[ "${line}" =~ \[Job\ ${_jobid}\]\ argv\[2\]= ]]; then
	   _user=$(cut -d'"' -f2 <<< "${line}")
	   [[ -z "${_user}" ]] && exit 1
       fi

       # not interested in different printers
       [[ "${line}" =~ add_job && ! "${line}" =~ "${_user}" ]] && continue

       echo "${line}"

       # probably last line for a job
       [[ "${line}" =~ \[Job\ ${_jobid}\]\ Unloading\.\.\. ]] && break

   # read since matched Receive print job line till end...
   done < <(sed -n '/Client '${_client}'\]/,$p' "${ERRORLOG}")

}

# main
read -r lpd jobid <<< $(get_jobid)
get_jobdet ${jobid}
```

``` shell
$ ./cups_trace.sh messages-20211110 error_log.O 2021-11-09T10:57:58 psebr00135_ps | grep -vE '(Discarding|cupsd)' | tail -n 20
D [09/Nov/2021:10:58:19 +0100] [Job 3623826] Reading command status...
D [09/Nov/2021:10:58:19 +0100] [Job 3623826] lpd_command returning 0
D [09/Nov/2021:10:58:19 +0100] [Job 3623826] Sending data file (142382 bytes)
D [09/Nov/2021:10:58:19 +0100] [Job 3623826] Spooling job, 0% complete.
D [09/Nov/2021:10:58:19 +0100] [Job 3623826] Set job-printer-state-message to "Spooling job, 0% complete.", current level=INFO
D [09/Nov/2021:10:58:19 +0100] [Job 3623826] Spooling job, 23% complete.
D [09/Nov/2021:10:58:19 +0100] [Job 3623826] Set job-printer-state-message to "Spooling job, 23% complete.", current level=INFO
D [09/Nov/2021:10:58:19 +0100] [Job 3623826] Spooling job, 46% complete.
D [09/Nov/2021:10:58:19 +0100] [Job 3623826] Set job-printer-state-message to "Spooling job, 46% complete.", current level=INFO
D [09/Nov/2021:10:58:19 +0100] [Job 3623826] Spooling job, 69% complete.
D [09/Nov/2021:10:58:19 +0100] [Job 3623826] Set job-printer-state-message to "Spooling job, 69% complete.", current level=INFO
D [09/Nov/2021:10:58:19 +0100] [Job 3623826] Spooling job, 92% complete.
D [09/Nov/2021:10:58:19 +0100] [Job 3623826] Set job-printer-state-message to "Spooling job, 92% complete.", current level=INFO
D [09/Nov/2021:10:58:19 +0100] [Job 3623826] Data file sent successfully.
D [09/Nov/2021:10:58:19 +0100] [Job 3623826] Set job-printer-state-message to "Data file sent successfully.", current level=INFO
D [09/Nov/2021:10:58:19 +0100] [Job 3623826] STATE: +cups-waiting-for-job-completed
D [09/Nov/2021:10:58:19 +0100] [Job 3623826] time-at-completed=1636451899
I [09/Nov/2021:10:58:19 +0100] [Job 3623826] Job completed.
I [09/Nov/2021:10:58:19 +0100] Expiring subscriptions...
D [09/Nov/2021:10:58:20 +0100] [Job 3623826] Unloading...
```

CUPS files decribes: for a job it creates in spool directory at least two files,
at least one data file - eg. `d123456-001` (multidocument jobs could have more
data files with same `d<job id>` prefix) - and a control file - eg. `c123456`.
`testipp` which is not built by default but with `make unittests` could be used
to dissect a control file, an example taken from
[stackoverflow.com](https://stackoverflow.com/questions/53688075/how-to).

``` shell
$ ./testipp /var/spool/cups/c00089

 operation-attributes-tag:

     attributes-charset (charset): utf-8
     attributes-natural-language (naturalLanguage): en-us

 job-attributes-tag:

     printer-uri (uri): ipp://localhost:631/printers/hp
     job-originating-user-name (nameWithoutLanguage): kurtpfeifle
     job-name (nameWithoutLanguage): hosts
     copies (integer): 1
     finishings (enum): none
     job-cancel-after (integer): 10800
     job-hold-until (keyword): no-hold
     job-priority (integer): 50
     job-sheets (1setOf nameWithoutLanguage): none,none
     number-up (integer): 1
     job-uuid (uri): urn:uuid:ca854775-f721-34a5-57e0-b38b8fb0f4c8
     job-originating-host-name (nameWithoutLanguage): localhost
     time-at-creation (integer): 1472022731
     time-at-processing (integer): 1472022731
     time-at-completed (integer): 1472022732
     job-id (integer): 89
     job-state (enum): completed
     job-state-reasons (keyword): processing-to-stop-point
     job-media-sheets-completed (integer): 0
     job-printer-uri (uri): ipp://host13.local:631/printers/hp
     job-k-octets (integer): 1
     document-format (mimeMediaType): text/plain
     job-printer-state-message (textWithoutLanguage): Printing page 1, 4% complete.
     job-printer-state-reasons (keyword): none
```

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
# auditctl -l # list rules
-a never,task
-w /usr/bin/docker -p rwxa -k docker
-w /var/lib/docker -p rwxa -k docker
-w /etc/docker -p rwxa -k docker
-w /usr/lib/systemd/system/docker-registry.service -p rwxa -k docker
-w /usr/lib/systemd/system/docker.service -p rwxa -k docker
-w /var/run/docker.sock -p rwxa -k docker
-w /etc/sysconfig/docker -p rwxa -k docker
-w /etc/sysconfig/docker-network -p rwxa -k docker
-w /etc/sysconfig/docker-registry -p rwxa -k docker
-w /etc/sysconfig/docker-storage -p rwxa -k docker
-w /etc/default/docker -p rwxa -k docker
```

With the above `-a never,task` no audit events would appear. See below:

``` shell
$ man auditctl | col -b | sed -n '/never,task/,/^FILES/{/^FILES/q;p}' | \
  fmt -w 80
       On many systems auditd is configured to install an -a never,task
       rule by default. This rule causes every new process to skip all audit
       rule processing. This is usually done to avoid a small  performance
       overhead  imposed  by syscall auditing. If you want to use auditd,
       you need to remove that rule by deleting 10-no-audit.rules and adding
       10-base-config.rules to the audit rules directory.

       If you have defined audit rules that are not matching when they should,
       check auditctl -l to make sure there is no never,task rule there.
```

Thus update the rules!

``` shell
# sed -i 's/^\-a task\,never/#&/' /etc/audit/rules.d/audit.rules # uncomment default
# augenrules --check
# augenrules --load
# auditctl -l
```

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

#### passwords

to generate encrypted/salted password use `mkpasswd`

``` shell
mkpasswd -m sha-512 -s <<< 'pass123'
$6$AOYSAh/LyR4A.Dz.$A/HSpublK0yEObt9h7MQVOMOp7AKTrA0QxYjHfH/fIM27Zv0yIT1bxoIxPSZWxd8yB6O9OqUYyjDoGt2MyAgd1

python3 -c 'import crypt; print(crypt.crypt("pass123", crypt.mksalt(crypt.METHOD_SHA512)))'
$6$zyuGj55qkPCh/zht$PDk60osb/mzE6xCvJx/X3uDWtU/8jGRefSQHIjCDdYsDEiKcZE3XmX/0dW7Eyz6VUIujn5aJLVslsbywA7su0.
```

### sudo

#### AD users/groups

See [Configure sudo authentication for Active Directory
group](https://www.suse.com/support/kb/doc/?id=000018877).

- winbind based authentication

IIUC if not quoted, then use '\\' as separator and '\' before whitespaces.

  ```
  # AD user
  "<DOMAIN>\<user>" ALL=(ALL) ALL
  # AD group
  "<DOMAIN>\<group name>" ALL=(ALL) ALL
  ```
- sssd based authentication
  ```
  # AD group
  "<group name>@<realm>" ALL=(ALL) ALL
  ```

#### debugging

``` shell
# grep '^Debug' /etc/sudo.conf
Debug sudo /var/log/sudo_debug.log all@debug
Debug sudoers.so /var/log/sudo_debug.log all@debug
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
$ openssl crl2pkcs7 -nocrl -certfile /etc/ssl/ca-bundle.pem | \
  openssl pkcs7 -print_certs -text -noout | \
  grep -Po '(\K(Subject:.*)|\K(Not (Before|After) *:.*))' | \
  grep -A 2 Starfield
Subject: C=US, O=Starfield Technologies, Inc., OU=Starfield Class 2 Certification Authority
Not Before: Sep  1 00:00:00 2009 GMT
Not After : Dec 31 23:59:59 2037 GMT
Subject: C=US, ST=Arizona, L=Scottsdale, O=Starfield Technologies, Inc., CN=Starfield Root Certificate Authority - G2
Not Before: Sep  1 00:00:00 2009 GMT
Not After : Dec 31 23:59:59 2037 GMT
Subject: C=US, ST=Arizona, L=Scottsdale, O=Starfield Technologies, Inc., CN=Starfield Services Root Certificate Authority - G2
Not Before: Oct 25 08:30:35 2006 GMT
Not After : Oct 25 08:30:35 2036 GMT

# an alternative

$ awk -v cmd='openssl x509 -noout -subject -startdate -enddate' \
  '/BEGIN/{close(cmd)}; { print | cmd }' < /etc/ssl/ca-bundle.pem  2>/dev/null \
  | grep -A 2 'Starfield'
subject=C = US, O = "Starfield Technologies, Inc.", OU = Starfield Class 2 Certification Authority
notBefore=Jun 29 17:39:16 2004 GMT
notAfter=Jun 29 17:39:16 2034 GMT
subject=C = US, ST = Arizona, L = Scottsdale, O = "Starfield Technologies, Inc.", CN = Starfield Root Certificate Authority - G2
notBefore=Sep  1 00:00:00 2009 GMT
notAfter=Dec 31 23:59:59 2037 GMT
subject=C = US, ST = Arizona, L = Scottsdale, O = "Starfield Technologies, Inc.", CN = Starfield Services Root Certificate Authority - G2
notBefore=Sep  1 00:00:00 2009 GMT
notAfter=Dec 31 23:59:59 2037 GMT
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

### bash

- test via regex: `<string> =~ <regex_expr>`
  ``` shell
  man bash | col -b | sed -n '/=~/,/^ *$/{/^ *$/q;p}' | fmt -w 80 | sed 's/\- //'
              An  additional  binary  operator, =~, is available, with the
              same precedence as == and !=.  When it is used, the string
              to the right of the operator is considered a POSIX extended
              regular expression and matched accordingly (using the POSIX
              regcomp and regexec interfaces usually described in regex(3)).
              The return value is 0 if the string matches the pattern, and
              1 otherwise.  If the regular expression  is  syntactically
              incorrect, the  conditional  expression's return value is 2.
              If the nocasematch shell option is enabled, the match is
              performed without regard to the case of alphabetic characters.
              Any part of the pattern may be quoted to force the quoted
              portion to be matched as a string.  Bracket expressions in
              regular expressions must be treated carefully, since normal
              quoting characters lose their meanings between brackets.  If the
              pattern is stored in  a shell variable, quoting the variable
              expansion forces the entire pattern to be matched as a string.
  ```
  An example:
  ``` shell
  $ [[ ${URL} =~ ([^:]+)://([^/]+)(.*) ]]
  $  echo ${BASH_REMATCH[*]}
  https://www.kernel.org/doc/html/v5.12/networking/bonding.html https www.kernel.org /doc/html/v5.12/networking/bonding.html
  $ read -r url protocol host path <<< $(echo ${BASH_REMATCH[*]})
  $ echo $url $protocol $host $path | tr ' ' '\n'
  https://www.kernel.org/doc/html/v5.12/networking/bonding.html
  https
  www.kernel.org
  /doc/html/v5.12/networking/bonding.html
  ```
- list functions: `declare -F`
- printing command output/multiline content saved in a variable
  ``` shell
  $ f="fafafda
  > adffd
  > adfadf
  > adfafd
  > afd"
  $ echo $f
  fafafda adffd adfadf adfafd afd
  $ echo "$f"
  fafafda
  adffd
  adfadf
  adfafd
  afd
  ```
- multiple columns into one: `echo one two three | xargs -n1`
- show files' content side by side: `pr -m -f -Tt -w 200 file1 file2`
- multiline variable in shell script
``` shell
read -r -d '' VAR << EOM
This is line 1.
This is line 2.
Line 3.
EOM

echo "${VAR}"
```
- using BASH function in `find`
   ``` shell
   $ type _kdump
   _kdump is a function
   _kdump ()
   {
       sed -n '/find -L/,/^ *$/{/^ *$/q;p}' $1 | tail -n1 | grep --color=auto -qv '/var/crash/$' && echo $1
   }
   $ export -f _kdump
   $ find ../../ -type f -name crash.txt -exec bash -c \
     '_kdump "$@"' bash {} {} \;
   ```
- inherit `set -x` via *SHELLOPTS*
  ``` shell
  $ man bash | col -b | sed -rn '/^ *SHELLOPTS/,/^ *[[:upper:]]/p' | \
      head -n -1 | fmt -w80
       SHELLOPTS
              A colon-separated list of enabled shell options.  Each word
              in the list is a valid argument for the -o option to the set
              builtin command (see SHELL BUILTIN COMMANDS below).  The options
              appearing in SHELLOPTS are those reported as on by set -o.
              If this variable is in the environment when bash starts up,
              each shell option in the list will be enabled before reading
              any startup files.  This variable is read-only.
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

do not print content of a file till pattern (excl/incl):

``` shell
$ cat /tmp/input 
jedna
dva
tri
ctyri
pet

$ sed '1,/tri/d' /tmp/input  # excluding the pattern
ctyri
pet
$ sed '/tri/,$!d' /tmp/input # including the pattern
tri
ctyri
pet
```

### tmux

#### tmate

[`tmate`](https://tmate.io/) does not seem to be working with proxy jumps specified
in `ssh_config`, thus a workaround is to use eg. `proxychains4`.

``` shell
$ cat /etc/proxychains.conf
[proxychains]
strict_chain
remote_dns_subnet 10
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
localnet 192.168.0.0/255.255.0.0
[ProxyList]
socks5  192.168.124.1 9999

# to use custom tmate server
$ cat ~/.tmate.conf
set -g tmate-server-host "tmate.example.com"
set -g tmate-server-port "23"

# fingerprints in SHA256 format for tmate > 2.2.*
#set -g tmate-server-rsa-fingerprint "SHA256:a6o2NWaAGRzeWq8H7zia5v/3y3hkzre9YJug5vaKjYo"

# fingerprints in MD5 format for tmate 2.2.* (as in Leap 15.2)
set -g tmate-server-rsa-fingerprint "91:cf:4f:cd:45:6b:c5:e0:9a:54:2e:90:7e:61:62:e2"
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

### strace

``` shell
# strace -f -t -o /tmp/strace.txt -e trace=%file,%process <command> # file
                                                                    # and exec
                                                                    # operations
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

#### disk

QEMU supports many [*blockdev*/*disk image*](
  https://qemu-project.gitlab.io/qemu/system/qemu-block-drivers.html) formats

``` shell
# qemu-img --help | grep -Po '^Supported formats: \K(.*)' | xargs -n 1 | sort
blkdebug
blklogwrites
blkverify
bochs
cloop
compress
copy-on-read
dmg
file
ftp
ftps
gluster
host_cdrom
host_device
http
https
iscsi
iser
luks
nbd
nfs
null-aio
null-co
nvme
preallocate
qcow
qcow2
qed
quorum
raw
rbd
replication
ssh
throttle
vdi
vhdx
vmdk
vpc
vvfat
```

Some *blockdev* types are supported via external libraries

``` shell
# ls -1 /usr/lib64/qemu/block*
/usr/lib64/qemu/block-curl.so
/usr/lib64/qemu/block-iscsi.so
/usr/lib64/qemu/block-rbd.so

# rpm -qf /usr/lib64/qemu/block*
qemu-block-curl-6.0.0-29.1.x86_64
qemu-block-iscsi-6.0.0-29.1.x86_64
qemu-block-rbd-6.0.0-29.1.x86_64
```

##### iscsi

QEMU default built-in initiator name is *iqn.2008-11.org.linux-kvm[:uuid | vmname]*. One can
change it per whole VM or per initiator, see [QEMU block drivers reference
](https://qemu-project.gitlab.io/qemu/system/qemu-block-drivers.html#iscsi-luns).

``` shell
# qemu-system-x86_64 --help | sed -n '/\-iscsi/,/^ *$/{/^ *$/q;p}'
-iscsi [user=user][,password=password]
       [,header-digest=CRC32C|CR32C-NONE|NONE-CRC32C|NONE
       [,initiator-name=initiator-iqn][,id=target-iqn]
       [,timeout=timeout]
                iSCSI session parameters
```

#### qemu-nbd

``` shell
qemu-nbd --connect=/dev/nbd0 <qemu_image> # connect eg. a qcow2 image
qemu-nbd -d /dev/nbd0
```

### libguestfs

#### guestfish

``` shell
guestfish -a sles12sp4-template.qcow2 -m /dev/sda2:/::btrfs

Welcome to guestfish, the guest filesystem shell for
editing virtual machine filesystems and disk images.

Type: ‘help’ for help on commands
      ‘man’ to read the manual
      ‘quit’ to quit the shell

><fs> list-filesystems
/dev/sda1: swap
/dev/sda2: btrfs
btrfsvol:/dev/sda2/@: btrfs
btrfsvol:/dev/sda2/@/.snapshots: btrfs
btrfsvol:/dev/sda2/@/boot/grub2/i386-pc: btrfs
btrfsvol:/dev/sda2/@/boot/grub2/x86_64-efi: btrfs
btrfsvol:/dev/sda2/@/opt: btrfs
btrfsvol:/dev/sda2/@/srv: btrfs
btrfsvol:/dev/sda2/@/tmp: btrfs
btrfsvol:/dev/sda2/@/usr/local: btrfs
btrfsvol:/dev/sda2/@/var/cache: btrfs
btrfsvol:/dev/sda2/@/var/crash: btrfs
btrfsvol:/dev/sda2/@/var/lib/libvirt/images: btrfs
btrfsvol:/dev/sda2/@/var/lib/machines: btrfs
btrfsvol:/dev/sda2/@/var/lib/mailman: btrfs
btrfsvol:/dev/sda2/@/var/lib/mariadb: btrfs
btrfsvol:/dev/sda2/@/var/lib/mysql: btrfs
btrfsvol:/dev/sda2/@/var/lib/named: btrfs
btrfsvol:/dev/sda2/@/var/lib/pgsql: btrfs
btrfsvol:/dev/sda2/@/var/log: btrfs
btrfsvol:/dev/sda2/@/var/opt: btrfs
btrfsvol:/dev/sda2/@/var/spool: btrfs
btrfsvol:/dev/sda2/@/var/tmp: btrfs
btrfsvol:/dev/sda2/@/.snapshots/2/snapshot: btrfs
/dev/sda3: xfs
><fs> mount-options subvol=/@/var/log /dev/sda2 /var/log
><fs> mountpoints
/dev/sda2: /
/dev/sda2: /var/log
><fs> truncate /var/log/pbl.log
><fs> truncate /var/log/alternatives.log
><fs> truncate /var/log/zypp/history
><fs> exit
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
    <dnsmasq:option value='dhcp-option=210,"/"'/>
  </dnsmasq:options>
</network>
```

See `<dnsmasq:option value='dhcp-option=210,"/"'/>` above! This is to
solve the issue with *PathPrefix* when booting [*pxelinux*](#pxelinux) from
*GRUB2*.

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

### vmware

#### esxi

##### cli

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

##### logs

See [ESXi Log File
Locations](https://docs.vmware.com/en/VMware-vSphere/6.7/com.vmware.vsphere.monitoring.doc/GUID-832A2618-6B11-4A28-9672-93296DA931D0.html)
for ESXi logs details.

##### ssh

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

##### network trace

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

##### esxi on KVM

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

## windows

### easy passwords

See https://serverfault.com/a/19613/451558.

### Active Directory

See https://www.virtualgyanis.com/post/step-by-step-how-to-install-and-configure-domain-controller-on-windows-server-2019 .

``` shell
> dcdiag

Directory Server Diagnosis

Performing initial setup:
   Trying to find home server...
   Home Server = win2k19-01
   * Identified AD Forest.
   Done gathering initial info.

Doing initial required tests

   Testing server: Default-First-Site-Name\WIN2K19-01
      Starting test: Connectivity
         The host 40adac3c-dd9c-462c-95b0-c347bc1195e7._msdcs.HOME.ARPA could not be resolved to an IP address. Check the
         DNS server, DHCP, server name, etc.
         Got error while checking LDAP and RPC connectivity. Please check your firewall settings.
         ......................... WIN2K19-01 failed test Connectivity

Doing primary tests

   Testing server: Default-First-Site-Name\WIN2K19-01
      Skipping all tests, because server WIN2K19-01 is not responding to directory service requests.


   Running partition tests on : ForestDnsZones
      Starting test: CheckSDRefDom
         ......................... ForestDnsZones passed test CheckSDRefDom
      Starting test: CrossRefValidation
         ......................... ForestDnsZones passed test CrossRefValidation

   Running partition tests on : DomainDnsZones
      Starting test: CheckSDRefDom
         ......................... DomainDnsZones passed test CheckSDRefDom
      Starting test: CrossRefValidation
         ......................... DomainDnsZones passed test CrossRefValidation

   Running partition tests on : Schema
      Starting test: CheckSDRefDom
         ......................... Schema passed test CheckSDRefDom
      Starting test: CrossRefValidation
         ......................... Schema passed test CrossRefValidation

   Running partition tests on : Configuration
      Starting test: CheckSDRefDom
         ......................... Configuration passed test CheckSDRefDom
      Starting test: CrossRefValidation
         ......................... Configuration passed test CrossRefValidation

   Running partition tests on : HOME
      Starting test: CheckSDRefDom
         ......................... HOME passed test CheckSDRefDom
      Starting test: CrossRefValidation
         ......................... HOME passed test CrossRefValidation

   Running enterprise tests on : HOME.ARPA
      Starting test: LocatorCheck
         ......................... HOME.ARPA passed test LocatorCheck
      Starting test: Intersite
         ......................... HOME.ARPA passed test Intersite
```

``` shell
$ dig +short +noall +answer @192.168.122.200 _ldap._tcp.home.arpa. SRV
0 100 389 win2k19-01.HOME.ARPA.
```

### OpenSSH server

See https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse

