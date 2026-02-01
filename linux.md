# Linux cheat-sheet

## ACL

- *mask* is maximum permission for users (other than the owner) and groups!
- `chmod` incluences mask of ACL file/dir!
- default ACL of a directory for inheritance

## Authentication

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

### nscd

Do not use `nscd` with *sssd* or *winbind*. See [7.8. USING NSCD WITH SSSD](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/system-level_authentication_guide/usingnscd-sssd).

``` shell
enable-cache hosts yes
enable-cache passwd no
enable-cache group no
enable-cache netgroup no
enable-cache services no
```

Sometimes is also needed to increase `max-db-size` for some databases.


### OpenSSH

How SCP protocol works, in [WaybackMachine
archive](https://web.archive.org/web/20170215184048/https://blogs.oracle.com/janp/entry/how_the_scp_protocol_works).


### PAM

An example of tracing a user login with expired password, see `pam_sm_acct_mgmt(3)`.

``` shell
$ ltrace -ft -x '*@pam_unix.so' -L /usr/sbin/sshd -p 2222 -D
[pid 9562] 09:30:16 --- Called exec() ---
[pid 9564] 09:30:17 pam_sm_authenticate@pam_unix.so(0x5610d5ef2ff0, 1, 1, [ "try_first_pass" ]) = SUCCESS
[pid 9564] 09:30:20 pam_sm_acct_mgmt@pam_unix.so(0x5610d5ef2ff0, 0, 1, [ "try_first_pass" ]) = NEW_AUTHTOK_REQD
[pid 9564] 09:30:20 pam_sm_chauthtok@pam_unix.so(0x5610d5ef2ff0, 0x4020, 4, 0x5610d5ee22c0
```


### SSSD


#### SSSD with LDAP backend

The bind password can be obfuscated with `sss_offuscate -s -d
<DOMAIN>`, still do not make it world readable!

``` shell
$ grep -Pv '^\s*($|#)' /etc/sssd/sssd.conf
[sssd]
config_file_version = 2
services = nss, pam
domains = LDAP
[nss]
[pam]
[domain/LDAP]
id_provider = ldap
auth_provider = ldap
ldap_uri = ldaps://127.0.0.1
ldap_search_base = dc=example,dc=com
ldap_default_bind_dn = cn=Manager,dc=example,dc=com
ldap_tls_reqcert = allow
ldap_schema = rfc2307bis
access_provider = permit
sudo_provider = ldap
chpass_provider = ldap
autofs_provider = ldap
resolver_provider = ldap
ldap_default_authtok = AAAQAGGoVoHtJJrfe9zbbZe331Uc2CC8gm6TL27QlD9PZRbkYjYbcvOv3JjDEV2IIuxLeISWK+yfoSOBD41c34HkQi0AAQID
ldap_default_authtok_type = obfuscated_password
```

``` shell
$ systemd-cgls -u sssd.service
Unit sssd.service (/system.slice/sssd.service):
├─3017 /usr/sbin/sssd -i --logger=files
├─3018 /usr/libexec/sssd/sssd_be --domain LDAP --uid 0 --gid 0 --logger=files
├─3019 /usr/libexec/sssd/sssd_nss --uid 0 --gid 0 --logger=files
└─3020 /usr/libexec/sssd/sssd_pam --uid 0 --gid 0 --logger=files
```

#### SSSD troubleshooting

*sssd* validates CN in TLS cert!

``` shell
journalctl -u sssd -p err --since='2021-06-10 15:49:37' --no-pager
-- Logs begin at Thu 2021-06-10 13:35:58 CEST, end at Thu 2021-06-10 15:50:56 CEST. --
Jun 10 15:49:37 localhost.localdomain sssd[be[ldap]][17206]: Could not start TLS encryption. TLS: hostname does not match CN in peer certificate
Jun 10 15:50:50 localhost.localdomain sssd[be[ldap]][17206]: Could not start TLS encryption. TLS: hostname does not match CN in peer certificate
Jun 10 15:50:52 localhost.localdomain sssd[be[ldap]][17206]: Could not start TLS encryption. TLS: hostname does not match CN in peer certificate
Jun 10 15:50:56 localhost.localdomain sssd[be[ldap]][17206]: Could not start TLS encryption. TLS: hostname does not match CN in peer certificate
```

Invalid credentials to LDAP server:

``` shell
   *  (2022-10-04 14:18:48): [be[LDAP]] [simple_bind_done] (0x0400): Bind result: Invalid credentials(49), no errmsg set
   *  (2022-10-04 14:18:48): [be[LDAP]] [sdap_op_destructor] (0x2000): Operation 2 finished
   *  (2022-10-04 14:18:48): [be[LDAP]] [sdap_cli_connect_recv] (0x0040): Unable to establish connection [1432158227]: Authentication Failed

# or with more debug level

(2022-10-04 14:17:06): [be[LDAP]] [sdap_call_op_callback] (0x20000): Handling LDAP operation [2][server: [127.0.0.1:636] simple bind: [cn=Manager,dc=example,dc=com]] took [0.217] milliseconds.
(2022-10-04 14:17:06): [be[LDAP]] [simple_bind_done] (0x1000): Server returned no controls.
(2022-10-04 14:17:06): [be[LDAP]] [simple_bind_done] (0x0400): Bind result: Invalid credentials(49), no errmsg set
(2022-10-04 14:17:06): [be[LDAP]] [sdap_op_destructor] (0x2000): Operation 2 finished
(2022-10-04 14:17:06): [be[LDAP]] [sdap_cli_connect_recv] (0x0040): Unable to establish connection [1432158227]: Authentication Failed
```

LDAP server not reachable:

``` shell
(2022-10-04 14:25:43): [be[LDAP]] [sssd_async_connect_done] (0x0020): connect failed [111][Connection refused].
   *  (2022-10-04 14:25:43): [be[LDAP]] [sssd_async_socket_init_send] (0x4000): Using file descriptor [19] for the connection.
   *  (2022-10-04 14:25:43): [be[LDAP]] [sssd_async_socket_init_send] (0x0400): Setting 6 seconds timeout [ldap_network_timeout] for connecting
   *  (2022-10-04 14:25:43): [be[LDAP]] [sssd_async_connect_done] (0x0020): connect failed [111][Connection refused].
(2022-10-04 14:25:43): [be[LDAP]] [sssd_async_socket_init_done] (0x0020): sdap_async_sys_connect request failed: [111]: Connection refused.(2022-10-04 14:25:43): [be[LDAP]] [sss_ldap_init_sys_connect_done] (0x0020): sssd_async_socket_init request failed: [111]: Connection refused.
   *  (2022-10-04 14:25:43): [be[LDAP]] [sssd_async_socket_init_done] (0x0020): sdap_async_sys_connect request failed: [111]: Connection refused.   *  (2022-10-04 14:25:43): [be[LDAP]] [sssd_async_socket_state_destructor] (0x0400): closing socket [19]
   *  (2022-10-04 14:25:43): [be[LDAP]] [sss_ldap_init_sys_connect_done] (0x0020): sssd_async_socket_init request failed: [111]: Connection refused.
(2022-10-04 14:26:58): [be[LDAP]] [sssd_async_connect_done] (0x0020): [RID#4] connect failed [111][Connection refused].
   *  (2022-10-04 14:26:58): [be[LDAP]] [sssd_async_socket_init_send] (0x4000): [RID#4] Using file descriptor [21] for the connection.
   *  (2022-10-04 14:26:58): [be[LDAP]] [sssd_async_socket_init_send] (0x0400): [RID#4] Setting 6 seconds timeout [ldap_network_timeout] for connecting
   *  (2022-10-04 14:26:58): [be[LDAP]] [sssd_async_connect_done] (0x0020): [RID#4] connect failed [111][Connection refused].
(2022-10-04 14:26:58): [be[LDAP]] [sssd_async_socket_init_done] (0x0020): [RID#4] sdap_async_sys_connect request failed: [111]: Connection refused.(2022-10-04 14:26:58): [be[LDAP]] [sss_ldap_init_sys_connect_done] (0x0020): [RID#4] sssd_async_socket_init request failed: [111]: Connection refused.
   *  (2022-10-04 14:26:58): [be[LDAP]] [sssd_async_socket_init_done] (0x0020): [RID#4] sdap_async_sys_connect request failed: [111]: Connection refused.   *  (2022-10-04 14:26:58): [be[LDAP]] [sssd_async_socket_state_destructor] (0x0400): [RID#4] closing socket [21]
   *  (2022-10-04 14:26:58): [be[LDAP]] [sss_ldap_init_sys_connect_done] (0x0020): [RID#4] sssd_async_socket_init request failed: [111]: Connection refused.
(2022-10-04 14:27:00): [be[LDAP]] [sssd_async_connect_done] (0x0020): [RID#5] connect failed [111][Connection refused].
(2022-10-04 14:27:00): [be[LDAP]] [sssd_async_socket_init_done] (0x0020): [RID#5] sdap_async_sys_connect request failed: [111]: Connection refused.   *  ... skipping repetitive backtrace ...
(2022-10-04 14:27:00): [be[LDAP]] [sss_ldap_init_sys_connect_done] (0x0020): [RID#5] sssd_async_socket_init request failed: [111]: Connection refused.
(2022-10-04 14:27:04): [be[LDAP]] [sssd_async_connect_done] (0x0020): [RID#6] connect failed [111][Connection refused].
(2022-10-04 14:27:04): [be[LDAP]] [sssd_async_socket_init_done] (0x0020): [RID#6] sdap_async_sys_connect request failed: [111]: Connection refused.   *  ... skipping repetitive backtrace ...
(2022-10-04 14:27:04): [be[LDAP]] [sss_ldap_init_sys_connect_done] (0x0020): [RID#6] sssd_async_socket_init request failed: [111]: Connection refused.
```

Not maching `ldap_access_filter` (note that with default debug level
you won't be able to figure out it!, use higher debug leve, eg. '6' l!!!):

```
(2023-02-17 15:36:56): [be[ldap]] [dp_get_options] (0x0400): Option ldap_access_filter has value (memberOf=cn=nonexistent,ou=groups,dc=example,dc=com)
...
(2023-02-17 15:37:05): [be[ldap]] [sdap_access_filter_send] (0x0400): [RID#8] Performing access filter check for user [testovic@ldap]
(2023-02-17 15:37:05): [be[ldap]] [sdap_access_filter_send] (0x0400): [RID#8] Checking filter against LDAP
(2023-02-17 15:37:05): [be[ldap]] [sdap_get_generic_ext_step] (0x0400): [RID#8] calling ldap_search_ext with [(&(uid=testovic)(objectclass=posixAccount)(memberOf=cn=nonexistent,ou=groups,dc=example,dc=com))][uid=testovic,ou=people,dc=example,dc=com].
(2023-02-17 15:37:05): [be[ldap]] [sdap_get_generic_op_finished] (0x0400): [RID#8] Search result: Success(0), no errmsg set
(2023-02-17 15:37:05): [be[ldap]] [sdap_access_filter_done] (0x0100): [RID#8] User [testovic@ldap] was not found with the specified filter. Denying access.
(2023-02-17 15:37:05): [be[ldap]] [sdap_access_filter_done] (0x0400): [RID#8] Access denied by online lookup
(2023-02-17 15:37:05): [be[ldap]] [sysdb_set_entry_attr] (0x0200): [RID#8] Entry [name=testovic@ldap,cn=users,cn=ldap,cn=sysdb] has set [cache, ts_cache] attrs.
(2023-02-17 15:37:05): [be[ldap]] [sdap_access_done] (0x0400): [RID#8] Access was denied.
```

and now working example:

```
(2023-02-17 15:39:58): [be[ldap]] [dp_get_options] (0x0400): Option ldap_access_filter has value (memberOf=cn=demo_group,ou=groups,dc=example,dc=com)
...
(2023-02-17 15:40:04): [be[ldap]] [sdap_access_filter_send] (0x0400): [RID#9] Performing access filter check for user [testovic@ldap]
(2023-02-17 15:40:04): [be[ldap]] [sdap_access_filter_send] (0x0400): [RID#9] Checking filter against LDAP
(2023-02-17 15:40:04): [be[ldap]] [sdap_get_generic_ext_step] (0x0400): [RID#9] calling ldap_search_ext with [(&(uid=testovic)(objectclass=posixAccount)(memberOf=cn=demo_group,ou=groups,dc=example,dc=com))][uid=testovic,ou=people,dc=example,dc=com].
(2023-02-17 15:40:04): [be[ldap]] [sdap_get_generic_op_finished] (0x0400): [RID#9] Search result: Success(0), no errmsg set
(2023-02-17 15:40:04): [be[ldap]] [sdap_access_filter_done] (0x0400): [RID#9] Access granted by online lookup
(2023-02-17 15:40:04): [be[ldap]] [sysdb_set_entry_attr] (0x0200): [RID#9] Entry [name=testovic@ldap,cn=users,cn=ldap,cn=sysdb] has set [cache, ts_cache] attrs.
(2023-02-17 15:40:04): [be[ldap]] [sdap_account_expired_rhds] (0x0400): [RID#9] Performing RHDS access check for user [testovic@ldap]
```

- `sss_cache -E` invalidate all cached entries, with the exception of sudo rules
- `sss_cache -u <username>`, invalidate a specific user entries
- `systemctl stop sssd; rm -rf /var/lib/sss/db/*; systemctl restart sssd`

Note that *sssd* caches, so do not run `nscd` caching `passwd` and `group` DBs.


## Boot loaders


### GRUB

``` shell
GRUB_CMDLINE_LINUX                     <--+-- appended for normal & recovery mode
GRUB_CMDLINE_LINUX_DEFAULT             <--+-- appended for normal mode only
GRUB_CMDLINE_LINUX_RECOVERY            <--+-- appended for recovery mode only
GRUB_CMDLINE_LINUX_XEN_REPLACE         <--+-- replaces all values in GRUB_CMDLINE_LINUX
GRUB_CMDLINE_LINUX_XEN_REPLACE_DEFAULT <--+-- replaces all values in GRUB_CMDLINE_LINUX_DEFAULT
GRUB_CMDLINE_XEN                       <--+-- appended for Xen kernel only
GRUB_CMDLINE_XEN_DEFAULT               <--+-- appended for Xen kernel normal mode only
```

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


#### grub2-once

`grub2-once` allows change of next-boot menu entry.

``` shell
$ grep -Pv '^#{2,}' /boot/grub2/grubenv
# GRUB Environment Block
# WARNING: Do not edit this file by tools other than grub2-editenv!!!
saved_entry=SLES 15-SP4

$ grub2-once list | head

WARNING: Detected GRUB environment block on lvm device
list will remain the default boot entry until manually cleared with:
    grub2-editenv /boot/grub2/grubenv unset next_entry

$ grub2-once --list | head
     0 SLES 15-SP4
     1 Advanced options for SLES 15-SP4>SLES 15-SP4, with Linux 5.14.21-150400.24.46-default
     2 Advanced options for SLES 15-SP4>SLES 15-SP4, with Linux 5.14.21-150400.24.46-default (recovery mode)
     3 Advanced options for SLES 15-SP4>SLES 15-SP4, with Linux 5.14.21-150400.24.41-default
     4 Advanced options for SLES 15-SP4>SLES 15-SP4, with Linux 5.14.21-150400.24.41-default (recovery mode)
     5 Advanced options for SLES 15-SP4>SLES 15-SP4, with Linux 5.14.21-150400.24.38-default
     6 Advanced options for SLES 15-SP4>SLES 15-SP4, with Linux 5.14.21-150400.24.38-default (recovery mode)
     7 UEFI Firmware Settings
     8 Start bootloader from a read-only snapshot>*SLES15-SP4 (5.14.21-150400.24.38,2023-02-22T09:46,post,zypp(zypper))
     9 Start bootloader from a read-only snapshot>*SLES15-SP4 (5.14.21-150400.24.46,2023-02-22T09:45,pre,zypp(zypper))

$ grub2-once 5

WARNING: Detected GRUB environment block on lvm device
Advanced options for SLES 15-SP4>SLES 15-SP4, with Linux 5.14.21-150400.24.38-default will remain the default boot entry until manually cleared with:
    grub2-editenv /boot/grub2/grubenv unset next_entry

$ grep -Pv '^#{2,}' /boot/grub2/grubenv
# GRUB Environment Block
# WARNING: Do not edit this file by tools other than grub2-editenv!!!
saved_entry=SLES 15-SP4
next_entry=Advanced options for SLES 15-SP4>SLES 15-SP4, with Linux 5.14.21-150400.24.38-default

$ grub2-editenv /boot/grub2/grubenv unset next_entry

$ grep -Pv '^#{2,}' /boot/grub2/grubenv
# GRUB Environment Block
# WARNING: Do not edit this file by tools other than grub2-editenv!!!
saved_entry=SLES 15-SP4
```

Another "workaround" is to use `awk`:

``` shell
$ awk -F\' '$1 == "menuentry " || $1=="submenu " {print i++ " : " $2}; /^(\t)?menuentry / { if(i-1) print "\t" i-1">"j++ " : " $2};' /boot/grub2/grub.cfg
0 : SLES 15-SP3
1 : Advanced options for SLES 15-SP3
        1>0 : SLES 15-SP3, with Linux 5.3.18-150300.59.164-default
        1>1 : SLES 15-SP3, with Linux 5.3.18-150300.59.164-default (recovery mode)
        1>2 : SLES 15-SP3, with Linux 5.3.18-150300.59.158-default
        1>3 : SLES 15-SP3, with Linux 5.3.18-150300.59.158-default (recovery mode)
```


#### GRUB internals


##### GRUB on gpt/bios

What makes "core.img" on GPT/BIOS?

``` shell
# diskboot.img

$ stat -c '%s' /usr/share/grub2/i386-pc/diskboot.img
512

$ xxd /usr/share/grub2/i386-pc/diskboot.img | head -n2
00000000: 5256 be1b 81e8 3901 5ebf f481 668b 2d83  RV....9.^...f.-.
00000010: 7d08 000f 84e2 0080 7cff 0074 4666 8b1d  }.......|..tFf..

$ sfdisk -d /dev/vda 2>/dev/null | grep vda1
/dev/vda1 : start=        2048, size=       16384, type=21686148-6449-6E6F-744E-656564454649, uuid=62E78F72-C9A9-4179-8E35-7F078D1229BB

$ xxd /dev/vda1 | head -n2
00000000: 5256 be1b 81e8 3901 5ebf f481 668b 2d83  RV....9.^...f.-.
00000010: 7d08 000f 84e2 0080 7cff 0074 4666 8b1d  }.......|..tFf..

# lzma_decompressor (comments inline)

$ stat -c '%s' /usr/share/grub2/i386-pc/lzma_decompress.img 
2880

$ xxd /usr/share/grub2/i386-pc/lzma_decompress.img | head -n2
00000000: ea1c 8200 0000 0000 0000 0000 0000 0000  ................
00000010: 0000 0000 7a07 0000 ffff ff00 fa31 c08e  ....z........1..

$ xxd -s 512 /dev/vda1 | head -n2
00000200: ea1c 8200 0000 0000 33db 0000 00c7 0100  ........3.......    <---+--- iiuc small difference is ok here, the .img is a "template"
00000210: 8deb 0000 7a07 0000 ffff ff00 fa31 c08e  ....z........1..

# a real core.img ???

$ xxd -s $((512 + 2880 )) /boot/grub2/i386-pc/core.img | head -n2
00000d40: 0044 a383 df0c b34d 0dcf b8d6 3fcd fe54  .D.....M....?..T
00000d50: 1ccd aafa 1ff5 c09e dc2a faad 120b 09a8  .........*......

$ xxd -s $((512 + 2880))  /dev/vda1 | head -n2
00000d40: 0044 a383 df0c b34d 0dcf b8d6 3fcd fe54  .D.....M....?..T
00000d50: 1ccd aafa 1ff5 c09e dc2a faad 120b 09a8  .........*......

$ xxd -s $((512 + 2880))  /dev/vda1 | grep -m 1 -B 2 '0000 0000'
0001d3e0: 218a 1e94 0260 06bd dba9 a46a 0903 2c11  !....`.....j..,.
0001d3f0: efc9 5a39 6c0c fe5d 0367 8590 58e9 ee53  ..Z9l..].g..X..S
0001d400: 0000 0000 0000 0000 0000 0000 0000 0000  ................

^^ needs clarification !!!
```


#### GRUB via PXE

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

An example of a PCAP with
[TFTP](https://www.wireshark.org/docs/dfref/t/tftp.html):

``` shell
$ tshark -r /tmp/example.pcap -Y 'tftp.opcode == 1' -T fields -e tftp.source_file
grub/shim.efi
revocations.efi
grub.efi
```

Extracting `grub/shim.efi`:

``` shell
$ cat > /tmp/extract.py <<EOF
#!/usr/bin/env python3
import sys
from binascii import unhexlify

blocks = {}

# Read from stdin line-by-line
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    parts = line.split()
    if len(parts) != 2:
        continue  # skip malformed lines
    try:
        block = int(parts[0])
        data = unhexlify(parts[1])
        blocks[block] = data
    except Exception:
        continue  # skip invalid lines

# Write blocks in order to stdout
for block in sorted(blocks):
    sys.stdout.buffer.write(blocks[block])
EOF

$ tshark -r /tmp/example.pcap \
  -Y 'tftp.opcode == 3' \
  -T fields \
  -e tftp.block \
  -e data.data | \
  python3 /tmp/data.py > /tmp/shim.efi

$ objdump -s -j .sbat /tmp/shim.efi
 
/tmp/shim.efi:     file format pei-x86-64
 
Contents of section .sbat:
 d4000 73626174 2c312c53 42415420 56657273  sbat,1,SBAT Vers
 d4010 696f6e2c 73626174 2c312c68 74747073  ion,sbat,1,https
 d4020 3a2f2f67 69746875 622e636f 6d2f7268  ://github.com/rh
 d4030 626f6f74 2f736869 6d2f626c 6f622f6d  boot/shim/blob/m
 d4040 61696e2f 53424154 2e6d640a 7368696d  ain/SBAT.md.shim
 d4050 2c342c55 45464920 7368696d 2c736869  ,4,UEFI shim,shi
 d4060 6d2c312c 68747470 733a2f2f 67697468  m,1,https://gith
 d4070 75622e63 6f6d2f72 68626f6f 742f7368  ub.com/rhboot/sh
 d4080 696d0a73 68696d2e 736c652c 312c5355  im.shim.sle,1,SU
 d4090 5345204c 696e7578 20456e74 65727072  SE Linux Enterpr
 d40a0 6973652c 7368696d 2c31352e 382c6d61  ise,shim,15.8,ma
 d40b0 696c3a73 65637572 69747940 73757365  il:security@suse
 d40c0 2e64650a                             .de.            
```


#### GRUB and serial console

for a bloody SOL (IPMI) which is *COM3* (ie. *ttyS2* - *0x3e8*)

``` shell
GRUB_TERMINAL="console serial"
GRUB_SERIAL_COMMAND="serial --port=0x3e8 --speed=115200"
# or via 'unit'
# GRUB_SERIAL_COMMAND="serial --unit=2 --speed=115200"
```

and run `grub2-mkconfig -o /boot/grub2/grub.cfg`.


#### GRUB shell commands

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


#### GRUB troubleshooting

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


#### iPXE with dnsmasq

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


### syslinux

An example how to make WinPE for non-UEFI system.

NOTE: I'm not a Windows sysadmin, so could be wrong in some assumptions!

WinPE ISO looks like this:

``` shell
$ ls -1d ./{Boot,EFI,bootmgr*}
./Boot
./EFI
./bootmgr
./bootmgr.efi

# a winpe iso

$ fdisk -l winpe.iso
Disk winpe.iso: 308.69 MiB, 323686400 bytes, 632200 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

# an debian iso for comparison

$ fdisk -l debian-11.5.0-amd64-netinst.iso
Disk debian-11.5.0-amd64-netinst.iso: 382 MiB, 400556032 bytes, 782336 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x5004a58b

Device                           Boot Start    End Sectors  Size Id Type
debian-11.5.0-amd64-netinst.iso1 *        0 782335  782336  382M  0 Empty
debian-11.5.0-amd64-netinst.iso2       4064   9247    5184  2.5M ef EFI (FAT-12/16/32)
```

The ISO does not have a partition table, I could not make it boot on non-EFI system. Thus,
workaround via `syslinux`:

- create a MBR based block device
- create FAT32 bootable partition
- format the partition

``` shell
$ mount /dev/sda1 /mnt
$ (cd /mnt && isoinfo -i winpe.iso -X)

$ mkdir /mnt/syslinux

# not all c32 are needed but copying all of them anyway...
$ cp /usr/share/syslinux/*.c32 /mnt/syslinux/

$ cat > /mnt/syslinux/syslinux.cfg <<EOF
DEFAULT winpe
LABEL winpe
        COM32 /syslinux/chain.c32
        APPEND fs ntldr=/BOOTMG
EOF

$ umount /mnt

$ dd bs=440 count=1 conv=notrunc if=/usr/share/syslinux/mbr.bin of=/dev/sda
$ syslinux -d syslinux -i /dev/sda1
```


## Disaster Recovery


### REAR

[Rear](https://github.com/rear/rear) is not ready to use tool, it's
more a DR framework written in BASH.

``` shell
$ grep -Pv '^\s*(#|$)' /etc/rear/{local,os}.conf
/etc/rear/os.conf:OS_VENDOR=SUSE_LINUX
/etc/rear/os.conf:OS_VERSION=12

# if it is EFI system ISO_MKISOFS_BIN has to be changed

$ ls /sys/firmware/efi
ls: cannot access '/sys/firmware/efi': No such file or directory
$ grep MKISOFS /usr/share/rear/conf/default.conf
# to use ebiso, specify ISO_MKISOFS_BIN=<full_path_to_ebiso>/ebiso
ISO_MKISOFS_BIN="$( type -p xorrisofs || type -p mkisofs || type -p genisoimage )"
# (via ISO_MKISOFS_BIN=/usr/bin/ebiso - see the ISO_MKISOFS_BIN variable above).
```

And some very basic configuration.

``` shell
$ grep -Pv '^\s*(#|$)' /etc/rear/{local,os}.conf
/etc/rear/local.conf:BACKUP_URL=nfs://192.168.122.1/tmp
/etc/rear/local.conf:BACKUP=NETFS
/etc/rear/os.conf:OS_VENDOR=SUSE_LINUX
/etc/rear/os.conf:OS_VERSION=12
```

Generate rear boot media (default is an iso).

``` shell
$ rear -d -D mkbackup
Relax-and-Recover 2.4 / Git
Running rear mkbackup (PID 24256)
Using log file: /var/log/rear/rear-s125qb01.log
Using backup archive '/tmp/rear.E6R6I929nBcRCUU/outputfs/s125qb01/backup.tar.gz'
Creating disk layout
Doing SLES12-SP1 (and later) btrfs subvolumes setup because the default subvolume path contains '@/.snapshots/'
Using sysconfig bootloader 'grub2'
Creating root filesystem layout
Handling network interface 'br0'
br0 is a bridge
br0 has lower interface eth0
eth0 is a physical device
Handled network interface 'br0'
To log into the recovery system via ssh set up /root/.ssh/authorized_keys or specify SSH_ROOT_PASSWORD
Copying logfile /var/log/rear/rear-s125qb01.log into initramfs as '/tmp/rear-s125qb01-partial-2022-09-08T11:50:33+02:00.log'
Copying files and directories
Copying binaries and libraries
Copying kernel modules
Copying all files in /lib*/firmware/
Creating recovery/rescue system initramfs/initrd initrd.cgz with gzip default compression
Created initrd.cgz with gzip default compression (281906287 bytes) in 28 seconds
Making ISO image
Wrote ISO image: /var/lib/rear/output/rear-s125qb01.iso (278M)
Copying resulting files to nfs location
Saving /var/log/rear/rear-s125qb01.log as rear-s125qb01.log to nfs location
Creating tar archive '/tmp/rear.E6R6I929nBcRCUU/outputfs/s125qb01/backup.tar.gz'
Archived 1488 MiB [avg 7977 KiB/sec] OK
Archived 1488 MiB in 192 seconds [avg 7936 KiB/sec]
Exiting rear mkbackup (PID 24256) and its descendant processes
Running exit tasks
You should also rm -Rf /tmp/rear.E6R6I929nBcRCUU

# see what it did create...

$ mount 192.168.122.1:/tmp /mnt # mounting the NFS share

$ ls -l /mnt/s125qb01/
total 1823168
-rw------- 1 nobody nogroup    9039974 Sep  8 11:55 backup.log
-rw------- 1 nobody nogroup 1560350159 Sep  8 11:55 backup.tar.gz
-rw------- 1 nobody nogroup        202 Sep  8 11:51 README
-rw------- 1 nobody nogroup  291344384 Sep  8 11:51 rear-s125qb01.iso
-rw------- 1 nobody nogroup    6175380 Sep  8 11:51 rear-s125qb01.log
-rw------- 1 nobody nogroup        265 Sep  8 11:51 VERSION

# listing the iso..

$ 7z l /mnt/s125qb01/rear-s125qb01.iso

7-Zip [64] 9.20  Copyright (c) 1999-2010 Igor Pavlov  2010-11-18
p7zip Version 9.20 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,2 CPUs)

Listing archive: /mnt/s125qb01/rear-s125qb01.iso

--
Path = /mnt/s125qb01/rear-s125qb01.iso
Type = Iso
Created = 2022-09-08 11:51:22
Modified = 2022-09-08 11:51:22

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2022-09-08 11:51:21 D....                            isolinux
2022-09-08 11:51:22 .....         2048         2048  isolinux/boot.cat
2022-09-08 11:51:21 .....        20192        20192  isolinux/chain.c32
2022-09-08 11:51:21 .....       280644       280644  isolinux/hdt.c32
2022-09-08 11:51:22 .....    281906287    281906287  isolinux/initrd.cgz
2022-09-08 11:51:21 .....        24576        24576  isolinux/isolinux.bin
2022-09-08 11:51:21 .....         2150         2150  isolinux/isolinux.cfg
2022-08-03 11:28:28 .....      7323392      7323392  isolinux/kernel
2022-09-08 11:51:21 .....        55140        55140  isolinux/menu.c32
2022-09-08 11:51:21 .....          265          265  isolinux/message
2022-09-08 11:51:21 .....      1183752      1183752  isolinux/pci.ids
2022-09-08 11:51:21 .....          239          239  isolinux/poweroff.com
2022-09-08 11:51:21 .....          985          985  isolinux/rear.help
2022-09-08 11:51:21 .....          800          800  isolinux/reboot.c32
2022-09-08 11:51:21 .....       153104       153104  isolinux/vesamenu.c32
                    .....         2048         2048  [BOOT]/Bootable_NoEmulation.img
------------------- ----- ------------ ------------  ------------------------
                             290955622    290955622  15 files, 1 folders

# extracting rear boot media initrd from iso

$ 7z e -so /mnt/s125qb01/rear-s125qb01.iso isolinux/initrd.cgz > /tmp/initrd.cgz

7-Zip [64] 9.20  Copyright (c) 1999-2010 Igor Pavlov  2010-11-18
p7zip Version 9.20 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,2 CPUs)

Processing archive: /mnt/s125qb01/rear-s125qb01.iso

Extracting  isolinux/initrd.cgz

Everything is Ok

Size:       281906287
Compressed: 291344384

# extracting rear boot media initrd itself...

$ /usr/lib/dracut/skipcpio /tmp/initrd.cgz | zcat -- | \
    ( [[ -d /tmp/rear-initrd ]] && rm -rf /tmp/read-initrd;  \
        mkdir /tmp/rear-initrd 2>/dev/null ; \
        cd /tmp/rear-initrd; \
        cpio -id )
1443261 blocks

$ find /tmp/rear-initrd/ | grep -P '(etc/rear|/var/lib/rear/)'
/tmp/rear-initrd/etc/rear
/tmp/rear-initrd/etc/rear/rescue.conf
/tmp/rear-initrd/etc/rear/cert
/tmp/rear-initrd/etc/rear/os.conf
/tmp/rear-initrd/etc/rear/local.conf
/tmp/rear-initrd/etc/rear-release
/tmp/rear-initrd/var/lib/rear/output
/tmp/rear-initrd/var/lib/rear/recovery
/tmp/rear-initrd/var/lib/rear/recovery/bootdisk
/tmp/rear-initrd/var/lib/rear/recovery/directories_permissions_owner_group
/tmp/rear-initrd/var/lib/rear/recovery/diskbyid_mappings
/tmp/rear-initrd/var/lib/rear/recovery/mountpoint_device
/tmp/rear-initrd/var/lib/rear/recovery/bootloader
/tmp/rear-initrd/var/lib/rear/recovery/initrd_modules
/tmp/rear-initrd/var/lib/rear/recovery/storage_drivers
/tmp/rear-initrd/var/lib/rear/recovery/if_inet6
/tmp/rear-initrd/var/lib/rear/layout
/tmp/rear-initrd/var/lib/rear/layout/config
/tmp/rear-initrd/var/lib/rear/layout/config/df.txt
/tmp/rear-initrd/var/lib/rear/layout/config/files.md5sum
/tmp/rear-initrd/var/lib/rear/layout/disklayout.conf
/tmp/rear-initrd/var/lib/rear/layout/diskdeps.conf
/tmp/rear-initrd/var/lib/rear/layout/disktodo.conf
/tmp/rear-initrd/var/lib/rear/layout/lvm
/tmp/rear-initrd/var/lib/rear/sysreqs
/tmp/rear-initrd/var/lib/rear/sysreqs/Minimal_System_Requirements.txt

# "blueprint" for disk layout to be restored

$ grep -Pv '^\s*($|#)' /tmp/rear-initrd/var/lib/rear/layout/disklayout.conf
disk /dev/vda 22548578304 msdos
part /dev/vda 525336576 1048576 primary boot,lba /dev/vda1
part /dev/vda 20398997504 526385152 primary none /dev/vda2
part /dev/vda 1076887552 20925382656 primary none /dev/vda3
part /dev/vda 546308096 22002270208 primary none /dev/vda4
fs /dev/vda2 / btrfs uuid=b36e74cd-86ce-40f6-b760-e792f9d5be52 label= options=rw,relatime,space_cache,subvolid=259,subvol=/@/.snapshots/1/snapshot
btrfsdefaultsubvol /dev/vda2 / 259 @/.snapshots/1/snapshot
btrfsnormalsubvol /dev/vda2 / 257 @
btrfsnormalsubvol /dev/vda2 / 260 @/boot/grub2/i386-pc
btrfsnormalsubvol /dev/vda2 / 261 @/boot/grub2/x86_64-efi
btrfsnormalsubvol /dev/vda2 / 262 @/home
btrfsnormalsubvol /dev/vda2 / 263 @/opt
btrfsnormalsubvol /dev/vda2 / 264 @/srv
btrfsnormalsubvol /dev/vda2 / 265 @/tmp
btrfsnormalsubvol /dev/vda2 / 266 @/usr/local
btrfsnormalsubvol /dev/vda2 / 267 @/var/cache
btrfsnormalsubvol /dev/vda2 / 268 @/var/crash
btrfsnormalsubvol /dev/vda2 / 269 @/var/lib/libvirt/images
btrfsnormalsubvol /dev/vda2 / 270 @/var/lib/machines
btrfsnormalsubvol /dev/vda2 / 271 @/var/lib/mailman
btrfsnormalsubvol /dev/vda2 / 272 @/var/lib/mariadb
btrfsnormalsubvol /dev/vda2 / 273 @/var/lib/mysql
btrfsnormalsubvol /dev/vda2 / 274 @/var/lib/named
btrfsnormalsubvol /dev/vda2 / 275 @/var/lib/pgsql
btrfsnormalsubvol /dev/vda2 / 276 @/var/log
btrfsnormalsubvol /dev/vda2 / 277 @/var/opt
btrfsnormalsubvol /dev/vda2 / 278 @/var/spool
btrfsnormalsubvol /dev/vda2 / 279 @/var/tmp
btrfsmountedsubvol /dev/vda2 / rw,relatime,space_cache,subvolid=259,subvol=/@/.snapshots/1/snapshot @/.snapshots/1/snapshot
btrfsmountedsubvol /dev/vda2 /var/opt rw,relatime,space_cache,subvolid=277,subvol=/@/var/opt @/var/opt
btrfsmountedsubvol /dev/vda2 /var/lib/mariadb rw,relatime,space_cache,subvolid=272,subvol=/@/var/lib/mariadb @/var/lib/mariadb
btrfsmountedsubvol /dev/vda2 /var/spool rw,relatime,space_cache,subvolid=278,subvol=/@/var/spool @/var/spool
btrfsmountedsubvol /dev/vda2 /boot/grub2/i386-pc rw,relatime,space_cache,subvolid=260,subvol=/@/boot/grub2/i386-pc @/boot/grub2/i386-pc
btrfsmountedsubvol /dev/vda2 /var/crash rw,relatime,space_cache,subvolid=268,subvol=/@/var/crash @/var/crash
btrfsmountedsubvol /dev/vda2 /var/lib/machines rw,relatime,space_cache,subvolid=270,subvol=/@/var/lib/machines @/var/lib/machines
btrfsmountedsubvol /dev/vda2 /var/lib/mailman rw,relatime,space_cache,subvolid=271,subvol=/@/var/lib/mailman @/var/lib/mailman
btrfsmountedsubvol /dev/vda2 /opt rw,relatime,space_cache,subvolid=263,subvol=/@/opt @/opt
btrfsmountedsubvol /dev/vda2 /.snapshots rw,relatime,space_cache,subvolid=258,subvol=/@/.snapshots @/.snapshots
btrfsmountedsubvol /dev/vda2 /var/lib/pgsql rw,relatime,space_cache,subvolid=275,subvol=/@/var/lib/pgsql @/var/lib/pgsql
btrfsmountedsubvol /dev/vda2 /boot/grub2/x86_64-efi rw,relatime,space_cache,subvolid=261,subvol=/@/boot/grub2/x86_64-efi @/boot/grub2/x86_64-efi
btrfsmountedsubvol /dev/vda2 /var/lib/named rw,relatime,space_cache,subvolid=274,subvol=/@/var/lib/named @/var/lib/named
btrfsmountedsubvol /dev/vda2 /home rw,relatime,space_cache,subvolid=262,subvol=/@/home @/home
btrfsmountedsubvol /dev/vda2 /var/lib/mysql rw,relatime,space_cache,subvolid=273,subvol=/@/var/lib/mysql @/var/lib/mysql
btrfsmountedsubvol /dev/vda2 /var/tmp rw,relatime,space_cache,subvolid=279,subvol=/@/var/tmp @/var/tmp
btrfsmountedsubvol /dev/vda2 /tmp rw,relatime,space_cache,subvolid=265,subvol=/@/tmp @/tmp
btrfsmountedsubvol /dev/vda2 /var/cache rw,relatime,space_cache,subvolid=267,subvol=/@/var/cache @/var/cache
btrfsmountedsubvol /dev/vda2 /usr/local rw,relatime,space_cache,subvolid=266,subvol=/@/usr/local @/usr/local
btrfsmountedsubvol /dev/vda2 /srv rw,relatime,space_cache,subvolid=264,subvol=/@/srv @/srv
btrfsmountedsubvol /dev/vda2 /var/lib/libvirt/images rw,relatime,space_cache,subvolid=269,subvol=/@/var/lib/libvirt/images @/var/lib/libvirt/images
btrfsmountedsubvol /dev/vda2 /var/log rw,relatime,space_cache,subvolid=276,subvol=/@/var/log @/var/log
btrfsnocopyonwrite @/var/lib/mariadb
btrfsnocopyonwrite @/var/lib/pgsql
btrfsnocopyonwrite @/var/lib/mysql
btrfsnocopyonwrite @/var/lib/libvirt/images
btrfsnocopyonwrite @/var/log
swap /dev/vda3 uuid=2210ab59-f22a-4c39-a973-31ebeaf3cc85 label=

# data itself

$ tar tzf /mnt/s125qb01/backup.tar.gz | head -n 20
./
etc/
etc/snapper/
etc/snapper/configs/
etc/snapper/configs/root
etc/snapper/config-templates/
etc/snapper/config-templates/default
etc/snapper/filters/
etc/snapper/filters/base.txt
etc/snapper/filters/lvm.txt
etc/snapper/filters/x11.txt
etc/snapper/zypp-plugin.conf
etc/zypp/
etc/zypp/credentials.d/
etc/zypp/credentials.d/SCCcredentials
etc/zypp/credentials.d/SUSE_Linux_Enterprise_Server_12_SP5_x86_64
etc/zypp/credentials.d/SUSE_Linux_Enterprise_High_Availability_Extension_12_SP5_x86_64
etc/zypp/credentials.d/SUSE_Linux_Enterprise_Live_Patching_12_SP5_x86_64
etc/zypp/credentials.d/SUSE_Package_Hub_12_SP5_x86_64
etc/zypp/credentials.d/Advanced_Systems_Management_Module_12_x86_64
```

ReaR and SecureBoot:

``` shell
$ 7z e -so localhost/rear-localhost.iso EFI/BOOT/initrd.cgz | \
    zcat | cpio --to-stdout -i etc/rear/local.conf 2>/dev/null | \
    grep SECURE_BOOT_BOOTLOADER
SECURE_BOOT_BOOTLOADER="/usr/share/efi/x86_64/shim-sles.efi"


$ 7z l localhost/rear-localhost.iso | grep 'EFI/.*\.efi'
2024-08-01 08:55:47 .....       965672       965672  EFI/BOOT/BOOTX64.efi
2024-08-01 08:55:47 .....      1275904      1275904  EFI/BOOT/grub.efi
[root@avocado rear]# for i in EFI/BOOT/BOOTX64.efi EFI/BOOT/grub.efi ; do 7z e -so localhost/rear-localhost.iso $i | xxd -a | grep -A 1 -P '(shim,|SBAT.md.grub)' ; done
000c9c50: 2c34 2c55 4546 4920 7368 696d 2c73 6869  ,4,UEFI shim,shi
000c9c60: 6d2c 312c 6874 7470 733a 2f2f 6769 7468  m,1,https://gith
--
000c9ca0: 6973 652c 7368 696d 2c31 352e 382c 6d61  ise,shim,15.8,ma
000c9cb0: 696c 3a73 6563 7572 6974 7940 7375 7365  il:security@suse
00135040: 6169 6e2f 5342 4154 2e6d 640a 6772 7562  ain/SBAT.md.grub
00135050: 2c34 2c46 7265 6520 536f 6674 7761 7265  ,4,Free Software
```


## DBUS

``` shell
$ dbus-send --system --print-reply --dest=org.freedesktop.DBus  /org/freedesktop/DBus org.freedesktop.DBus.ListNames | grep -i network
      string "org.opensuse.Network.Nanny"
      string "org.opensuse.Network"
      string "org.opensuse.Network.DHCP4"
      string "org.opensuse.Network.AUTO4"
      string "org.opensuse.Network.DHCP6"
```

``` shell
$ dbus-send --print-reply --dest=org.freedesktop.DBus  /org/freedesktop/DBus org.freedesktop.DBus.ListNames | grep -i network
      string "org.freedesktop.network-manager-applet"
```


## Linux filesystems


``` shell
mount | column -t # more readable mount output
```


### AutoFS

TODO: ...

Configuration consists of three columns:

1. mountpoint
2. map
3. options

Warning! - _autofs_ makes a distinction about "maptype", thus if
`auto.master(5)` "maptype" is not a script but "plain" `autofs(5)`
automounter map, then the "maptype" file should not be executable.

A workaround to create a mountpoint before the actual mount; an
executable map file is used!

``` shell
$ grep -Pv '^\s*(#|$)' /etc/auto.master
/etc/auto.master:+auto.master
/etc/auto.master:/run/autofs auto.removable

$ ls -l /etc/auto.removable
-rwxr-xr-x 1 root root 147 Jan 30 15:57 /etc/auto.removable

$ cat /etc/auto.removable
#!/bin/sh

case $1 in
    000-1ES162)
        mkdir -p /run/autofs
        echo -fstype=xfs :/dev/disk/by-id/scsi-SST1000VX_000-1ES162_3000CCCCBBBBAAAA
        ;;
esac
```

``` shell
# /etc/auto.smb is an executable as shipped by SLES RPM

$ rtss strace -f -e trace=file automount -f -v -d10 2>&1 | grep -P '(lookup|execve|/etc/auto.smb)'
   3.7ms    3.7ms # execve("/usr/sbin/automount", ["automount", "-f", "-v", "-d10"], 0x7ffeb5479010 /* 50 vars */) = 0
  20.2ms    3.5ms # [pid 10621] execve("/sbin/mount.nfs", ["/sbin/mount.nfs", "-V"], 0x55c662b7bc80 /* 69 vars */) = 0
  36.1ms   48.4μs # [pid 10620] openat(AT_FDCWD, "/usr/lib64/autofs/lookup_files.so", O_RDONLY|O_CLOEXEC) = 5
  43.4ms    0.3ms # [pid 10625] execve("/usr/bin/mount", ["/usr/bin/mount", "-n", "--bind", "/tmp/autoiSO3Qz", "/tmp/autoElclRH"], 0x55c662b7bc80 /* 69 vars */) = 0
  57.4ms    4.8ms # [pid 10626] execve("/usr/bin/umount", ["/usr/bin/umount", "-c", "-n", "/tmp/autoElclRH"], 0x55c662b7bc80 /* 69 vars */) = 0
  65.1ms    0.3ms # lookup_read_master: lookup(file): read entry /smb
  66.6ms    0.3ms # lookup_nss_read_map: reading map file /etc/auto.smb
  66.9ms    0.2ms # [pid 10627] newfstatat(AT_FDCWD, "/etc/auto.smb", {st_mode=S_IFREG|0755, st_size=2083, ...}, 0) = 0
  67.0ms   72.9μs # [pid 10627] openat(AT_FDCWD, "/usr/lib64/autofs/lookup_program.so", O_RDONLY|O_CLOEXEC) = 7
  67.5ms    0.4ms # [pid 10627] access("/etc/auto.smb", X_OK) = 0
  74.8ms    0.3ms # [pid 10628] execve("/usr/bin/mount", ["/usr/bin/mount", "-n", "--bind", "/tmp/auto3r7NHZ", "/tmp/autok50x7R"], 0x55c662b7bc80 /* 69 vars */) = 0
  88.2ms    4.0ms # [pid 10629] execve("/usr/bin/umount", ["/usr/bin/umount", "-c", "-n", "/tmp/autok50x7R"], 0x55c662b7bc80 /* 69 vars */) = 0
  95.2ms   45.4μs # [pid 10627] mount("/etc/auto.smb", "/smb", "autofs", MS_MGC_VAL, "fd=6,pgrp=10613,minproto=5,maxpr"...) = 0

   v--- here when I executed `ls /smb/avocado/iso' where 'iso' is the share and 'avocado' is the host

  12.65s    0.2ms # [pid 10645] newfstatat(AT_FDCWD, "/etc/auto.smb", {st_mode=S_IFREG|0755, st_size=2083, ...}, 0) = 0
  12.65s   52.5μs # lookup_mount: lookup(program): looking up avocado
  12.66s    0.2ms # [pid 10646] execve("/etc/auto.smb", ["/etc/auto.smb", "avocado"], 0x55c662b855e0 /* 89 vars */) = 0
  12.66s    0.4ms # [pid 10646] openat(AT_FDCWD, "/etc/auto.smb", O_RDONLY) = 3
  12.66s   67.7μs # [pid 10646] stat("/etc/auto.smb", {st_mode=S_IFREG|0755, st_size=2083, ...}) = 0
  12.67s    0.2ms # [pid 10648] execve("/usr/bin/ls", ["ls", "-d", "/run/user/0/krb5cc_*"], 0x55a118e60970 /* 89 vars */) = 0
  12.68s    0.2ms # [pid 10649] execve("/usr/bin/smbclient", ["/usr/bin/smbclient", "-N", "-gL", "avocado"], 0x55a118e60970 /* 89 vars */ <unfinished ...>
  12.68s   20.1μs # [pid 10649] <... execve resumed>)       = 0
  12.68s   92.5μs # [pid 10650] execve("/usr/bin/awk", ["awk", "-v", "key=avocado", "-v", "opts=-fstype=cifs,guest", "-F", "|", "--", "\n\tBEGIN\t{ ORS=\"\"; first=1 }\n\t/Di"...], 0x55a118e60970 /* 89 vars */ <unfinished ...>
  12.68s   78.2μs # [pid 10650] <... execve resumed>)       = 0
  13.01s    1.0ms # lookup_mount: lookup(program): avocado -> -fstype=cifs,guest         "/iso" "://avocado/iso"
  13.01s   49.1μs # [pid 10645] mount("/etc/auto.smb", "/smb/avocado/iso", "autofs", MS_MGC_VAL, "fd=6,pgrp=10613,minproto=5,maxpr"...) = 0
  13.01s    0.2ms # [pid 10652] newfstatat(AT_FDCWD, "/etc/auto.smb", {st_mode=S_IFREG|0755, st_size=2083, ...}, 0) = 0
  13.01s   60.2μs # lookup_mount: lookup(program): /smb/avocado/iso -> -fstype=cifs,guest ://avocado/iso
  13.02s    3.7ms # [pid 10653] execve("/usr/bin/mount", ["/usr/bin/mount", "-t", "cifs", "-o", "guest", "//avocado/iso", "/smb/avocado/iso"], 0x55c662b7bc80 /* 69 vars */) = 0
  13.03s    0.3ms # [pid 10654] execve("/sbin/mount.cifs", ["/sbin/mount.cifs", "//avocado/iso", "/smb/avocado/iso", "-o", "rw,guest"], 0x7ffe5d3f3cb8 /* 65 vars */) = 0

# /etc/auto.smb executable and having a map
...
  61.4ms    0.2ms # [pid 10990] newfstatat(AT_FDCWD, "/etc/auto.smb", {st_mode=S_IFREG|0755, st_size=127, ...}, 0) = 0
  61.5ms   62.4μs # [pid 10990] openat(AT_FDCWD, "/usr/lib64/autofs/lookup_program.so", O_RDONLY|O_CLOEXEC) = 7
  61.9ms    0.3ms # [pid 10990] access("/etc/auto.smb", X_OK) = 0
  67.9ms    0.2ms # [pid 10991] execve("/usr/bin/mount", ["/usr/bin/mount", "-n", "--bind", "/tmp/autoMC7k0t", "/tmp/autoamzl0I"], 0x5562c2c7cc80 /* 69 vars */) = 0
  77.8ms    4.5ms # [pid 10992] execve("/usr/bin/umount", ["/usr/bin/umount", "-c", "-n", "/tmp/autoamzl0I"], 0x5562c2c7cc80 /* 69 vars */) = 0
  83.9ms   36.5μs # [pid 10990] mount("/etc/auto.smb", "/smb", "autofs", MS_MGC_VAL, "fd=6,pgrp=10976,minproto=5,maxpr"...) = 0
   2.66s    0.2ms # [pid 10997] newfstatat(AT_FDCWD, "/etc/auto.smb", {st_mode=S_IFREG|0755, st_size=127, ...}, 0) = 0
   2.66s   29.3μs # lookup_mount: lookup(program): looking up avocado-iso
   2.67s    0.2ms # [pid 10998] execve("/etc/auto.smb", ["/etc/auto.smb", "avocado-iso"], 0x5562c2c865e0 /* 89 vars */) = -1 ENOEXEC (Exec format error)
   2.67s    0.2ms # lookup(program): lookup for avocado-iso failed

# /etc/auto.smb non-executable and having just autofs(5) map
...
  59.8ms    0.3ms # [pid 11217] newfstatat(AT_FDCWD, "/etc/auto.smb", {st_mode=S_IFREG|0644, st_size=127, ...}, 0) = 0
  59.9ms   74.0μs # [pid 11217] openat(AT_FDCWD, "/usr/lib64/autofs/lookup_file.so", O_RDONLY|O_CLOEXEC) = 7
  60.4ms    0.4ms # [pid 11217] access("/etc/auto.smb", R_OK) = 0
  67.7ms    0.3ms # [pid 11218] execve("/usr/bin/mount", ["/usr/bin/mount", "-n", "--bind", "/tmp/auto0vHUIu", "/tmp/autoHRdljb"], 0x559d54aaac80 /* 69 vars */) = 0
  79.7ms    4.2ms # [pid 11222] execve("/usr/bin/umount", ["/usr/bin/umount", "-c", "-n", "/tmp/autoHRdljb"], 0x559d54aaac80 /* 69 vars */) = 0
  86.5ms    0.1ms # [pid 11217] openat(AT_FDCWD, "/etc/auto.smb", O_RDONLY|O_CLOEXEC) = 7
  87.0ms   47.3μs # [pid 11217] mount("/etc/auto.smb", "/smb", "autofs", MS_MGC_VAL, "fd=6,pgrp=11203,minproto=5,maxpr"...) = 0
   1.88s    0.2ms # [pid 11224] newfstatat(AT_FDCWD, "/etc/auto.smb", {st_mode=S_IFREG|0644, st_size=127, ...}, 0) = 0
   1.88s   49.4μs # lookup_mount: lookup(file): looking up avocado-iso
   1.88s   90.4μs # [pid 11224] newfstatat(AT_FDCWD, "/etc/auto.smb", {st_mode=S_IFREG|0644, st_size=127, ...}, 0) = 0
   1.88s   43.1μs # lookup_mount: lookup(file): avocado-iso -> -fstype=cifs,credentials=/root/smb.avocado,uid=oracle,gid=dba,dir_mode=0700,file_mode=0500,vers=2.1 ://avocado/iso
   1.88s    3.9ms # [pid 11225] execve("/usr/bin/mount", ["/usr/bin/mount", "-t", "cifs", "-o", "credentials=/root/smb.avocado,ui"..., "//avocado/iso", "/smb/avocado-iso"], 0x559d54aaac80 /* 69 vars */) = 0
   1.89s    0.3ms # [pid 11226] execve("/sbin/mount.cifs", ["/sbin/mount.cifs", "//avocado/iso", "/smb/avocado-iso", "-o", "rw,credentials=/root/smb.avocado"...], 0x7fff8880cf78 /* 65 vars */) = 0
```


### BTRFS

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

List subvols on non-mounted FS:

``` shell
$ btrfs inspect-internal dump-tree -t 1 /dev/system/root | \
    grep -P 'item \d+ key \(\d+ ROOT_ITEM' | wc -l
78
$ btrfs subvolume list / | wc -l
78
```

Set or get default subvol when the filesystem is mounted:

``` shell
$ btrfs subvolume set-default --help
usage: btrfs subvolume set-default <subvolume>
       btrfs subvolume set-default <subvolid> <path>

    Set the default subvolume of the filesystem mounted as default.

    The subvolume can be specified by its path,
    or the pair of subvolume id and path to the filesystem.

$ btrfs subvolume get-default /
ID 266 gen 1764765 top level 265 path @/.snapshots/1/snapshot
```

Set r/w of BTRFS snapshot created by `snapper`:

``` shell
$ btrfs property list -t subvol /.snapshots/421/snapshot
ro                  read-only status of a subvolume
$ btrfs property get -t subvol /.snapshots/421/snapshot ro
ro=true

$ touch /.snapshots/421/snapshot/TEST
touch: cannot touch '/.snapshots/421/snapshot/TEST': Read-only file system

$ btrfs property set -t subvol /.snapshots/421/snapshot ro false
$ btrfs property get -t subvol /.snapshots/421/snapshot ro
ro=false

$ touch /.snapshots/421/snapshot/TEST
$ ls -l /.snapshots/421/snapshot/TEST
-rw-r--r-- 1 root root 0 Oct 25 09:47 /.snapshots/421/snapshot/TEST
```

BTRFS superblock query (for example, GRUB2 has this definition in its
code
https://github.com/rhboot/grub2/blob/fedora-39/grub-core/fs/btrfs.c#L262).

``` c
static grub_disk_addr_t superblock_sectors[] = { 64 * 2, 64 * 1024 * 2,
  256 * 1048576 * 2, 1048576ULL * 1048576ULL * 2
};
```

``` shell
$ grep -h --only-matching --byte-offset --max-count=1 --text _BHRfS_M /dev/loop0
1114176:_BHRfS_M
$ echo $((1114176-65536-64))
1048576

$ wipefs /dev/loop9
DEVICE OFFSET  TYPE  UUID                                 LABEL
loop9  0x10040 btrfs cf5c6059-03c4-4341-ad26-1ffc3d6659a6

$  printf '%d\n' 0x10040
65600
```

- disable copy-on-write (cow)
  > A subvolume may contain files that constantly change, such as
  > virtualized disk images, database files, or log files. If so,
  > consider disabling the copy-on-write feature for this volume, to
  > avoid duplication of disk blocks.
  ``` shell
  grep '\bbtrfs\b.*nodatacow' /etc/fstab # check if cow disabled in /etc/fstab
  lsattr -d /var                         # check if cow disabled via attributes
  ```


#### BTRFS: snapper

Snapper can work also with LVM but generally used mostly with BTRFS.

Automatically triggered btrfs snapshots

``` shell
$ snapper list
 # | Type   | Pre # | Date                     | User | Used Space | Cleanup | Description           | Userdata
---+--------+-------+--------------------------+------+------------+---------+-----------------------+---------
0  | single |       |                          | root |            |         | current               |
1* | single |       | Mon May  3 10:38:56 2021 | root |  28.12 GiB |         | first root filesystem |
```

Snapshot '0' is only a virtual snapshot pointing to the real
snapshot. So you will always have snapshot '0' and a second snapshot.

``` shell
$ snapper create
$ snapper list
 # | Type   | Pre # | Date                     | User | Used Space | Cleanup | Description           | Userdata
---+--------+-------+--------------------------+------+------------+---------+-----------------------+---------
0  | single |       |                          | root |            |         | current               |
1* | single |       | Mon May  3 10:38:56 2021 | root | 718.64 MiB |         | first root filesystem |
2  | single |       | Thu Mar 23 12:45:24 2023 | root |   2.00 MiB |         |                       |

$ echo 'Hello snapper' > /etc/testsnapper

$ diff -uNpr /.snapshots/2/snapshot/etc/ /.snapshots/1/snapshot/etc/ 2>/dev/null
diff -uNpr /.snapshots/2/snapshot/etc/testsnapper /.snapshots/1/snapshot/etc/testsnapper
--- /.snapshots/2/snapshot/etc/testsnapper      1970-01-01 01:00:00.000000000 +0100
+++ /.snapshots/1/snapshot/etc/testsnapper      2023-03-23 12:46:56.719176895 +0100
@@ -0,0 +1 @@
+Hello snapper

$ snapper diff 2..1
--- /.snapshots/2/snapshot/etc/testsnapper      1970-01-01 01:00:00.000000000 +0100
+++ /.snapshots/1/snapshot/etc/testsnapper      2023-03-23 12:46:56.719176895 +0100
@@ -0,0 +1 @@
+Hello snapper
```

``` shell
# comparing the latest snapshot with current filesystem ('1' is current filesystem).

$ snapper diff 2..1
--- /.snapshots/2/snapshot/etc/testsnapper      1970-01-01 01:00:00.000000000 +0100
+++ /.snapshots/1/snapshot/etc/testsnapper      2023-03-23 15:57:03.381353110 +0100
@@ -0,0 +1 @@
+foo

$ snapper undochange 2..1 /etc/testsnapper
create:0 modify:0 delete:1

$ ls -l /etc/testsnapper
ls: cannot access '/etc/testsnapper': No such file or directory
```


#### BTRFS: troubleshooting

Understanding space occupation in BTRFS:

``` shell
# btrfs is also a kind of volume manager, but here only one volume/device
# is used

$ btrfs fi show --mbytes /
Label: none  uuid: 3230dffb-e7eb-4bb3-a30e-e168c7b90197
        Total devices 1 FS bytes used 34807.12MiB
        devid    1 size 51200.00MiB used 51199.00MiB path /dev/mapper/system-root

$ btrfs fi df -m /
Data, single: total=48859.00MiB, used=33585.86MiB
System, single: total=32.00MiB, used=0.02MiB
Metadata, single: total=2308.00MiB, used=1221.25MiB
GlobalReserve, single: total=141.77MiB, used=0.00MiB

$ echo $((48859+32+2308))
51199
```

The point here is that space was *allocated*, the *used* is smaller
but is it NOT *free/unallocated* space. The next command makes it more
clear:

``` shell
$ btrfs fi usage --mbytes /
Overall:
    Device size:                       51200.00MiB
    Device allocated:                  51199.00MiB
    Device unallocated:                    1.00MiB
    Device missing:                        0.00MiB
    Device slack:                          0.00MiB
    Used:                              34807.66MiB
    Free (estimated):                  15272.60MiB      (min: 15272.60MiB)
    Free (statfs, df):                 15272.60MiB
    Data ratio:                               1.00
    Metadata ratio:                           1.00
    Global reserve:                      141.77MiB      (used: 0.00MiB)
    Multiple profiles:                          no

Data,single: Size:48859.00MiB, Used:33586.40MiB (68.74%)
   /dev/mapper/system-root      48859.00MiB

Metadata,single: Size:2308.00MiB, Used:1221.25MiB (52.91%)
   /dev/mapper/system-root      2308.00MiB

System,single: Size:32.00MiB, Used:0.02MiB (0.05%)
   /dev/mapper/system-root        32.00MiB

Unallocated:
   /dev/mapper/system-root         1.00MiB
```

``` shell
$ btrfs balance start -dusage=70 /
btrfs filesystem usage -m -T /
Overall:
    Device size:                       51200.00MiB
    Device allocated:                  41983.00MiB
    Device unallocated:                 9217.00MiB
    Device missing:                        0.00MiB
    Device slack:                          0.00MiB
    Used:                              35847.59MiB
    Free (estimated):                  14261.38MiB      (min: 14261.38MiB)
    Free (statfs, df):                 14260.38MiB
    Data ratio:                               1.00
    Metadata ratio:                           1.00
    Global reserve:                      124.05MiB      (used: 0.00MiB)
    Multiple profiles:                          no

                           Data        Metadata   System
Id Path                    single      single     single   Unallocated Total       Slack
-- ----------------------- ----------- ---------- -------- ----------- ----------- -------
 1 /dev/mapper/system-root 39643.00MiB 2308.00MiB 32.00MiB  9217.00MiB 51200.00MiB       -
-- ----------------------- ----------- ---------- -------- ----------- ----------- -------
   Total                   39643.00MiB 2308.00MiB 32.00MiB  9217.00MiB 51200.00MiB 0.00MiB
   Used                    34598.62MiB 1248.95MiB  0.02MiB
```

An attempt to mount BTRFS outside of LVM:

``` shell
# just a demonstration that the block device is a PV
$ xxd -s $((512+32)) -l 32 /dev/loop0
00000220: 6938 7070 3932 4852 6b66 6939 6f73 4949  i8pp92HRkfi9osII
00000230: 5246 746f 6545 6649 6678 376d 3730 5246  RFtoeEfIfx7m70RF

# LVM metadata are usually 1 or 4 MB, here skipping 1 MB
# plus skipping 65536 for BTRFS superblock start offset
$ xxd -s $(( (1 * 1024 * 1024) + 65536)) -l 4096 /dev/loop0 | grep _BHRfS_M
00110040: 5f42 4852 6653 5f4d 0800 0000 0000 0000  _BHRfS_M........

# BTRFS superblock starts at 65536, the magic number `_BHRfS_M` is located
# at offset 64 within the superblock
$ printf '%d - %d - %d\n' 0x00110040 $((1 * 1024 * 1024)) 64 | bc
65536

# or... skipping LVM, BTRFS superblock start offset and checking if BTRFS
# magic number starts at offset 64 (0x40)
$ dd if=/dev/loop0 bs=1 skip=$(( (1 * 1024 * 1024) + 65536 )) count=4096 status=none | \
    xxd -l $((64+16))
00000000: 7803 d745 0000 0000 0000 0000 0000 0000  x..E............
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: cf5c 6059 03c4 4341 ad26 1ffc 3d66 59a6  .\`Y..CA.&..=fY.
00000030: 0000 0100 0000 0000 0100 0000 0000 0000  ................
00000040: 5f42 4852 6653 5f4d 0800 0000 0000 0000  _BHRfS_M........

# skipping LVM metadata
$ losetup -o $((1 * 1024 * 1024)) /dev/loop9 /dev/loop0

$ btrfs inspect-internal dump-super -F /dev/loop9
superblock: bytenr=65536, device=/dev/loop9
---------------------------------------------------------
csum_type               0 (crc32c)
csum_size               4
csum                    0x7803d745 [match]
bytenr                  65536
flags                   0x1
                        ( WRITTEN )
magic                   _BHRfS_M [match]
fsid                    cf5c6059-03c4-4341-ad26-1ffc3d6659a6
metadata_uuid           00000000-0000-0000-0000-000000000000
label
generation              8
root                    30638080
sys_array_size          129
chunk_root_generation   6
root_level              0
chunk_root              22036480
chunk_root_level        0
log_root                0
log_root_transid (deprecated)   0
log_root_level          0
total_bytes             520093696
bytes_used              147456
sectorsize              4096
nodesize                16384
leafsize (deprecated)   16384
stripesize              4096
root_dir                6
num_devices             1
compat_flags            0x0
compat_ro_flags         0x3
                        ( FREE_SPACE_TREE |
                          FREE_SPACE_TREE_VALID )
incompat_flags          0x361
                        ( MIXED_BACKREF |
                          BIG_METADATA |
                          EXTENDED_IREF |
                          SKINNY_METADATA |
                          NO_HOLES )
cache_generation        0
uuid_tree_generation    8
dev_item.uuid           59fb9221-a858-47fe-9711-f228a6976b53
dev_item.fsid           cf5c6059-03c4-4341-ad26-1ffc3d6659a6 [match]
dev_item.type           0
dev_item.total_bytes    520093696
dev_item.bytes_used     92274688
dev_item.io_align       4096
dev_item.io_width       4096
dev_item.sector_size    4096
dev_item.devid          1
dev_item.dev_group      0
dev_item.seek_speed     0
dev_item.bandwidth      0
dev_item.generation     0

$ wipefs /dev/loop9
DEVICE OFFSET  TYPE  UUID                                 LABEL
loop9  0x10040 btrfs cf5c6059-03c4-4341-ad26-1ffc3d6659a6

# see btrfs(5) for details
$ mount -t btrfs -o ro,skip_balance,norecovery /dev/loop9 /mnt
$ cat /mnt/test.txt
hello world
```


### SMB aka CIFS

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

Or an example of whole debugging attempt:

``` shell
$ dmesg --clear

# load cifs.ko module
$ modprobe cifs

# make the kernel as verbose as possible
$ echo 'module cifs +p' > /sys/kernel/debug/dynamic_debug/control
$ echo 'file fs/cifs/* +p' > /sys/kernel/debug/dynamic_debug/control
$ echo 1 > /proc/fs/cifs/cifsFYI
$ echo 1 > /sys/module/dns_resolver/parameters/debug

# get kernel output + network trace
$ tcpdump -s 0 -w /tmp/trace.pcap & pid=$!
$ sleep 3
$ mount.cifs <share> <local_mountpoint> -o <mount_options>
$ ls <local_mountpoint>
$ sleep 3
$ kill $pid
$ dmesg > /tmp/trace.log
$ cat /proc/fs/cifs/dfscache >> /tmp/trace.log

# disable verbose
$ echo 'module cifs -p' > /sys/kernel/debug/dynamic_debug/control
$ echo 'file fs/cifs/* -p' > /sys/kernel/debug/dynamic_debug/control
$ echo 0 > /proc/fs/cifs/cifsFYI
$ echo 0 > /sys/module/dns_resolver/parameters/debug

# get data to provide for an analysis
$ tar cvzf /tmp/cifs-troubleshooting.tgz /tmp/trace.pcap /tmp/trace.log
```

Let's see `/proc/fs/cifs/DebugData`:

``` shell
$ mount -t cifs -o guest //127.0.0.1/pub-test$ /mnt

$ cat /proc/fs/cifs/DebugData
Display Internal CIFS Data Structures for Debugging
---------------------------------------------------
CIFS Version 2.36
Features: DFS,FSCACHE,STATS2,DEBUG,ALLOW_INSECURE_LEGACY,CIFS_POSIX,UPCALL(SPNEGO),XATTR,ACL,WITNESS
CIFSMaxBufSize: 16384
Active VFS Requests: 0

Servers:
1) ConnectionId: 0xc Hostname: 127.0.0.1
Number of credits: 389 Dialect 0x311
TCP status: 1 Instance: 1
Local Users To Server: 1 SecMode: 0x1 Req On Wire: 0
In Send: 0 In MaxReq Wait: 0

        Sessions:
        1) Address: 127.0.0.1 Uses: 1 Capability: 0x300047      Session Status: 1
        Security type: RawNTLMSSP  SessionId: 0xf40dcb8
        User: 0 Cred User: 0

        Shares:
        0) IPC: \\127.0.0.1\IPC$ Mounts: 1 DevInfo: 0x0 Attributes: 0x0
        PathComponentMax: 0 Status: 0 type: 0 Serial Number: 0x0
        Share Capabilities: None        Share Flags: 0x0
        tid: 0xb875c11c Maximal Access: 0x1f00a9

        1) \\127.0.0.1\pub-test$ Mounts: 1 DevInfo: 0x20 Attributes: 0x1006f
        PathComponentMax: 255 Status: 0 type: DISK Serial Number: 0xb86bf3d5
        Share Capabilities: None Aligned, Partition Aligned,    Share Flags: 0x0
        tid: 0xe5d96f6f Optimal sector size: 0x200      Maximal Access: 0x1f01ff


        Server interfaces: 4
        1)      Speed: 1000000000 bps
                Capabilities:
                IPv4: 10.0.0.1

        2)      Speed: 1000000000 bps
                Capabilities:
                IPv4: 192.168.1.5

        3)      Speed: 10000000 bps
                Capabilities:
                IPv4: 192.168.122.1

        4)      Speed: 10000000 bps
                Capabilities:
                IPv4: 192.168.123.1


        MIDs:
--

Witness registrations:
```

File `/proc/fs/cifs/open_files` is also interesting.

``` shell
$ umount /mnt
umount: /mnt: target is busy.
$ fuser -cuv /mnt
                     USER        PID ACCESS COMMAND
/mnt:                root     kernel mount (root)/mnt
                     root      32283 f.... (root)less
$ ps auxww | grep '32283'
root       335  0.0  0.0   3932  2124 pts/10   S+   11:39   0:00 grep --color=auto 32283
root     32283  0.0  0.0   3588  2624 pts/11   S+   11:36   0:00 less /mnt/foobar.txt

$ cat /proc/fs/cifs/open_files
# Version:1
# Format:
# <tree id> <persistent fid> <flags> <count> <pid> <uid> <filename>
0xe5d96f6f 0xe61dfe5f 0x8000 1 32283 0 foobar.txt
```

Let's assume that we request that SMB package *must* be signed and
*must* use NTLMv2 and NTLMSSP. See
https://elixir.bootlin.com/linux/latest/source/fs/cifs/cifsglob.h#L1778.

``` shell
$ echo '0x85085' > /proc/fs/cifs/SecurityFlags

$ mount -v -t cifs -o guest //127.0.0.1/pub-test$ /mnt
mount.cifs kernel mount options: ip=127.0.0.1,unc=\\127.0.0.1\pub-test$,user=,pass=********
mount error(13): Permission denied
Refer to the mount.cifs(8) manual page (e.g. man mount.cifs) and kernel log messages (dmesg)

$ dmesg | grep CIFS:
[363189.451715] CIFS: Attempting to mount \\127.0.0.1\pub-test$
[363189.487060] CIFS: VFS: sign fail cmd 0x3 message id 0x3
[363189.487073] CIFS: VFS: \\127.0.0.1 SMB signature verification returned error = -13
[363189.487081] CIFS: VFS: \\127.0.0.1 failed to connect to IPC (rc=-13)
[363189.487261] CIFS: VFS: sign fail cmd 0x3 message id 0x4
[363189.487267] CIFS: VFS: \\127.0.0.1 SMB signature verification returned error = -13
[363189.487278] CIFS: VFS: session 0000000009b6ef72 has no tcon available for a dfs referral request
[363189.487438] CIFS: VFS: sign fail cmd 0x2 message id 0x5
[363189.487444] CIFS: VFS: \\127.0.0.1 SMB signature verification returned error = -13
[363189.487451] CIFS: VFS: \\127.0.0.1 cifs_put_smb_ses: Session Logoff failure rc=-13
[363189.487465] CIFS: VFS: cifs_mount failed w/return code = -13
```

Logged issues:

``` shell
[126347.433310] CIFS: Attempting to mount //t14s/test
[126347.460616] CIFS: Status code returned 0xc000006d STATUS_LOGON_FAILURE
[126347.460652] CIFS: VFS: \\t14s Send error in SessSetup = -13
[126347.460688] CIFS: VFS: cifs_mount failed w/return code = -13

^^^ here bad password was used

[126519.696342] CIFS: Attempting to mount //t14s/testt
[126519.719473] CIFS: VFS:  BAD_NETWORK_NAME: \\t14s\testt
[126521.736215] CIFS: VFS: cifs_mount failed w/return code = -2

^^ here bad share name 'testt' instead of 'test'

[126593.988846] CIFS: Attempting to mount //t14s/test
[126594.010417] CIFS: VFS:  BAD_NETWORK_NAME: \\t14s\test
[126596.032531] CIFS: VFS: cifs_mount failed w/return code = -2

^^ here a backing directory of the 'test' share did not exit
```


### XFS

An example of an impact done with `lvreduce` on the XFS filesystem,
which does not (yet) support shrinking.

``` shell
mount: /var/lib/pgsql: can't read superblock on /dev/mapper/vg00-sumalv1
```

`/var/mapper/vg00-sumalv1` is `/dev/dm-2`:

``` shell
2025-02-10T13:03:17.195773+03:00 example01 kernel: [   82.424459][T40684] SGI XFS with ACLs, security attributes, quota, no debug enabled
2025-02-10T13:03:17.200028+03:00 example01 kernel: [   82.429009][T40683] attempt to access beyond end of device
2025-02-10T13:03:17.200039+03:00 example01 kernel: [   82.429009][T40683] dm-2: rw=4096, want=908066816, limit=750780416
2025-02-10T13:03:17.200041+03:00 example01 kernel: [   82.429013][T40683] XFS (dm-2): last sector read failed
2025-02-10T13:03:17.208032+03:00 example01 kernel: [   82.433619][T40683] XFS (dm-3): Mounting V5 Filesystem
2025-02-10T13:03:19.476042+03:00 example01 kernel: [   84.720203][T40683] XFS (dm-3): Ending clean mount
2025-02-10T13:03:19.516018+03:00 example01 kernel: [   84.760709][T40683] XFS (dm-4): Mounting V5 Filesystem
2025-02-10T13:03:19.648043+03:00 example01 kernel: [   84.895215][T40683] XFS (dm-4): Ending clean mount
```

Where `limit` is current `dm-2` size and `want` is the original size
(in 512 blocks); see below for the original size.

``` shell
$ echo '(750780416*512)/2^30' | bc
358

$ lvs | grep sumalv1
  sumalv1    vg00 -wi-a----- 358.00g
```

``` shell
$ grep -A 2 -P 'description.*sumalv1' /etc/lvm/archive/vg00*
description = "Created *before* executing 'lvextend -L +50G /dev/vg00/sumalv1'"
creation_host = "example01"      # Linux example01 5.14.21-150400.24.128-default #1 SMP PREEMPT_DYNAMIC Wed Aug 7 10:28:44 UTC 2024 (a6f23d4) x86_64
creation_time = 1727760026      # Tue Oct  1 08:20:26 2024
--
description = "Created *before* executing 'lvextend -L +100G /dev/vg00/sumalv1'"
creation_host = "example01"      # Linux example01 5.14.21-150400.24.136-default #1 SMP PREEMPT_DYNAMIC Wed Oct 2 09:41:54 UTC 2024 (adc7c83) x86_64
creation_time = 1729694847      # Wed Oct 23 17:47:27 2024
--
description = "Created *before* executing 'lvreduce -L -75G /dev/vg00/sumalv1'"
creation_host = "example01"      # Linux example01 5.14.21-150400.24.136-default #1 SMP PREEMPT_DYNAMIC Wed Oct 2 09:41:54 UTC 2024 (adc7c83) x86_64
creation_time = 1729695434      # Wed Oct 23 17:57:14 2024
```

Oops, `lvreduce`? That's the culprit!

Some LVM archive file math from `/etc/lvm/archive/vg00_00026-751798520.vg`:

``` shell
$ awk '
NR > 3 && !/^[[:blank:]]*(#|$)/ && /sumalv1/{flag=1;}
/sumalv2/{flag=0}
flag && /extent_count = [0-9]+/ { sum += $3 }
END { print "Total size: ", sum * 4* 2^20 / 512 }
' < /etc/lvm/archive/vg00_00026-751798520.vg
Total size:  908066816
```

So, LVM archive file saves the original size before the action was
executed.

An attempt to mount XFS outside of LVM:

``` shell
# just a demonstration that the block device is a PV
$ xxd -s $((512+32)) -l 32 /dev/loop0
00000220: 6938 7070 3932 4852 6b66 6939 6f73 4949  i8pp92HRkfi9osII
00000230: 5246 746f 6545 6649 6678 376d 3730 5246  RFtoeEfIfx7m70RF

$ xxd -c 32 /dev/loop0 | grep -m 1 XFS
00100000: 5846 5342 0000 1000 0000 0000 0001 f000 0000 0000 0000 0000 0000 0000 0000 0000  XFSB............................

$ printf '%d\n' 0x00100000 | bc
104857600010020

$ xxd -s $((1048576)) -l 32 /dev/loop0
00100000: 5846 5342 0000 1000 0000 0000 0001 f000  XFSB............
00100010: 0000 0000 0000 0000 0000 0000 0000 0000  ................

$ losetup -o 1048576 /dev/loop9 /dev/loop0

$ wipefs /dev/loop9
DEVICE OFFSET TYPE UUID                                 LABEL
loop9  0x0    xfs  bdbe2aca-5ba0-4e2c-a3d0-96798248e075

$ mount -o ro /dev/loop9 /mnt
$ cat /mnt/test.txt
hello world
```


### Linux filesystem: troubleshooting

Get physical location of a file, eg. `/boot/grub2/grub.cfg`.

``` shell
$ ls -l /boot/grub2/grub.cfg
-rw------- 1 root root 10386 May 19 22:23 /boot/grub2/grub.cfg

$ filefrag -v /boot/grub2/grub.cfg
Filesystem type is: 9123683e
File size of /boot/grub2/grub.cfg is 10386 (3 blocks of 4096 bytes)
 ext:     logical_offset:        physical_offset: length:   expected: flags:
   0:        0..       2:     632470..    632472:      3:             last,shared,eof
/boot/grub2/grub.cfg: 1 extent found

$ dd skip=2590597120 if=/dev/mapper/system-root count=10386 ibs=1 2>/dev/null | strings | head
# DO NOT EDIT THIS FILE
# It is automatically generated by grub2-mkconfig using templates
# from /etc/grub.d and settings from /etc/default/grub
### BEGIN /etc/grub.d/00_header ###
set btrfs_relative_path="y"
export btrfs_relative_path
if [ -f ${config_directory}/grubenv ]; then
  load_env -f ${config_directory}/grubenv
elif [ -s $prefix/grubenv ]; then
  load_env
```

TODO: continue over LVM to physical disk...


## GLIBC


### Linux CPU flags

A program can expect that a CPU implements a feature, these are based
on CPU flags, see
https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/master/x86-64-ABI/low-level-sys-info.tex.

``` shell
$ /lib64/ld-linux-x86-64.so.2 --help 2>&1 | tail -n3
  x86-64-v4
  x86-64-v3 (supported, searched)
  x86-64-v2 (supported, searched)
```

The above is a combination of CPU flags; a kind of variety:

``` shell
$ grep -m1 '^flags' /proc/cpuinfo | cut -d: -f2 | xargs -n1 | sort | \
    grep -P '\b(cx16|lahf|popcnt|sse4_1|sse4_2|ssse3)' | nl
     1  cx16
     2  lahf_lm
     3  popcnt
     4  sse4_1
     5  sse4_2
     6  ssse3
```


## Linux firewall


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


## Linux kernel





### Linux kernel configuration

- `/proc/config.gz`


### console

``` shell
$ udevadm info /dev/fb0 | grep -Po 'DEVPATH=\K(.*)' | xargs -I '{}' bash -c "grep -H '' /sys{}/* 2>/dev/null"
/sys/devices/pci0000:00/0000:00:1c.5/0000:02:00.0/0000:03:00.0/graphics/fb0/bits_per_pixel:32
/sys/devices/pci0000:00/0000:00:1c.5/0000:02:00.0/0000:03:00.0/graphics/fb0/dev:29:0
/sys/devices/pci0000:00/0000:00:1c.5/0000:02:00.0/0000:03:00.0/graphics/fb0/modes:U:1024x768p-0
/sys/devices/pci0000:00/0000:00:1c.5/0000:02:00.0/0000:03:00.0/graphics/fb0/name:astdrmfb
/sys/devices/pci0000:00/0000:00:1c.5/0000:02:00.0/0000:03:00.0/graphics/fb0/pan:0,0
/sys/devices/pci0000:00/0000:00:1c.5/0000:02:00.0/0000:03:00.0/graphics/fb0/rotate:0
/sys/devices/pci0000:00/0000:00:1c.5/0000:02:00.0/0000:03:00.0/graphics/fb0/state:0
/sys/devices/pci0000:00/0000:00:1c.5/0000:02:00.0/0000:03:00.0/graphics/fb0/stride:4096
/sys/devices/pci0000:00/0000:00:1c.5/0000:02:00.0/0000:03:00.0/graphics/fb0/uevent:MAJOR=29
/sys/devices/pci0000:00/0000:00:1c.5/0000:02:00.0/0000:03:00.0/graphics/fb0/uevent:MINOR=0
/sys/devices/pci0000:00/0000:00:1c.5/0000:02:00.0/0000:03:00.0/graphics/fb0/uevent:DEVNAME=fb0
/sys/devices/pci0000:00/0000:00:1c.5/0000:02:00.0/0000:03:00.0/graphics/fb0/virtual_size:1024,768
```

Resolution was changed via kernel boot param `video=2560x1600`:

``` shell
$ udevadm info /dev/fb0 | grep -Po 'DEVPATH=\K(.*)' | xargs -I '{}' bash -c "grep -H '' /sys{}/* 2>/dev/null"
/sys/devices/pci0000:00/0000:00:01.0/graphics/fb0/bits_per_pixel:32
/sys/devices/pci0000:00/0000:00:01.0/graphics/fb0/dev:29:0
/sys/devices/pci0000:00/0000:00:01.0/graphics/fb0/modes:U:2560x1600p-0
/sys/devices/pci0000:00/0000:00:01.0/graphics/fb0/name:qxldrmfb
/sys/devices/pci0000:00/0000:00:01.0/graphics/fb0/pan:0,0
/sys/devices/pci0000:00/0000:00:01.0/graphics/fb0/rotate:0
/sys/devices/pci0000:00/0000:00:01.0/graphics/fb0/state:0
/sys/devices/pci0000:00/0000:00:01.0/graphics/fb0/stride:10240
/sys/devices/pci0000:00/0000:00:01.0/graphics/fb0/uevent:MAJOR=29
/sys/devices/pci0000:00/0000:00:01.0/graphics/fb0/uevent:MINOR=0
/sys/devices/pci0000:00/0000:00:01.0/graphics/fb0/uevent:DEVNAME=fb0
/sys/devices/pci0000:00/0000:00:01.0/graphics/fb0/virtual_size:2560,1600

$ grep -H '' /sys/class/drm/*/*Virtual-1/* 2>/dev/null
/sys/class/drm/card0/card0-Virtual-1/dpms:On
/sys/class/drm/card0/card0-Virtual-1/enabled:enabled
/sys/class/drm/card0/card0-Virtual-1/modes:1024x768
/sys/class/drm/card0/card0-Virtual-1/modes:2560x1600
/sys/class/drm/card0/card0-Virtual-1/modes:2560x1600
/sys/class/drm/card0/card0-Virtual-1/modes:1920x1440
/sys/class/drm/card0/card0-Virtual-1/modes:1856x1392
/sys/class/drm/card0/card0-Virtual-1/modes:1792x1344
/sys/class/drm/card0/card0-Virtual-1/modes:2048x1152
/sys/class/drm/card0/card0-Virtual-1/modes:1920x1200
/sys/class/drm/card0/card0-Virtual-1/modes:1920x1200
/sys/class/drm/card0/card0-Virtual-1/modes:1920x1080
/sys/class/drm/card0/card0-Virtual-1/modes:1600x1200
/sys/class/drm/card0/card0-Virtual-1/modes:1680x1050
/sys/class/drm/card0/card0-Virtual-1/modes:1680x1050
/sys/class/drm/card0/card0-Virtual-1/modes:1400x1050
/sys/class/drm/card0/card0-Virtual-1/modes:1400x1050
/sys/class/drm/card0/card0-Virtual-1/modes:1600x900
/sys/class/drm/card0/card0-Virtual-1/modes:1280x1024
/sys/class/drm/card0/card0-Virtual-1/modes:1440x900
/sys/class/drm/card0/card0-Virtual-1/modes:1440x900
/sys/class/drm/card0/card0-Virtual-1/modes:1280x960
/sys/class/drm/card0/card0-Virtual-1/modes:1280x854
/sys/class/drm/card0/card0-Virtual-1/modes:1366x768
/sys/class/drm/card0/card0-Virtual-1/modes:1366x768
/sys/class/drm/card0/card0-Virtual-1/modes:1360x768
/sys/class/drm/card0/card0-Virtual-1/modes:1280x800
/sys/class/drm/card0/card0-Virtual-1/modes:1280x800
/sys/class/drm/card0/card0-Virtual-1/modes:1280x768
/sys/class/drm/card0/card0-Virtual-1/modes:1280x768
/sys/class/drm/card0/card0-Virtual-1/modes:1280x720
/sys/class/drm/card0/card0-Virtual-1/modes:1152x768
/sys/class/drm/card0/card0-Virtual-1/modes:800x600
/sys/class/drm/card0/card0-Virtual-1/modes:800x600
/sys/class/drm/card0/card0-Virtual-1/modes:848x480
/sys/class/drm/card0/card0-Virtual-1/modes:720x480
/sys/class/drm/card0/card0-Virtual-1/modes:640x480
/sys/class/drm/card0/card0-Virtual-1/status:connected
/sys/class/drm/card0/card0-Virtual-1/uevent:DEVTYPE=drm_connector
```

Similar output available via `systool -vc drm`.


``` shell
$ showconsolefont -C /dev/tty0 -iv
Character count: 256
Font width     : 8
Font height    : 16
```

Kernel boot param might be `fbcon=font:TER16x32`, see https://docs.kernel.org/fb/fbcon.html.

Change of font in virtual console can be done via `setfont <font>` or `/etc/vconsole.conf`.

Devices which are system consoles can be queried via:

``` shell
$ cat /sys/devices/virtual/tty/console/active
ttyS1 tty0
```

Getting info about kernel console:

``` shell
$ cat /proc/cmdline | grep -o 'console=[^ ]*' # empty in my case

$ cat /proc/consoles # W=write, EC=echo and console deice
tty0                 -WU (EC  p  )    4:7

$ ls -l /dev/console
crw------- 1 root root 5, 1 Feb 16 10:06 /dev/console # 5,1 is primary console

$ dmesg | grep -iP 'printk:.*console'
[    0.053131] printk: legacy console [tty0] enabled

$ cat /proc/sys/kernel/printk 4 # columns: default level, min level, max level
4       4       1       7
```


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

*corename* format is as follows:

```
* corename format specifiers::

        %<NUL>  '%' is dropped
        %%      output one '%'
        %p      pid
        %P      global pid (init PID namespace)
        %i      tid
        %I      global tid (init PID namespace)
        %u      uid (in initial user namespace)
        %g      gid (in initial user namespace)
        %d      dump mode, matches PR_SET_DUMPABLE and
                /proc/sys/fs/suid_dumpable
        %s      signal number
        %t      UNIX time of dump
        %h      hostname
        %e      executable filename (may be shortened)
        %E      executable path
        %<OTHER> both are dropped
```


#### analysis

NOTE: VM snapshot from VMware environement (`.vmsn` and `.vmem` files)
can be analyzed directly with `crash` tool

Same kernel and kernel debug files have to be present.

``` shell
$ strings /home/vmcore | grep -m 1 -i osrelease
OSRELEASE=5.14.21-150400.24.18-default

# or if newer file/libmagic
$ file /tmp/2024-05-10-15\:53/vmcore | tr ',' '\n'
/tmp/2024-05-10-15:53/vmcore: Kdump compressed dump v6
 system Linux
 node x23
 release 5.14.21-150500.55.59-default
 version #1 SMP PREEMPT_DYNAMIC Thu Apr 18 12:59:33 UTC 2024 (e8ae24a)
 machine x86_64
```

``` shell
$  crash /boot/vmlinux-5.14.21-150400.24.18-default.gz /home/vmcore
...
WARNING: kernel relocated [344MB]: patching 118441 gdb minimal_symbol values

      KERNEL: /boot/vmlinux-5.14.21-150400.24.18-default.gz
   DEBUGINFO: /usr/lib/debug/boot/vmlinux-5.14.21-150400.24.18-default.debug
    DUMPFILE: /home/vmcore  [PARTIAL DUMP]
        CPUS: 8
        DATE: Mon Oct 17 15:17:15 CEST 2022
      UPTIME: 00:59:10
LOAD AVERAGE: 0.39, 0.17, 0.06
       TASKS: 337
    NODENAME: intpocvm015
     RELEASE: 5.14.21-150400.24.18-default
     VERSION: #1 SMP PREEMPT_DYNAMIC Thu Aug 4 14:17:48 UTC 2022 (e9f7bfc)
     MACHINE: x86_64  (2299 Mhz)
      MEMORY: 64 GB
       PANIC: ""
         PID: 62215
     COMMAND: "kfod.bin"
        TASK: ffff8cd0660b4000  [THREAD_INFO: ffff8cd0660b4000]
         CPU: 3
       STATE: TASK_RUNNING (PANIC)

crash> bt 62215
PID: 62215  TASK: ffff8cd0660b4000  CPU: 3   COMMAND: "kfod.bin"
 #0 [ffffa7eb08d8fa80] machine_kexec at ffffffff9687ec63
 #1 [ffffa7eb08d8fad8] __crash_kexec at ffffffff9697fbed
 #2 [ffffa7eb08d8fba0] crash_kexec at ffffffff96980b04
 #3 [ffffa7eb08d8fbb0] oops_end at ffffffff9683ddb8
 #4 [ffffa7eb08d8fbd0] exc_general_protection at ffffffff97234063
 #5 [ffffa7eb08d8fc70] asm_exc_general_protection at ffffffff97400a4e
    [exception RIP: kmem_cache_free+71]
    RIP: ffffffff96b10fa7  RSP: ffffa7eb08d8fd28  RFLAGS: 00010207
    RAX: 014c530d8efa3800  RBX: 531f7ee27e8e05c2  RCX: ffffd34540000000
    RDX: 00000000140f6003  RSI: 531f7ee27e8e05c2  RDI: ffff8cdefffb9200
    RBP: 0000000000000000   R8: 0000000000000000   R9: ffff8cd047059628
    R10: 0000000000020000  R11: 0000000000000000  R12: ffff8ccfea29b800
    R13: 531f7ee2fe8e05c2  R14: 0000000000000000  R15: 0000000000000000
    ORIG_RAX: ffffffffffffffff  CS: 0010  SS: 0018
 #6 [ffffa7eb08d8fd58] __bio_crypt_free_ctx at ffffffff96d1f389
 #7 [ffffa7eb08d8fd68] bio_free at ffffffff96ccd356
 #8 [ffffa7eb08d8fd80] asm_cleanup_bios at ffffffffc0ba916e [oracleasm]
 #9 [ffffa7eb08d8fda8] asmfs_file_read at ffffffffc0ba945e [oracleasm]
#10 [ffffa7eb08d8fdc8] vfs_read at ffffffff96b4710a
#11 [ffffa7eb08d8fdf8] ksys_read at ffffffff96b47525
#12 [ffffa7eb08d8fe38] do_syscall_64 at ffffffff97233468
#13 [ffffa7eb08d8fe68] vfs_read at ffffffff96b4710a
#14 [ffffa7eb08d8feb8] exit_to_user_mode_prepare at ffffffff969531dc
#15 [ffffa7eb08d8fed0] syscall_exit_to_user_mode at ffffffff972376f8
#16 [ffffa7eb08d8fee0] do_syscall_64 at ffffffff97233477
#17 [ffffa7eb08d8ff00] syscall_exit_to_user_mode at ffffffff972376f8
#18 [ffffa7eb08d8ff10] do_syscall_64 at ffffffff97233477
#19 [ffffa7eb08d8ff28] exc_page_fault at ffffffff97236f27
#20 [ffffa7eb08d8ff50] entry_SYSCALL_64_after_hwframe at ffffffff97400099
    RIP: 00007f8b6105d6ce  RSP: 00007ffd934cd4a8  RFLAGS: 00000246
    RAX: ffffffffffffffda  RBX: 00007ffd934cd4d0  RCX: 00007f8b6105d6ce
    RDX: 0000000000000050  RSI: 00007ffd934cd4d0  RDI: 0000000000000009
    RBP: 00007ffd934cdac0   R8: 0000000000000001   R9: 0000000000000000
    R10: 0000000000000000  R11: 0000000000000246  R12: 00000000ffffffff
    R13: 00007ffd934cdcb8  R14: 0000000000000000  R15: 0000000001bae8a0
    ORIG_RAX: 0000000000000000  CS: 0033  SS: 002b

crash> ps -p 62215
PID: 0      TASK: ffffffff9821a940  CPU: 0   COMMAND: "swapper/0"
 PID: 1      TASK: ffff8ccfc021c000  CPU: 4   COMMAND: "systemd"
  PID: 2134   TASK: ffff8ccfc3e58000  CPU: 3   COMMAND: "sshd"
   PID: 58625  TASK: ffff8ccfeedd8000  CPU: 0   COMMAND: "sshd"
    PID: 58669  TASK: ffff8cd051d54000  CPU: 5   COMMAND: "sshd"
     PID: 58817  TASK: ffff8cd014b68000  CPU: 2   COMMAND: "bash"
      PID: 58976  TASK: ffff8ccffe650000  CPU: 3   COMMAND: "gridSetup.sh"
       PID: 58992  TASK: ffff8ccffa774000  CPU: 4   COMMAND: "perl"
        PID: 62214  TASK: ffff8ccfdbe88000  CPU: 1   COMMAND: "java"
         PID: 62215  TASK: ffff8cd0660b4000  CPU: 3   COMMAND: "kfod.bin"

crash> p ((struct task_struct *) 0xffff8cd0660b4000)->cred->uid
$1 = {
  val = 1001
}

crash> sys
      KERNEL: /boot/vmlinux-5.14.21-150400.24.18-default.gz
   DEBUGINFO: /usr/lib/debug/boot/vmlinux-5.14.21-150400.24.18-default.debug
    DUMPFILE: /home/vmcore  [PARTIAL DUMP]
        CPUS: 8
        DATE: Mon Oct 17 15:17:15 CEST 2022
      UPTIME: 00:59:10
LOAD AVERAGE: 0.39, 0.17, 0.06
       TASKS: 337
    NODENAME: intpocvm015
     RELEASE: 5.14.21-150400.24.18-default
     VERSION: #1 SMP PREEMPT_DYNAMIC Thu Aug 4 14:17:48 UTC 2022 (e9f7bfc)
     MACHINE: x86_64  (2299 Mhz)
      MEMORY: 64 GB
       PANIC: ""
```

``` shell
crash> !date --date='2022-12-06 15:02:29' +"%s"
1670335349
```

``` shell
crash> log -T | tail
[Fri May 10 13:52:10 UTC 2024] RIP: 0033:0x7f39e6910263
[Fri May 10 13:52:10 UTC 2024] Code: 0f 1f 80 00 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 64 8b 04 25 18 00 00 00 85 c0 75 14 b8 01 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 55 f3 c3 0f 1f 00 41 54 55 49 89 d4 53 48 89
[Fri May 10 13:52:10 UTC 2024] RSP: 002b:00007ffd02bbd878 EFLAGS: 00000246 ORIG_RAX: 0000000000000001
[Fri May 10 13:52:10 UTC 2024] RAX: ffffffffffffffda RBX: 0000000000000002 RCX: 00007f39e6910263
[Fri May 10 13:52:10 UTC 2024] RDX: 0000000000000002 RSI: 000056262f12dd90 RDI: 0000000000000001
[Fri May 10 13:52:10 UTC 2024] RBP: 000056262f12dd90 R08: 000000000000000a R09: 0000000000000000
[Fri May 10 13:52:10 UTC 2024] R10: 00007f39e6810468 R11: 0000000000000246 R12: 00007f39e69f5500
[Fri May 10 13:52:10 UTC 2024] R13: 0000000000000002 R14: 00007f39e69fac00 R15: 0000000000000002
[Fri May 10 13:52:10 UTC 2024]  </TASK>
[Fri May 10 13:52:11 UTC 2024] Kernel Offset: disabled

crash> log -T | grep -m1 -C 10 sysrq
[Fri May 10 13:48:40 UTC 2024] dlm: 26C3414655214AD98A484083744B44A1: generation 52 slots 4 1:4 2:2 3:3 4:1
[Fri May 10 13:48:40 UTC 2024] dlm: 26C3414655214AD98A484083744B44A1: dlm_recover_directory
[Fri May 10 13:48:40 UTC 2024] dlm: 26C3414655214AD98A484083744B44A1: dlm_recover_directory 4 in 3 new
[Fri May 10 13:48:40 UTC 2024] dlm: 7D854860259C4E52874EC9D8BFDD7277: generation 52 slots 4 1:4 2:2 3:3 4:1
[Fri May 10 13:48:40 UTC 2024] dlm: 7D854860259C4E52874EC9D8BFDD7277: dlm_recover_directory
[Fri May 10 13:48:40 UTC 2024] dlm: 7D854860259C4E52874EC9D8BFDD7277: dlm_recover_directory 2 in 1 new
[Fri May 10 13:48:40 UTC 2024] dlm: 26C3414655214AD98A484083744B44A1: dlm_recover_directory 0 out 3 messages
[Fri May 10 13:48:40 UTC 2024] dlm: 26C3414655214AD98A484083744B44A1: dlm_recover 3 generation 52 done: 84 ms
[Fri May 10 13:48:40 UTC 2024] dlm: 7D854860259C4E52874EC9D8BFDD7277: dlm_recover_directory 0 out 3 messages
[Fri May 10 13:48:41 UTC 2024] dlm: 7D854860259C4E52874EC9D8BFDD7277: dlm_recover 3 generation 52 done: 228 ms
[Fri May 10 13:52:10 UTC 2024] sysrq: Trigger a crash
[Fri May 10 13:52:10 UTC 2024] Kernel panic - not syncing: sysrq triggered crash
[Fri May 10 13:52:10 UTC 2024] CPU: 48 PID: 15658 Comm: bash Tainted: G           O   X    5.14.21-150500.55.59-default #1 SLE15-SP5 3a8569df5696e57cdcb648c7e890af33bdc23f85
[Fri May 10 13:52:10 UTC 2024] Hardware name: HPE ProLiant DL360 Gen10/ProLiant DL360 Gen10, BIOS U32 07/20/2023
[Fri May 10 13:52:10 UTC 2024] Call Trace:
[Fri May 10 13:52:10 UTC 2024]  <TASK>
[Fri May 10 13:52:10 UTC 2024]  dump_stack_lvl+0x45/0x5b
[Fri May 10 13:52:10 UTC 2024]  panic+0x118/0x2f0
[Fri May 10 13:52:10 UTC 2024]  ? printk+0x52/0x72
[Fri May 10 13:52:10 UTC 2024]  sysrq_handle_crash+0x16/0x20
[Fri May 10 13:52:10 UTC 2024]  __handle_sysrq+0x9b/0x160
```

``` shell
crash> files
PID: 4049   TASK: ffff8a7943518000  CPU: 1   COMMAND: "bash"
ROOT: /    CWD: /root
 FD       FILE            DENTRY           INODE       TYPE PATH
  0 ffff8a7944382800 ffff8a794b4a2b40 ffff8a794b57ca20 CHR  /dev/pts/0
  1 ffff8a7943026100 ffff8a794bbe8b40 ffff8a794173e4d8 REG  /proc/sysrq-trigger
  2 ffff8a7944382800 ffff8a794b4a2b40 ffff8a794b57ca20 CHR  /dev/pts/0
 10 ffff8a7944382800 ffff8a794b4a2b40 ffff8a794b57ca20 CHR  /dev/pts/0
255 ffff8a7944382800 ffff8a794b4a2b40 ffff8a794b57ca20 CHR  /dev/pts/0
```


``` shell
# for tainted kernel modules

crash> mod -t
NAME      TAINTS
smartpqi  OX
qla2xxx   OX
```

``` shell
crash> mount
     MOUNT           SUPERBLK     TYPE   DEVNAME   DIRNAME
ffff8881001e1500 ffff88810004b000 rootfs none      /
ffff8881125e5f80 ffff888104789800 proc   proc      /@/.snapshots/1/snapshot/proc
ffff8881125e7d80 ffff88810478f000 sysfs  sysfs     /@/.snapshots/1/snapshot/sys
ffff8881125e4780 ffff88810004e800 devtmpfs devtmpfs /@/.snapshots/1/snapshot/dev
ffff8881125e5080 ffff88810004f000 securityfs securityfs /@/.snapshots/1/snapshot/sys/kernel/security
ffff8881125e5b00 ffff88810478b000 tmpfs  tmpfs     /@/.snapshots/1/snapshot/dev/shm
ffff8881125e4a80 ffff88810478c800 devpts devpts    /@/.snapshots/1/snapshot/dev/pts
ffff8881125e4480 ffff88810478d800 tmpfs  tmpfs     /@/.snapshots/1/snapshot/run
ffff8881125e7780 ffff88810478e800 tmpfs  tmpfs     /@/.snapshots/1/snapshot/sys/fs/cgroup
ffff8881125e7480 ffff88810478f800 cgroup2 cgroup2  /@/.snapshots/1/snapshot/sys/fs/cgroup/unified
ffff8881125e4180 ffff88810478c000 cgroup cgroup    /@/.snapshots/1/snapshot/sys/fs/cgroup/systemd
ffff8881125e5500 ffff888104788000 pstore pstore    /@/.snapshots/1/snapshot/sys/fs/pstore
ffff8881001e0d80 ffff888103431800 efivarfs efivarfs /@/.snapshots/1/snapshot/sys/firmware/efi/efivars
ffff8881001e2a00 ffff888103437000 bpf    bpf       /@/.snapshots/1/snapshot/sys/fs/bpf
ffff8881001e0f00 ffff888103433000 cgroup cgroup    /@/.snapshots/1/snapshot/sys/fs/cgroup/perf_event
ffff8881001e0c00 ffff888103434800 cgroup cgroup    /@/.snapshots/1/snapshot/sys/fs/cgroup/rdma
ffff8881001e2400 ffff888103435800 cgroup cgroup    /@/.snapshots/1/snapshot/sys/fs/cgroup/net_cls,net_prio
ffff8881001e1980 ffff888103436800 cgroup cgroup    /@/.snapshots/1/snapshot/sys/fs/cgroup/hugetlb
ffff8881001e0600 ffff88810007b000 cgroup cgroup    /@/.snapshots/1/snapshot/sys/fs/cgroup/memory
ffff8881001e0900 ffff88810007c800 cgroup cgroup    /@/.snapshots/1/snapshot/sys/fs/cgroup/devices
ffff8881001e2e80 ffff88810007d800 cgroup cgroup    /@/.snapshots/1/snapshot/sys/fs/cgroup/cpu,cpuacct
ffff8881001e1e00 ffff88810007e800 cgroup cgroup    /@/.snapshots/1/snapshot/sys/fs/cgroup/pids
ffff8881001e3900 ffff88810007f800 cgroup cgroup    /@/.snapshots/1/snapshot/sys/fs/cgroup/freezer
ffff8881001e2100 ffff88810007c000 cgroup cgroup    /@/.snapshots/1/snapshot/sys/fs/cgroup/cpuset
ffff8881001e2d00 ffff888100078000 cgroup cgroup    /@/.snapshots/1/snapshot/sys/fs/cgroup/blkio
ffff8881001e1800 ffff88810007b800 cgroup cgroup    /@/.snapshots/1/snapshot/sys/fs/cgroup/misc
ffff888124011f80 ffff88812cb0e000 btrfs  /dev/sdb2 /
ffff888122789980 ffff88810f0c7800 autofs systemd-1 /@/.snapshots/1/snapshot/proc/sys/fs/binfmt_misc
ffff888109188900 ffff8881027a8800 mqueue mqueue    /@/.snapshots/1/snapshot/dev/mqueue
ffff88810918ae80 ffff88810004f800 debugfs debugfs  /@/.snapshots/1/snapshot/sys/kernel/debug
ffff88811bd06700 ffff8881034b6000 tracefs tracefs  /@/.snapshots/1/snapshot/sys/kernel/tracing
ffff888102cf6700 ffff88812cfc7800 xenfs  xenfs     /@/.snapshots/1/snapshot/proc/xen
ffff88811bd06880 ffff88810a7c3000 fusectl fusectl  /@/.snapshots/1/snapshot/sys/fs/fuse/connections
ffff88811ddab300 ffff88812d34a800 configfs configfs /@/.snapshots/1/snapshot/sys/kernel/config
ffff888198478180 ffff88812cb0e000 btrfs  /dev/sdb2 /@/.snapshots/1/snapshot/.snapshots
ffff88818824fa80 ffff88812cb0e000 btrfs  /dev/sdb2 /@/.snapshots/1/snapshot/boot/grub2/i386-pc
ffff88819847a880 ffff88812cb0e000 btrfs  /dev/sdb2 /@/.snapshots/1/snapshot/boot/grub2/x86_64-efi
ffff888124947d80 ffff88812cb0e000 btrfs  /dev/sdb2 /@/.snapshots/1/snapshot/home
ffff8881001e2580 ffff88812cb0e000 btrfs  /dev/sdb2 /@/.snapshots/1/snapshot/opt
ffff888102cf6880 ffff88812cb0e000 btrfs  /dev/sdb2 /@/.snapshots/1/snapshot/srv
ffff8881125e5680 ffff88812cb0e000 btrfs  /dev/sdb2 /@/.snapshots/1/snapshot/usr/local
ffff8881053b8480 ffff88812cb0e000 btrfs  /dev/sdb2 /@/.snapshots/1/snapshot/tmp
ffff888124944480 ffff88812cb0e000 btrfs  /dev/sdb2 /@/.snapshots/1/snapshot/var
ffff888106235b00 ffff88812dca7000 vfat   /dev/sdb1 /@/.snapshots/1/snapshot/boot/efi
ffff88818dcaf600 ffff88811bab7000 tmpfs  tmpfs     /@/.snapshots/1/snapshot/run/user/600
ffff8881251b2100 ffff8881910ca800 ocfs2  /dev/mapper/ocfs2-pm_01-part1 /@/.snapshots/1/snapshot/media/ocfs2_01
ffff8881be9d7d80 ffff88812d919000 ocfs2  /dev/mapper/ocfs2-pm_02-part1 /@/.snapshots/1/snapshot/media/ocfs2_02
ffff88819ab65200 ffff88811bfbd000 tmpfs  tmpfs     /@/.snapshots/1/snapshot/run/user/0
ffff8880066cd680 ffff888188d19800 fuse   gvfsd-fuse /@/.snapshots/1/snapshot/run/user/0/gvfs
```

``` shell
crash> p vm_swappiness
vm_swappiness = $2 = 60
```

Another example, here the panic reveals:

``` shell
crash> sys
      KERNEL: vmlinux-4.12.14-122.219.1.28275.1.PTF.1227122-default  [TAINTED]
   DEBUGINFO: vmlinux-4.12.14-122.219.1.28275.1.PTF.1227122-default.debug
    DUMPFILE: vmcore  [PARTIAL DUMP]
        CPUS: 40
        DATE: Tue Jul  2 15:30:47 CEST 2024
      UPTIME: 03:22:08
LOAD AVERAGE: 36.69, 13.33, 4.82
       TASKS: 709
    NODENAME: example1
     RELEASE: 4.12.14-122.219.1.28275.1.PTF.1227122-default
     VERSION: #1 SMP Thu Jun 27 21:40:03 UTC 2024 (daeeee0)
     MACHINE: x86_64  (2596 Mhz)
      MEMORY: 127.9 GB
       PANIC: "Kernel panic - not syncing: panic_on_warn set ..."

crash> p panic_on_warn
panic_on_warn = $12 = 0
```

Huh? The system had `/proc/sys/kernel/panic_on_warn` set to `1`, so
why is `panic_on_warn` in `crash` zero?

```
kernel/panic.c:panic()

        if (panic_on_warn) {
                /*
                 * This thread may hit another WARN() in the panic path.
                 * Resetting this prevents additional WARN() from panicking the
                 * system on this thread.  Other threads are blocked by the
                 * panic_mutex in panic().
                 */
                panic_on_warn = 0;
        }
```

Miracles!


### tracing

* systemtap - generated a kernel module, thus if using SecureBoot it has to be signed
* ftrace - works out of the box

``` shell
$ readelf -s $(which lvmlockd) | awk 'NR > 3 && $4 == "FUNC" && !/UND/' | sort -k8 | nl | head
     1     261: 0000000000009b40    34 FUNC    GLOBAL DEFAULT   16 _start
     2     471: 0000000000026100    53 FUNC    GLOBAL DEFAULT   16 add_dev_node
     3     409: 000000000000e990   125 FUNC    GLOBAL DEFAULT   16 alloc_lockspace
     4     279: 000000000001dac0    99 FUNC    GLOBAL DEFAULT   16 buffer_append
     5     482: 000000000001de00   182 FUNC    GLOBAL DEFAULT   16 buffer_append_f
     6     420: 000000000001db30   720 FUNC    GLOBAL DEFAULT   16 buffer_append_vf
     7     429: 000000000001df10    22 FUNC    GLOBAL DEFAULT   16 buffer_destroy
     8     498: 000000000001df00    16 FUNC    GLOBAL DEFAULT   16 buffer_init
     9     435: 000000000001dec0    49 FUNC    GLOBAL DEFAULT   16 buffer_line
    10     314: 000000000001ce80   423 FUNC    GLOBAL DEFAULT   16 buffer_read
```


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


Troubleshooting could be done with `KDUMP_IMMEDIATE_REBOOT=no` and
with serial console enabled:

``` shell
...
         Starting save kernel crash dump...
Cannot blink LEDs: Unable to ioctl(KDSETLED) -- are you not on the console? (Inappropriate ioctl for device)Extracting dmesg
-------------------------------------------------------------------------------
.

The dmesg log is saved to /kdump/mnt1/var/crash/2023-02-10-11:00/dmesg.txt.

makedumpfile Completed.
-------------------------------------------------------------------------------
Saving dump using makedumpfile
-------------------------------------------------------------------------------
Copying data                                      : [100.0 %] |           eta: 0s

The dumpfile is saved to /kdump/mnt1/var/crash/2023-02-10-11:00/vmcore.

makedumpfile Completed.
-------------------------------------------------------------------------------
Generating README              Finished.
Copying System.map             Finished.
Copying kernel                 Finished.

Dump saving completed.
Type 'reboot -f' to reboot the system or 'exit' to
resume the boot process.
sh-4.4#
```


### kdump inside cluster

If there would be a crash and kdump would be running to save kernel
memory image, one does not want that the cluster fences the node
running kdump collection activity.

``` shell
$ grep -Pv '(^\s*(#|$)|="")' /etc/sysconfig/kdump
KDUMP_AUTO_RESIZE="no"
KDUMP_IMMEDIATE_REBOOT="no"
KDUMP_SAVEDIR="/var/crash"
KDUMP_KEEP_OLD_DUMPS="5"
KDUMP_FREE_DISK_SIZE="64"
KDUMP_VERBOSE="3"
KDUMP_DUMPLEVEL="31"
KDUMP_DUMPFORMAT="lzo"
KDUMP_CONTINUE_ON_ERROR="true"
KDUMP_POSTSCRIPT="/usr/lib/fence_kdump_send -v -f ipv4 -i 5 -c 5 jb154sapqe01 jb154sapqe02"
KDUMP_COPY_KERNEL="yes"
KDUMP_NETCONFIG="auto"
KDUMP_NET_TIMEOUT="30
```

The cluster configuration - it adds `fence_kdump`-based stonith device
and modifies fencing topology in a way, that if if a message from
`fence_kdump_send` arrives, then the node wanting to fence the node
being in kdump activity will give actual fence as it thinks the fence
already occurred.

```
primitive stonith-kdump-jb154sapqe01 stonith:fence_kdump \
        params nodename=jb154sapqe01 \
        pcmk_host_check=static-list \
        pcmk_reboot_action=off \
        pcmk_monitor_action=metadata \
        pcmk_reboot_retries=1 \
        timeout=60
primitive stonith-kdump-jb154sapqe02 stonith:fence_kdump \
        params nodename=jb154sapqe02 \
        pcmk_host_check=static-list \
        pcmk_reboot_action=off \
        pcmk_monitor_action=metadata \
        pcmk_reboot_retries=1 \
        timeout=60
primitive stonith-sbd stonith:external/sbd \
        params pcmk_delay_max=30
location l-stonith-kdump-jb154sapqe01 stonith-kdump-jb154sapqe01 inf: jb154sapqe01
location l-stonith-kdump-jb154sapqe02 stonith-kdump-jb154sapqe02 inf: jb154sapqe02
fencing_topology \
        jb154sapqe01: stonith-kdump-jb154sapqe01 stonith-sbd \
        jb154sapqe02: stonith-kdump-jb154sapqe02 stonith-sbd
```

Logged `fence_kdump_send` message causing return value for stonith action to be '0'.

```
Feb 10 12:13:56 jb154sapqe02 pacemaker-fenced[2566]:  notice: Operation 'reboot' [18940] targeting jb154sapqe01 using stonith-sbd returned 0 (OK)
Feb 10 12:13:56 jb154sapqe02 pacemaker-fenced[2566]:  notice: Action 'reboot' targeting jb154sapqe01 using stonith-sbd on behalf of pacemaker-controld.2570@jb154sapqe02: OK
Feb 10 12:13:56 jb154sapqe02 pacemaker-fenced[2566]:  error: Already sent notifications for 'reboot' targeting jb154sapqe01 by jb154sapqe02 for client pacemaker-controld.2570@jb154sapqe02: OK
Feb 10 12:14:07 jb154sapqe02 pacemaker-fenced[2566]:  notice: Operation 'reboot' [18967] targeting jb154sapqe01 using stonith-sbd returned 0 (OK)
```

Network inspection of `fence_kdump_send` messages...

``` shell
$ tshark -i eth0 -f 'port 7410'
Running as user "root" and group "root". This could be dangerous.
Capturing on 'eth0'
 ** (tshark:18698) 12:12:56.681615 [Main MESSAGE] -- Capture started.
 ** (tshark:18698) 12:12:56.682024 [Main MESSAGE] -- File: "/tmp/wireshark_eth0UYXD01.pcapng"
    1 0.000000000 192.168.0.57 → 192.168.0.61 UDP 50 60006 → 7410 Len=8
    2 5.420996300 192.168.0.57 → 192.168.0.61 UDP 50 60006 → 7410 Len=8
    3 10.842449536 192.168.0.57 → 192.168.0.61 UDP 50 60006 → 7410 Len=8
    4 16.267093402 192.168.0.57 → 192.168.0.61 UDP 50 60006 → 7410 Len=8

```

### modules

kernel modules are usually loaded by `udev` based *uevent*, see [udev](#udev).

Blacklisting a module is either via file definition or via
`module_blacklist` kernel param, see [The kernel's command-line
parameters](https://www.kernel.org/doc/html/v5.13/admin-guide/kernel-parameters.html).

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

If multiple modules with same name exists, the priority can be defined
with `depmod.d(5)`. An example:

``` shell
$ rpm -qlp hpsa-kmp-default-3.4.20-208.sles12sp5.x86_64.rpm
warning: hpsa-kmp-default-3.4.20-208.sles12sp5.x86_64.rpm: Header V3 RSA/SHA256 Signature, key ID 26c2b797: NOKEY
/lib/modules/4.12.14-120-default
/lib/modules/4.12.14-120-default/updates
/lib/modules/4.12.14-120-default/updates/hpsa.ko
/usr/share/smartupdate/hpsa-kmp-default/component.xml

$ whatis depmod.d
depmod.d (5)         - Configuration directory for depmod

$ grep -Pv '^\s*(#|$)' /lib/depmod.d/*.conf
search updates extra weak-updates kgraft built-in
make_map_files no
```

So, it's clear what modules in 'update' have precedence over "classic"
in-tree modules.


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

Extracting initrd... (something odd with kdump-save binary here).

``` shell
$ /usr/lib/dracut/skipcpio initrd-5.14.21-150400.24.18-default-kdump | \
    xzcat -- | ( cd /tmp/kdump ; cpio -id)
$ objdump -p /tmp/kdump/kdump/kdump-save | grep NEEDED
  NEEDED               libz.so.1
  NEEDED               libelf.so.1
  NEEDED               libcurl.so.4
  NEEDED               libesmtp.so.6
  NEEDED               libmount.so.1
  NEEDED               libstdc++.so.6
  NEEDED               libgcc_s.so.1
  NEEDED               libc.so.6
$ find /tmp/kdump -type f -name 'lib*' | grep -c curl
0
```

### /proc

https://www.kernel.org/doc/html/latest/admin-guide/sysrq.html


### swap and memory

Terminology:

- swapping: refers to a mechanism originally adopted in the UNIX
  System versions of AT&T Bell Lab, and to copying the entire process
  address space, or at any rate, the non-shareable text data segment,
  out to the swap, or back, in one go. Generally an obsoleted
  "strategy".
- swap out/swap in: moving out and "importing" back memory of a process
- paging: refers to a mechanism originally added to UNIX BSD variants,
  and to copying in/out one or more pages of the address space.
- page cache: data in memory for read file to avoid expensive disk
  access on the subsequent reads; relates to _disk buffering. Since
  2.4.10 the _buffer cache_ (the contents of the blocks accessed by
  the VFS) does not really exit anymore; _block buffers_ are stored as
  _buffer pages_ in the page cache. This also works for _writes_
- dirty page: a page in cache that has been changed in memory and
  needs to be written back to disk, `kdmflush` treads periodically
  writes dirty pages to the underlying storage device.
- anonymous memory/anonymous mappings: represents a memory that is not
  backed by a filesystem, ie. mappings for a program's stack and heap
  or by explicit calls to `mmap(2)`.
- reclaimable memory: pages that can be swapped out, eg. page cache or
  anonymous memory.
- unreclaimable memory: not to be swapped out, eg. internal kernel
  data or DMA buffers...
- OOM killer: an operation to kill a task in a hope that after it
  exists enough memory will be freed to save the rest of the system,
  ie. kernel is unable to reclaim enough memory to continue to
  operate.
- compaction: defragmantation of memory.

How to check what has been swapped out:

``` shell
$ smem -U jiri | head
  PID User     Command                         Swap      USS      PSS      RSS
 4678 jiri     /bin/bash -c set -o pipefai      324        4        8     1564
 4680 jiri     grep -v INFO:                    188        4        8     1552
 5760 jiri     /bin/bash                        352        4        8     1524
 5782 jiri     /opt/google/chrome/nacl_hel      356        4        9     1632
 5769 jiri     cat                              144        4       11     1432
 5691 jiri     -bash                           2764        8       17     1968
 4713 jiri     /usr/libexec/gdm/gdm-x-sess      592       12       18     2172
 5720 jiri     -bash                           2660       12       21     1992
 5776 jiri     /opt/google/chrome/chrome_c      296       20       23     1360

$ grep '^VmSwap' /proc/5776/status
VmSwap:      296 kB
```

Tunning options:

- `vm.swappiness`: value represents the percentage of the free memory
  before swapping out application data (as anonymous pages); it also
  controls the degree to which the system favors anonymous pages or
  the page cache. A high value improves file-system performance, while
  aggressively swapping less active processes out of physical
  memory. A low value avoids swapping processes out of memory, which
  usually decreases latency, at the cost of I/O performance.

## network

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


### NetworkManager

NetworkManager with _dnsmasq_ and _dnscrypt-proxy_:

``` shell
$ grep -H '' /etc/NetworkManager/conf.d/dns.conf /usr/lib/systemd/system/dnscrypt-proxy.socket
/etc/NetworkManager/conf.d/dns.conf:[main]
/etc/NetworkManager/conf.d/dns.conf:dns=dnsmasq
/etc/NetworkManager/conf.d/dns.conf:
/etc/NetworkManager/conf.d/dns.conf:[global-dns-domain-*]
/etc/NetworkManager/conf.d/dns.conf:servers=127.0.2.1
/usr/lib/systemd/system/dnscrypt-proxy.socket:[Unit]
/usr/lib/systemd/system/dnscrypt-proxy.socket:Description=dnscrypt-proxy listening socket
/usr/lib/systemd/system/dnscrypt-proxy.socket:Documentation=https://github.com/DNSCrypt/dnscrypt-proxy/wiki
/usr/lib/systemd/system/dnscrypt-proxy.socket:Before=nss-lookup.target
/usr/lib/systemd/system/dnscrypt-proxy.socket:Wants=nss-lookup.target
/usr/lib/systemd/system/dnscrypt-proxy.socket:Wants=dnscrypt-proxy-resolvconf.service
/usr/lib/systemd/system/dnscrypt-proxy.socket:
/usr/lib/systemd/system/dnscrypt-proxy.socket:[Socket]
/usr/lib/systemd/system/dnscrypt-proxy.socket:ListenStream=127.0.2.1:53
/usr/lib/systemd/system/dnscrypt-proxy.socket:ListenDatagram=127.0.2.1:53
/usr/lib/systemd/system/dnscrypt-proxy.socket:NoDelay=true
/usr/lib/systemd/system/dnscrypt-proxy.socket:DeferAcceptSec=1
/usr/lib/systemd/system/dnscrypt-proxy.socket:
/usr/lib/systemd/system/dnscrypt-proxy.socket:[Install]
/usr/lib/systemd/system/dnscrypt-proxy.socket:WantedBy=sockets.targe

# `pkill -USR1 -f dnsmasq' will show in the journal
Jan 12 13:28:17 hostname dnsmasq[439980]: time 1705062497
Jan 12 13:28:17 hostname dnsmasq[439980]: cache size 1000, 0/32 cache insertions re-used unexpired cache entries.
Jan 12 13:28:17 hostname dnsmasq[439980]: queries forwarded 16, queries answered locally 20
Jan 12 13:28:17 hostname dnsmasq[439980]: queries for authoritative zones 0
Jan 12 13:28:17 hostname dnsmasq[439980]: pool memory in use 3024, max 4416, allocated 48000
Jan 12 13:28:17 hostname dnsmasq[439980]: server 127.0.2.1#53: queries sent 31, retried 0, failed 0, nxdomain replies 0, avg. latency 123ms
```

#### network-manager-openvpn

OpenVPN is under NM slice:

``` shell
$ systemd-cgls --no-pager -a -l -u NetworkManager.service
Unit NetworkManager.service (/system.slice/NetworkManager.service):
├─11603 /usr/libexec/nm-openvpn-service --debug
├─19797 /usr/sbin/NetworkManager --no-daemon
├─19969 /usr/sbin/openvpn --remote gate1.example.com 1194 udp --remote gate2.example.com 1194 udp --remote gate1.example.com 443 tcp-client --remote gate2.example.com 443 tcp-client --allow-compression no --ping 10 --ping-restart 30 --connect-timeout 20 --nobind --dev exampleovpn --dev-type tun --cipher AES-256-CBC --data-ciphers AES-256-CBC --auth SHA512 --auth-nocache --tls-auth /home/jiri/.cert/nm-openvpn/EXAMPLE-OpenVPN-tls-auth.pem 1 --remote-cert-tls server --reneg-sec 0 --verb 1 --syslog nm-openvpn --script-security 2 --up /usr/libexec/nm-openvpn-service-openvpn-helper --debug 0 11603 --bus-name org.freedesktop.NetworkManager.openvpn --tun -- --up-restart --persist-key --persist-tun --management /var/run/NetworkManager/nm-openvpn-f8cc0539-cb3d-4f95-b9f7-17c86f6b05fc unix --management-client-user root --management-client-group root --management-query-passwords --auth-retry interact --route-noexec --ifconfig-noexec --client --ca /home/jiri/.cert/nm-openvpn/EXAMPLE-OpenVPN-ca.pem --cert /home/jiri/.cert/nm-openvpn/EXAMPLE-OpenVPN-cert.pem --key /home/jiri/.cert/nm-openvpn/EXAMPLE-OpenVPN-key.pem --auth-user-pass --user nm-openvpn --group nm-openvpn
└─20002 /usr/sbin/dnsmasq --no-resolv --keep-in-foreground --no-hosts --bind-interfaces --pid-file=/run/NetworkManager/dnsmasq.pid --listen-address=127.0.0.1 --cache-size=400 --clear-on-reload --conf-file=/dev/null --enable-dbus=org.freedesktop.NetworkManager.dnsmasq --conf-dir=/etc/NetworkManager/dnsmasq.d
```

And it uses OpenVPN management channel to talk to OpenVPN:

``` shell
$ ss -xnlp | grep 19969
u_str LISTEN 0      1      /var/run/NetworkManager/nm-openvpn-f8cc0539-cb3d-4f95-b9f7-17c86f6b05fc 313720            * 0    users:(("openvpn",pid=19969,fd=4))
$ nmcli c s | grep f8cc
EXAMPLE-OpenVPN        f8cc0539-cb3d-4f95-b9f7-17c86f6b05fc  vpn       wlp3s0
```


### SR-IOV

``` shell
$ grep -P 'iommu' /etc/default/grub
GRUB_CMDLINE_LINUX_DEFAULT="console=ttyS2,115200 resume=/dev/system/swap rd.shell=0 crashkernel=196M,high crashkernel=72M,low mitigations=auto intel_iommu=on iommu=pt"

$ grub2-mkconfig -o /boot/grub2/grub.cfg # and reboot
```

After reboot:

``` shell
$ dmesg | grep -iP '(DMAR|IOMMU)'
<6>[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-5.3.18-150300.59.49-default root=/dev/mapper/system-root console=ttyS2,115200 resume=/dev/system/swap rd.shell=0 crashkernel=196M,high crashkernel=72M,low mitigations=auto intel_iommu=on iommu=pt
<6>[    0.031190] ACPI: DMAR 0x00000000BF7B00F0 000090 (v01 AMI    OEMDMAR  00000001 MSFT 00000097)
<5>[    0.380718] Kernel command line: BOOT_IMAGE=/boot/vmlinuz-5.3.18-150300.59.49-default root=/dev/mapper/system-root console=ttyS2,115200 resume=/dev/system/swap rd.shell=0 crashkernel=196M,high crashkernel=72M,low mitigations=auto intel_iommu=on iommu=pt
<6>[    0.380963] DMAR: IOMMU enabled
<6>[    1.225392] DMAR: Host address width 36
<6>[    1.229236] DMAR: DRHD base: 0x000000fed90000 flags: 0x1
<6>[    1.234564] DMAR: dmar0: reg_base_addr fed90000 ver 1:0 cap c90780106f0462 ecap f020e3
<6>[    1.242476] DMAR: RMRR base: 0x000000000ed000 end: 0x000000000effff
<6>[    1.248744] DMAR: RMRR base: 0x000000bf7ed000 end: 0x000000bf7fffff
<6>[    3.167095] iommu: Default domain type: Passthrough (set via kernel command line)
<6>[    6.337209] DMAR: No ATSR found
<6>[    6.340429] DMAR: dmar0: Using Queued invalidation
<6>[    6.345333] pci 0000:00:00.0: Adding to iommu group 0
<6>[    6.350412] pci 0000:00:03.0: Adding to iommu group 1
<6>[    6.355485] pci 0000:00:05.0: Adding to iommu group 2
<6>[    6.360556] pci 0000:00:08.0: Adding to iommu group 3
<6>[    6.365625] pci 0000:00:08.1: Adding to iommu group 4
<6>[    6.370696] pci 0000:00:08.2: Adding to iommu group 5
<6>[    6.375776] pci 0000:00:08.3: Adding to iommu group 6
<6>[    6.380861] pci 0000:00:10.0: Adding to iommu group 7
<6>[    6.385932] pci 0000:00:10.1: Adding to iommu group 7
<6>[    6.391002] pci 0000:00:1a.0: Adding to iommu group 8
<6>[    6.396071] pci 0000:00:1c.0: Adding to iommu group 9
<6>[    6.401142] pci 0000:00:1c.4: Adding to iommu group 10
<6>[    6.406301] pci 0000:00:1c.5: Adding to iommu group 11
<6>[    6.411458] pci 0000:00:1d.0: Adding to iommu group 12
<6>[    6.416613] pci 0000:00:1e.0: Adding to iommu group 13
<6>[    6.421792] pci 0000:00:1f.0: Adding to iommu group 14
<6>[    6.426950] pci 0000:00:1f.2: Adding to iommu group 14
<6>[    6.432110] pci 0000:00:1f.3: Adding to iommu group 14
<6>[    6.437268] pci 0000:02:00.0: Adding to iommu group 15
<6>[    6.442426] pci 0000:02:00.1: Adding to iommu group 16
<6>[    6.447579] pci 0000:03:00.0: Adding to iommu group 17
<6>[    6.452737] pci 0000:03:00.1: Adding to iommu group 18
<6>[    6.457892] pci 0000:04:00.0: Adding to iommu group 19
<6>[    6.463049] pci 0000:05:00.0: Adding to iommu group 20
<6>[    6.468195] pci 0000:06:03.0: Adding to iommu group 13
<6>[    6.473364] pci 0000:ff:00.0: Adding to iommu group 21
<6>[    6.478525] pci 0000:ff:00.1: Adding to iommu group 21
<6>[    6.483693] pci 0000:ff:02.0: Adding to iommu group 22
<6>[    6.488855] pci 0000:ff:02.1: Adding to iommu group 22
<6>[    6.494041] pci 0000:ff:03.0: Adding to iommu group 23
<6>[    6.499204] pci 0000:ff:03.1: Adding to iommu group 23
<6>[    6.504359] pci 0000:ff:03.2: Adding to iommu group 23
<6>[    6.509517] pci 0000:ff:03.4: Adding to iommu group 23
<6>[    6.514704] pci 0000:ff:04.0: Adding to iommu group 24
<6>[    6.519866] pci 0000:ff:04.1: Adding to iommu group 24
<6>[    6.525022] pci 0000:ff:04.2: Adding to iommu group 24
<6>[    6.530178] pci 0000:ff:04.3: Adding to iommu group 24
<6>[    6.535367] pci 0000:ff:05.0: Adding to iommu group 25
<6>[    6.540531] pci 0000:ff:05.1: Adding to iommu group 25
<6>[    6.545695] pci 0000:ff:05.2: Adding to iommu group 25
<6>[    6.550858] pci 0000:ff:05.3: Adding to iommu group 25
<6>[    6.556040] DMAR: Intel(R) Virtualization Technology for Directed I/O
```

Define number of VFs:

``` shell
$ grep -RH '' $(readlink -f /sys/class/net/{hor,dol}[01]/../../sriov_totalvfs)
/sys/devices/pci0000:00/0000:00:05.0/0000:02:00.1/sriov_totalvfs:7
/sys/devices/pci0000:00/0000:00:05.0/0000:02:00.0/sriov_totalvfs:7
/sys/devices/pci0000:00/0000:00:1c.0/0000:03:00.1/sriov_totalvfs:7
/sys/devices/pci0000:00/0000:00:1c.0/0000:03:00.0/sriov_totalvfs:7

# or via

$ lspci -vv -s 03:00.1 | grep VFs
                Initial VFs: 8, Total VFs: 8, Number of VFs: 7, Function Dependency Link: 01
```

Try to set `sriov_numvfs`:

``` shell
$ readlink -f /sys/class/net/{hor,dol}[01] | while read s; do echo 7 > ${s%%/net*}/sriov_numvfs ; done
-bash: P�: write error: Cannot allocate memory
-bash: ���U: write error: Cannot allocate memory
```

Oh, but this is a known issue for some HW, see
https://bugzilla.redhat.com/show_bug.cgi?id=1223376 and
https://www.kernel.org/doc/html/v5.3/admin-guide/kernel-parameters.html. Thus
try to add `pci=realloc` or `pci=assign-busses` (the latter worked for
me!) as another kernel boot parameter:

So final attemp to set VFs:

``` shell
$ cat /proc/cmdline
BOOT_IMAGE=/boot/vmlinuz-5.3.18-150300.59.49-default root=/dev/mapper/system-root console=ttyS2,115200 console=tty0 resume=/dev/system/swap rd.shell=0 crashkernel=196M,high crashkernel=72M,low mitigations=auto intel_iommu=on iommu=pt pci=assign-busses

$ cat /etc/modules-load.d/99-vfio.conf
vfio_iommu_type1
vfio-pci

$ cat /etc/modprobe.d/99-local.conf
options vfio_iommu_type1 allow_unsafe_interrupts=1
softdep igb pre: vfio-pci
```

Rebuilt initramds and after boot:

``` shell
$ readlink -f /sys/class/net/{hor,dol}[01] | while read s; do echo 7 > ${s%%/net*}/sriov_numvfs ; done

$ readlink -f /sys/class/net/{{hor,dol}[01],eth!(0|1)} | sort -t / -k 6 | wc -l
32
```

From 2 dual-port network cards - 82576 Gigabit Network Connection
(Gigabit ET Dual Port Server Adapter) - I got 32 interfaces.

Since I'm going to use the VFs inside libvirt VMs, let's automate this
`sriov_numvfs` increase action - note I'm doing that only for network
interfaces with names *hor0*, *hor1*, *dol0*, *dol1*.

``` shell
$ systemctl --no-pager cat sriov_numvfs.service
# /etc/systemd/system/sriov_numvfs.service
[Unit]
Before=libvirtd.service

[Service]
Type=oneshot
RemainAfterExit=true
ExecStart=/bin/bash -c ' \
    /usr/bin/readlink -f /sys/class/net/{hor,dol}[01] | \
    while read i; do \
        echo 7 > $${i%%/net*}/sriov_numvfs ; \
    done'

[Install]
WantedBy=multi-user.target
```

Details about physical ports:

``` shell
# only physical ports have sriov_totalvfs file

$ dirname /sys/class/net/*/../../sriov_totalvfs | grep -Po '/net/\K([^/]+)(?=.*)'
eth1
eth3
eth4
eth5

 $  dirname /sys/class/net/*/../../sriov_totalvfs | grep -Po '/net/\K([^/]+)(?=.*)' | while read l ; do ip link show $l ; done
3: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether 90:e2:ba:04:28:c0 brd ff:ff:ff:ff:ff:ff
    vf 0     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 1     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 2     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 3     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 4     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 5     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 6     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    altname enp2s0f0
5: eth3: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether 90:e2:ba:04:28:c1 brd ff:ff:ff:ff:ff:ff
    vf 0     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 1     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 2     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 3     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 4     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 5     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 6     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    altname enp2s0f1
6: eth4: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether 90:e2:ba:04:2d:74 brd ff:ff:ff:ff:ff:ff
    vf 0     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 1     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 2     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 3     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 4     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 5     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 6     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    altname enp3s0f0
7: eth5: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether 90:e2:ba:04:2d:75 brd ff:ff:ff:ff:ff:ff
    vf 0     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 1     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 2     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 3     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 4     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 5     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
    vf 6     link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff, spoof checking on, link-state auto, trust off
```

There are various options for VFs, see `ip-link(8)`:

```
spoofchk on|off - turn packet spoof checking on or
off for the specified VF.

...

state auto|enable|disable - set the virtual link state
as seen by the specified VF. Setting to auto means a
reflection of the PF link state, enable lets the VF
to communicate with other VFs on this host even if
the PF link state is down, disable causes the HW to
drop any packets sent by the VF.

trust on|off - trust the specified VF user. This
enables that VF user can set a specific feature which
may impact security and/or performance. (e.g. VF
multicast promiscuous mode)
```

**TODO**: under construction

A VM using VFs cannot change MAC address:

``` shell
vm $ dmesg | grep bond
[    8.045478] bond0: (slave eth0): Enslaving as a backup interface with a down link
[    8.345013] bond0: (slave eth1): Error -99 calling set_mac_address
[    8.697019] bond0: (slave eth0): link status definitely up, 1000 Mbps full duplex
[    8.697661] bond0: (slave eth0): making interface the new active one
[    8.715159] bond0: active interface up!
[    8.716329] IPv6: ADDRCONF(NETDEV_CHANGE): bond0: link becomes ready
[  503.892194] bond0: (slave eth1): Error -99 calling set_mac_address
```

On host, one can see:

``` shell
host $ dmesg -w
[18019.275993] igb 0000:03:00.0: VF 0 attempted to override administratively set MAC address
               Reload the VF driver to resume operations
```

Looking for VFs and back...

``` shell
# PFs

host $ ls -1 /sys/devices/*/*/*/net/eth*/../../sriov_totalvfs
/sys/devices/pci0000:00/0000:00:05.0/0000:02:00.0/net/eth1/../../sriov_totalvfs
/sys/devices/pci0000:00/0000:00:05.0/0000:02:00.1/net/eth3/../../sriov_totalvfs
/sys/devices/pci0000:00/0000:00:1c.0/0000:03:00.0/net/eth4/../../sriov_totalvfs
/sys/devices/pci0000:00/0000:00:1c.0/0000:03:00.1/net/eth5/../../sriov_totalvfs

# looking for VFs related to eth4 PF

host $ ls -1d $(readlink -f /sys/class/net/eth4)/../../virtfn*/net/*
/sys/devices/pci0000:00/0000:00:1c.0/0000:03:00.0/net/eth4/../../virtfn0/net/eth0
/sys/devices/pci0000:00/0000:00:1c.0/0000:03:00.0/net/eth4/../../virtfn1/net/eth2
/sys/devices/pci0000:00/0000:00:1c.0/0000:03:00.0/net/eth4/../../virtfn2/net/eth20
/sys/devices/pci0000:00/0000:00:1c.0/0000:03:00.0/net/eth4/../../virtfn3/net/eth21
/sys/devices/pci0000:00/0000:00:1c.0/0000:03:00.0/net/eth4/../../virtfn4/net/eth22
/sys/devices/pci0000:00/0000:00:1c.0/0000:03:00.0/net/eth4/../../virtfn5/net/eth23
/sys/devices/pci0000:00/0000:00:1c.0/0000:03:00.0/net/eth4/../../virtfn6/net/eth24

# looking PCI locations for VFs under eth4 PF

host $ readlink -f $(readlink -f /sys/class/net/eth4)/../../virtfn*/net/*)
/sys/devices/pci0000:00/0000:00:1c.0/0000:04:10.0/net/eth0
/sys/devices/pci0000:00/0000:00:1c.0/0000:04:10.2/net/eth2
/sys/devices/pci0000:00/0000:00:1c.0/0000:04:10.4/net/eth20
/sys/devices/pci0000:00/0000:00:1c.0/0000:04:10.6/net/eth21
/sys/devices/pci0000:00/0000:00:1c.0/0000:04:11.0/net/eth22
/sys/devices/pci0000:00/0000:00:1c.0/0000:04:11.2/net/eth23
/sys/devices/pci0000:00/0000:00:1c.0/0000:04:11.4/net/eth24
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

Checking RPM package files chksums and permissions.

``` shell
$ rpm -q --qf '[%{=NAME} %{FILENAMES} %{FILEMD5S}\n]' libcurl4
libcurl4 /usr/lib64/libcurl.so.4
libcurl4 /usr/lib64/libcurl.so.4.7.0 8c231b3ccbb33783f42367263b5fa5ff22341ab2e5e8566fedeeb62af26ed5cc
libcurl4 /usr/share/licenses/libcurl4
libcurl4 /usr/share/licenses/libcurl4/COPYING 6fd1a1c008b5ef4c4741dd188c3f8af6944c14c25afa881eb064f98fb98358e7

$ rpm -q --qf '[%{=NAME} %{FILENAMES} %{FILEMODES:perms}\n]' libcurl4
libcurl4 /usr/lib64/libcurl.so.4 lrwxrwxrwx
libcurl4 /usr/lib64/libcurl.so.4.7.0 -rwxr-xr-x
libcurl4 /usr/share/licenses/libcurl4 drwxr-xr-x
libcurl4 /usr/share/licenses/libcurl4/COPYING -rw-r--r--
```

Getting RPM GPG pub keyid of running kernel:

``` shell
$ rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\n' kernel-default | \
    grep -Po "$(uname -r | cut -d'-' -f1-2)"'.*\K(\w+){8}$'
39db7c82

$ rpm -qa gpg-pubkey | grep 39db7c82
gpg-pubkey-39db7c82-66c5d91a

$ rpm -qi gpg-pubkey-39db7c82-66c5d91a | sed -n '/Packager/,$p'
Packager    : SuSE Package Signing Key <build@suse.de>
Summary     : gpg(SuSE Package Signing Key <build@suse.de>)
Description :
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: rpm-4.11.2 (NSS-3)

mQENBFEKlmsBCADbpZZbbSC5Zi+HxCR/ynYsVxU5JNNiSSZabN5GMgc9Z0hxeXxp
YWvFoE/4n0+IXIsp83iKvxf06Eu8je/DXp0lMqDZu7WiT3XXAlkOPSNV4akHTDoY
91SJaZCpgUJ7K1QXOPABNbREsAMN1a7rxBowjNjBUyiTJ2YuvQRLtGdK1kExsVma
hieh/QxpoDyYd5w/aky3z23erCoEd+OPfAqEHd5tQIa6LOosa63BSCEl3milJ7J9
vDmoGPAoS6ui7S2R5X4/+PLN8Mm2kOBrFjhmL93LX0mrGCMxsNsKgP6zabYKQEb8
L028SXvl7EGoA+Vw5Vd3wIGbM73PfbgNrXjfABEBAAG0KFN1U0UgUGFja2FnZSBT
aWduaW5nIEtleSA8YnVpbGRAc3VzZS5kZT6JAVMEEwEIAD0CGwMGCwkIBwMCBBUC
CAMEFgIDAQIeAQIXgBYhBP6rUCU52EbbLAlhynCvnoE523yCBQJmxdkaBQkdeMEv
AAoJEHCvnoE523yCsyEH/1NZhXtgIa4kFCZdWhPhXPvqz7IkIm62yXpS3Iseivbm
rxzQNXNlQVLnaOOKZX4nEUyh1lr+w18PGlb1yIdMjQqt04hwFgCU+q99cTfrAHG5
jzirSq9I2iBjn+zARCjLzJsD+dH7JGfEMm0lxtPyMRoNJ6bq8eEkjEtKxDOg0iTE
vQ4eboRlR0a8hH06tauPfeWx6Ri6hIobN3TNdCY/RQe4WeyYL8vEog3c7uYYag/V
iMFfj8QzRHgkkcCE9W3TTfr1K/h8AGZTW0uJH4YQhl2HqUsspKmicZIbK/W9M87l
HUyO8EgreF1MuKsg1GWxV2OikZAJKMcNs6EhzLWUWHs=
=5hye
-----END PGP PUBLIC KEY BLOCK-----

Distribution: (none)

$ rpm -qi gpg-pubkey-39db7c82-66c5d91a | sed -n '/Packager/,$p' | gpg -n --with-fingerprint
pub  2048R/39DB7C82 2013-01-31 [expires: 2028-10-02]
      Key fingerprint = FEAB 5025 39D8 46DB 2C09  61CA 70AF 9E81 39DB 7C82
uid                            SuSE Package Signing Key <build@suse.de>

# eh, scraping works now.. maybe won't work in the future...
$ curl -Ls https://www.suse.com/support/security/keys/ | \
    w3m -T text/html -dump | \
    sed -ne '/SUSE Linux Enterprise 12/,/END/{/END/q;p}' | \
    gpg -n --with-fingerprint
pub  2048R/39DB7C82 2013-01-31 [expires: 2028-10-02]
      Key fingerprint = FEAB 5025 39D8 46DB 2C09  61CA 70AF 9E81 39DB 7C82
uid                            SuSE Package Signing Key <build@suse.de>
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

Cloning a partition table with `sfdisk` while using auto-calculation of size:

``` shell
$ sfdisk -d /dev/xvde
sfdisk: /dev/xvde: does not contain a recognized partition table

$ sfdisk -d /dev/xvda | \
    sed -e '/^device/d' -e '/^label-id/d' -e '/lba/d' -e '/xvda[34]/d' -e '/xvda2/s/size=\s\+[0-9]\+/size=+/' | \
    sfdisk /dev/xvde
Checking that no-one is using this disk right now ... OK

Disk /dev/xvde: 1 GiB, 1073741824 bytes, 2097152 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

>>> Script header accepted.
>>> Script header accepted.
>>> Script header accepted.
>>> Created a new GPT disklabel (GUID: 75E47120-470A-4059-8319-93A35C9A26B7).
/dev/xvde1: Created a new partition 1 of type 'BIOS boot' and of size 8 MiB.
/dev/xvde2: Created a new partition 2 of type 'Linux filesystem' and of size 1014 MiB.
/dev/xvde3: Done.

New situation:
Disklabel type: gpt
Disk identifier: 75E47120-470A-4059-8319-93A35C9A26B7

Device     Start     End Sectors  Size Type
/dev/xvde1  2048   18431   16384    8M BIOS boot
/dev/xvde2 18432 2095103 2076672 1014M Linux filesystem

The partition table has been altered.
Calling ioctl() to re-read partition table.
Syncing disks.

$ sfdisk -d /dev/xvde
label: gpt
label-id: 75E47120-470A-4059-8319-93A35C9A26B7
device: /dev/xvde
unit: sectors
first-lba: 2048
last-lba: 2097118
sector-size: 512

/dev/xvde1 : start=        2048, size=       16384, type=21686148-6449-6E6F-744E-656564454649, uuid=23FA7D6F-4257-4F59-AC34-46F51C4CDA78
/dev/xvde2 : start=       18432, size=     2076672, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=42758F36-B866-418E-B1A3-73371BBE8FFF, attrs="LegacyBIOSBootable"
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


### Fibre Channel aka FC (incl. FC over Ethernet)

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

For FCoE there could be no `supported_speeds` value,
eg. [`lpfc`](https://github.com/torvalds/linux/blob/master/drivers/scsi/lpfc/lpfc_init.c#L4870)
driver.

``` shell
$ lspci -b | grep 06:00.2
06:00.2 Fibre Channel: Emulex Corporation OneConnect FCoE Initiator (Skyhawk) (rev 10)

$ /usr/bin/systool -vc fc_host
Class = "fc_host"

  Class Device = "host6"
  Class Device path = "/sys/devices/pci0000:00/0000:00:02.0/0000:06:00.2/host6/fc_host/host6"
    active_fc4s         = "0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
    dev_loss_tmo        = "30"
    fabric_name         = "0x1000c4f57c0a1000"
    issue_lip           = <store method only>
    max_npiv_vports     = "255"
    maxframe_size       = "2048 bytes"
    node_name           = "0x1000de4b253003d1"
    npiv_vports_inuse   = "0"
    port_id             = "0x21a3c2"
    port_name           = "0x1000de4b253003d0"
    port_state          = "Online"
    port_type           = "NPort (fabric via point-to-point)"
    speed               = "20 Gbit"
    supported_classes   = "Class 3"
    supported_fc4s      = "0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
    supported_speeds    = "unknown"
    symbolic_name       = "Emulex 650FLB FV12.0.1345.0 DV14.2.0.1 HN:ihs-pruebas OS:Linux"
    tgtid_bind_type     = "wwpn (World Wide Port Name)"
    uevent              =
    vport_create        = <store method only>
    vport_delete        = <store method only>

    Device = "host6"
    Device path = "/sys/devices/pci0000:00/0000:00:02.0/0000:06:00.2/host6"
      uevent              = "DEVTYPE=scsi_host"
...
```

See, as regards above example,
`/sys/devices/pci0000:00/0000:00:02.0/0000:06:00.2/host6/scsi_host/host6/procol`
which would show *fcoe*.


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
$ lsmod | grep scsi_transport_iscsi # should be loaded by distro tools
$ cat /sys/module/iscsi_tcp/parameters/debug_iscsi_tcp # debugging
0
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
$ iscsiadm -m iface -P 1                                               # list initiator interfaces
$ iscsiadm -m iface -I <name> -o new                                   # add new interface named '<name>'
$ iscsiadm -m iface -I <name> -o update -n iface.hwaddress -v <hwaddr> # assing logical iface to hardware
                                                                     # address
$ iscsiadm -m iface -I <name>                                          # show logical iface details

$ iscsiadm -m iface -P1 2>/dev/null
Iface: tcp.52:54:00:08:0d:99.ipv4.0
Iface: tcp.52:54:00:f5:43:51.ipv4.0
Iface: virtio_net0
        Target: iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.d3b127e7b7a9
                Portal: 192.168.124.1:3260,1
Iface: virtio_net1
        Target: iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.d3b127e7b7a9
                Portal: 192.168.123.1:3260,2
Iface: default
Iface: iser
```

And to link *iface* to *node*:

``` shell
$ ss -tnp dport = 3260
State   Recv-Q   Send-Q            Local Address:Port         Peer Address:Port
ESTAB   0        0          192.168.123.200%eth1:45414       192.168.123.1:3260    users:(("iscsid",pid=1680,fd=6))
ESTAB   0        0          192.168.124.201%eth0:53768       192.168.124.1:3260    users:(("iscsid",pid=1680,fd=7))

$ iscsiadm -m node -P1
Target: iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.d3b127e7b7a9
        Portal: 192.168.123.1:3260,2
                Iface Name: virtio_net1
        Portal: 192.168.124.1:3260,1
                Iface Name: virtio_net0

$ multipathd show paths format '%i %d %D %t %o %T %s %z %n %a'
hcil    dev dev_t dm_st  dev_st  chk_st vend/prod/rev  serial                               target WWNN                                            host adapter
7:0:0:0 sdb 8:16  active running ready  LIO-ORG,test01 00dd53b1-85f8-4dc5-b90c-01c24fb68b97 iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.d3b127e7b7a9 192.168.123.200
6:0:0:0 sda 8:0   active running ready  LIO-ORG,test01 00dd53b1-85f8-4dc5-b90c-01c24fb68b97 iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.d3b127e7b7a9 192.168.124.201
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

##### demo mode

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

Note that writing to *debugfs* does not work with SecureBoot!

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

TODO: add `trace-cmd` tips...


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

``` shell
$ tshark -i eth0 -f '(tcp or udp) and port 3260' -Y 'iscsi.opcode == 0x03' -O iscsi
Running as user "root" and group "root". This could be dangerous.
Capturing on 'eth0'
Frame 6: 182 bytes on wire (1456 bits), 182 bytes captured (1456 bits) on interface eth0, id 0
Ethernet II, Src: RealtekU_79:5e:32 (52:54:00:79:5e:32), Dst: RealtekU_7f:b3:7a (52:54:00:7f:b3:7a)
Internet Protocol Version 4, Src: 192.168.252.100, Dst: 192.168.252.1
Transmission Control Protocol, Src Port: 37860, Dst Port: 3260, Seq: 49, Ack: 1, Len: 116
[2 Reassembled TCP Segments (164 bytes): #4(48), #6(116)]
iSCSI (Login Command)
    Opcode: Login Command (0x03)
    0... .... = T: Stay in current login stage
    .0.. .... = C: Text is complete
    .... 00.. = CSG: Security negotiation (0x0)
    VersionMax: 0x00
    VersionMin: 0x00
    TotalAHSLength: 0x00
    DataSegmentLength: 116 (0x00000074)
    ISID: 00023d000000
        00.. .... = ISID_t: IEEE OUI (0x0)
        ..00 0000 = ISID_a: 0x00
        ISID_b: 0x023d
        ISID_c: 0x00
        ISID_d: 0x0000
    TSIH: 0x0000
    InitiatorTaskTag: 0x00000000
    CID: 0x0000
    CmdSN: 0x00000001
    ExpStatSN: 0x00000000
    Key/Value Pairs
        KeyValue: InitiatorName=iqn.1996-04.de.suse:01:jb155sapqe01
        KeyValue: InitiatorAlias=jb155sapqe01
        KeyValue: SessionType=Discovery
        KeyValue: AuthMethod=CHAP
...

Frame 16: 174 bytes on wire (1392 bits), 174 bytes captured (1392 bits) on interface eth0, id 0
Ethernet II, Src: RealtekU_79:5e:32 (52:54:00:79:5e:32), Dst: RealtekU_7f:b3:7a (52:54:00:7f:b3:7a)
Internet Protocol Version 4, Src: 192.168.252.100, Dst: 192.168.252.1
Transmission Control Protocol, Src Port: 37860, Dst Port: 3260, Seq: 273, Ack: 225, Len: 108
[2 Reassembled TCP Segments (156 bytes): #15(48), #16(108)]
iSCSI (Login Command)
    Opcode: Login Command (0x03)
    1... .... = T: Transit to next login stage
    .0.. .... = C: Text is complete
    .... 00.. = CSG: Security negotiation (0x0)
    .... ..01 = NSG: Operational negotiation (0x1)
    VersionMax: 0x00
    VersionMin: 0x00
    TotalAHSLength: 0x00
    DataSegmentLength: 107 (0x0000006b)
    ISID: 00023d000000
        00.. .... = ISID_t: IEEE OUI (0x0)
        ..00 0000 = ISID_a: 0x00
        ISID_b: 0x023d
        ISID_c: 0x00
        ISID_d: 0x0000
    TSIH: 0x0000
    InitiatorTaskTag: 0x00000000
    CID: 0x0000
    CmdSN: 0x00000001
    ExpStatSN: 0x957e000b
    Key/Value Pairs
        KeyValue: CHAP_N=suse
        KeyValue: CHAP_R=0xc96e13f01d448a356cc727e6ebd94c6f
        KeyValue: CHAP_I=197
        KeyValue: CHAP_C=0xe9224ca1008ff6d9701df46da7ec5bd2
    Padding: 00
...
```


The above shows discovery auth from an initiator, *CHAP* authentication is used...

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

###### multipath with multiple tgps

IIUC one session is able to use only one interface, but I could be
mistaken. The point here is to use multiple iSCSI initiator ifaces,
each connecting to a portal in separate TPG.

``` shell
$ targetcli /iscsi/iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.d3b127e7b7a9 ls
o- iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.d3b127e7b7a9 .................................................. [TPGs: 2]
  o- tpg1 ........................................................................................ [gen-acls, no-auth]
  | o- acls ................................................................................................ [ACLs: 0]
  | o- luns ................................................................................................ [LUNs: 1]
  | | o- lun0 ................................................ [fileio/test01 (/suse/vms/test.raw) (default_tg_pt_gp)]
  | o- portals .......................................................................................... [Portals: 1]
  |   o- 192.168.124.1:3260 ..................................................................................... [OK]
  o- tpg2 ........................................................................................ [gen-acls, no-auth]
    o- acls ................................................................................................ [ACLs: 0]
    o- luns ................................................................................................ [LUNs: 1]
    | o- lun0 ................................................ [fileio/test01 (/suse/vms/test.raw) (default_tg_pt_gp)]
    o- portals .......................................................................................... [Portals: 1]
      o- 192.168.123.1:3260 ..................................................................................... [OK]
```

During simulation one could delete a port from a TPG and use `ss -K
dst <dst_ip> dport = <dst_port>` to kill an existing TCP session
(surprisinly after deleting the portal, the session still works).


##### tips and tricks

Mapping between target settings and initiator details for a lun.

``` shell
# on an initiator (comments inline)

$  lsscsi -w | grep /dev/sdf
[7:0:0:1]    disk    LIO-ORG  s154qe01-01      4.0   0x60014051e87fd39d65042cfb937fd  /dev/sdf
                              ^^^---+--- name of the lun
                                                              ^^^---+--- wwn of the lun
$ udevadm info -n /dev/sdf | grep -iP 'scsi_ident_.*(serial|naa|t10|port_name)'
E: SCSI_IDENT_SERIAL=1e87fd39-d650-42cf-b937-fdfa02481ed6     <---+--- wwn of the lun
E: SCSI_IDENT_LUN_NAA_REGEXT=60014051e87fd39d65042cfb937fdfa0 <---+--- wwn of the lun
E: SCSI_IDENT_LUN_T10=LIO-ORG_s154qe01-01:1e87fd39-d650-42cf-b937-fdfa02481ed6
E: SCSI_IDENT_PORT_NAME=iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.a47196ca0aac,t,0x0001
```

``` shell
# on a target

$ grep -H '' /sys/kernel/config/target/core/fileio_*/s154qe01-01/wwn/*
/sys/kernel/config/target/core/fileio_10/s154qe01-01/wwn/company_id:0x001405
/sys/kernel/config/target/core/fileio_10/s154qe01-01/wwn/product_id:s154qe01-01
/sys/kernel/config/target/core/fileio_10/s154qe01-01/wwn/revision:4.0
/sys/kernel/config/target/core/fileio_10/s154qe01-01/wwn/vendor_id:LIO-ORG
/sys/kernel/config/target/core/fileio_10/s154qe01-01/wwn/vpd_unit_serial:T10 VPD Unit Serial Number: 1e87fd39-d650-42cf-b937-fdfa02481ed6

$ readlink /sys/kernel/config/target/iscsi/iqn.2003-01.org.linux-iscsi.t14s.x8664\:sn.a47196ca0aac/tpgt_1/lun/lun_1/2bb7f3e6c6
../../../../../../target/core/fileio_10/s154qe01-01

$ targetcli /backstores/fileio/s154qe01-01 info
aio: False
dev: /home/vms/iscsi-s154qe01-01
name: s154qe01-01
plugin: fileio
size: 1073741824
write_back: True
wwn: 1e87fd39-d650-42cf-b937-fdfa02481ed6

$ targetcli /iscsi/iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.a47196ca0aac/tpg1/luns/lun1 info
alias: 2bb7f3e6c6
alua_tg_pt_gp_name: default_tg_pt_gp
index: 1
storage_object: /backstores/fileio/s154qe01-01
```

Finding LIO target lun details from wwn:

``` shell
$ grep -RH '' /sys/kernel/config/target/ 2>/dev/null | tr -d '-' | grep -P 'wwn/vp.*'"$( echo 6001405b04d547a91c34546bb46cf597 | cut -c8-)"
/sys/kernel/config/target/iscsi/iqn.202311.com.example.avocado:jbelka/tpgt_1/lun/lun_0/ef5dcbd51c/wwn/vpd_unit_serial:T10 VPD Unit Serial Number: b04d547a91c34546bb46cf59799cce12
/sys/kernel/config/target/core/fileio_5/jbelka001/wwn/vpd_unit_serial:T10 VPD Unit Serial Number: b04d547a91c34546bb46cf59799cce12
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
mdadm --create /dev/md/<name> --level=mirror --raid-devices=2 <realdev> missing # name will be symlink
echo 'CREATE names=yes' > /etc/mdadm.conf # careful!
madadm --detail --scan >> /etc/mdadm.conf

mdadm /dev/md/<name> --add <real_dev> # add disk to array
watch -n 1 cat /proc/mdstat # watch recovery
```

Decreasing number of raid devices (legs) in an array:

``` shell
$ cat /proc/mdstat
Personalities : [raid1]
md127 : active raid1 loop11[2] loop10[1] loop2[0]
      1046528 blocks super 1.2 [3/3] [UUU]

unused devices: <none>

# setting as faulty
$ mdadm --manage /dev/md127 -f /dev/loop11
mdadm: set /dev/loop11 faulty in /dev/md127

# removal
$ mdadm --manage /dev/md127 -r /dev/loop11
mdadm: hot removed /dev/loop11 from /dev/md127

# decreasing
$ mdadm --grow /dev/md127 -n 2
raid_disks for /dev/md127 set to 2

# an equivalent
$ echo 2 > /sys/class/block/md127/md/raid_disks

$ cat /proc/mdstat
Personalities : [raid1]
md127 : active raid1 loop10[1] loop2[0]
      1046528 blocks super 1.2 [2/2] [UU]

unused devices: <none>
```

Monitoring for mdraid via email.

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

#### troubleshooting

``` shell
$ cat /proc/mdstat
Personalities : [raid1]
md127 : active raid1 loop11[2] loop10[1] loop7[0]
      1046528 blocks super 1.2 [3/3] [UUU]
      [===>.................]  resync = 18.7% (196416/1046528) finish=0.3min speed=39283K/sec

unused devices: <none>
```

What is that `loopX[Y]`? `[Y]` corresponds to indexed number of the device when
the array is created and subsequently modified, see below:

``` shell
$ cat /proc/mdstat
Personalities : [raid1]
md127 : active raid1 loop11[2] loop10[1]
      1046528 blocks super 1.2 [2/2] [UU]

unused devices: <none>

# see there's no '0', it was already removed
```

And the list of disks is in backward order, from most recently added
to first failed! The order of disks line DOES NOT correspond to order
of line with 'bits' (eg. `U` or `_`).

``` shell
# comments inline
$ for i in loop11 loop10 ; do
  echo /dev/$i; dd if=/dev/$i bs=4K count=63 skip=1 2>/dev/null | xxd -s 0xa0 -l 0x20
  echo
done
/dev/loop11
000000a0: 0200 0000 0000 0000 9b77 fb5d e85b c9ad  .........w.].[..
          ^                   ^--+-- starts UUID_SUB
          +--+-- correspons to loop11[2] ?
000000b0: c26d e5ed 2dc4 9c5c 0000 0800 1000 0000  .m..-..\........

/dev/loop10
000000a0: 0100 0000 0000 0000 f662 655b 15c3 3fcb  .........be[..?.
          ^                   ^--+-- starts UUID_SUB
          +--+-- corresponds to loop10[1] ??
000000b0: 9d78 c04c 4d7a 8aa6 0000 0800 1000 0000  .x.LMz..........

$ for i in loop11 loop10 ; do
  echo /dev/$i; udevadm info -q property -n /dev/$i | grep ID_FS_UUID_SUB=
  echo
done
/dev/loop11
ID_FS_UUID_SUB=9b77fb5d-e85b-c9ad-c26d-e5ed2dc49c5c

/dev/loop10
ID_FS_UUID_SUB=f662655b-15c3-3fcb-9d78-c04c4d7a8aa6
```

``` shell
$ dd if=/dev/loop11 bs=4K count=63 skip=1 status=none | xxd -s 0xd0 -l 0x10
000000d0: ffff ffff ffff ffff 9e64 6062 8000 0000  .........d`b....
                              ^^^^^^^^^ checksum
$ mdadm -E /dev/loop11 | grep -i checksum
       Checksum : 6260649e - correct

$ dd if=/dev/loop11 bs=4K count=63 skip=1 status=none | xxd -s 0x10 -l 0x10
00000010: 2824 cfaa d562 0ce6 1686 bcf9 323b ab97  ($...b......2;..

$ mdadm -E /dev/loop11 | grep -i 'array uuid'
     Array UUID : 2824cfaa:d5620ce6:1686bcf9:323bab97
```

1.0 metadata version dump - see [RAID superblock
formats](https://raid.wiki.kernel.org/index.php/RAID_superblock_formats),
thus here it is first 4KB of the last 64KB of the device:

``` shell
$ wipefs /dev/loop11p1
DEVICE   OFFSET     TYPE              UUID                                   LABEL
loop11p1 0x3fefe000 linux_raid_member b4e54d33-903a-dcf7-90df-2e8d627ff57b   any:2
         ^--+-- hex offset
loop11p1 0x218      LVM2_member       ljxKlL-jbk3-Bjdy-zbtU-4pci-zYxL-VhfnLl

$ echo $((0x3fefe000))
1072685056 <--+-- in B
$ echo $(( $(blockdev --getsize64 /dev/loop11p1) - $((0x3fefe000)) ))
8192       <--+-- so how many B from the end of the device?

$ dd if=/dev/loop11p1 bs=1 skip=$((0x3fefe000)) conv=notrunc status=none | xxd -a
00000000: fc4e 2ba9 0100 0000 0000 0000 0000 0000  .N+.............
00000010: b4e5 4d33 903a dcf7 90df 2e8d 627f f57b  ..M3.:......b..{
00000020: 616e 793a 3200 0000 0000 0000 0000 0000  any:2...........
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: ec19 0e63 0000 0000 0100 0000 0000 0000  ...c............
00000050: 80f7 1f00 0000 0000 0000 0000 0200 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 0000 0000 0000 0000 e0f7 1f00 0000 0000  ................
00000090: f0f7 1f00 0000 0000 0000 0000 0000 0000  ................
000000a0: 0000 0000 0000 0000 2a9c 34ff f1f8 11ce  ........*.4.....
000000b0: 5047 882a 6cb7 06db 0000 0800 f8ff ffff  PG.*l...........
000000c0: d926 0e63 0000 0000 1d00 0000 0000 0000  .&.c............
000000d0: ffff ffff ffff ffff 54f9 4ab1 8000 0000  ........T.J.....
000000e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000100: 0000 ffff 0100 ffff ffff ffff ffff ffff  ................
00000110: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000120: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000130: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000140: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000150: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000160: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000170: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000180: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000190: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000001a0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000001b0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000001c0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000001d0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000001e0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000001f0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000200: 0000 0000 0000 0000 0000 0000 0000 0000  ................
*
00001ff0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

``` shell
$ dd if=/dev/loop12p1 bs=512 count=8 skip=$(($(blockdev --getsz /dev/loop12p1) - 16)) status=none | xxd -a
00000000: fc4e 2ba9 0100 0000 0000 0000 0000 0000  .N+.............
00000010: 009b f235 fb4b 7d12 0a2a 91d7 e45b 5421  ...5.K}..*...[T!
00000020: 616e 793a 3200 0000 0000 0000 0000 0000  any:2...........
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: ffa3 0c63 0000 0000 0100 0000 0000 0000  ...c............
00000050: 80f7 1f00 0000 0000 0000 0000 0200 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 0000 0000 0000 0000 e0f7 1f00 0000 0000  ................
00000090: f0f7 1f00 0000 0000 0000 0000 0000 0000  ................
000000a0: 0100 0000 0000 0000 c4da 2083 e66a e7b7  .......... ..j..
000000b0: 3c65 6e45 32ad b475 0000 0800 f8ff ffff  <enE2..u........
000000c0: 04a4 0c63 0000 0000 0800 0000 0000 0000  ...c............
000000d0: 800f 0c00 0000 0000 edc1 b3e1 8000 0000  ................
000000e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000100: 0000 0100 ffff ffff ffff ffff ffff ffff  ................
00000110: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000120: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000130: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000140: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000150: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000160: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000170: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000180: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000190: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000001a0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000001b0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000001c0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000001d0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000001e0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000001f0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000200: 0000 0000 0000 0000 0000 0000 0000 0000  ................
*
00000ff0: 0000 0000 0000 0000 0000 0000 0000 0000  ................

$ mdadm -E /dev/loop12p1 | grep -Pi '(uuid|version)'
        Version : 1.0
     Array UUID : 009bf235:fb4b7d12:0a2a91d7:e45b5421
    Device UUID : c4da2083:e66ae7b7:3c656e45:32adb475

```

Hot-spare:

Hot-spare disk is a disk, which when a failed drive would cause enter
into degraded mode, it would be introduced into the array, replacing
the failed drive.

``` shell
# adding hot-spare disk
$ mdadm /dev/md127 --add /dev/loop2
mdadm: added /dev/loop2

$ cat /proc/mdstat
Personalities : [raid1]
md127 : active raid1 loop2[3](S) loop11[2] loop10[1]
      1046528 blocks super 1.2 [2/2] [UU]

unused devices: <none>

$ mdadm -D /dev/md127
/dev/md127:
           Version : 1.2
     Creation Time : Wed Apr 27 18:37:07 2022
        Raid Level : raid1
        Array Size : 1046528 (1022.00 MiB 1071.64 MB)
     Used Dev Size : 1046528 (1022.00 MiB 1071.64 MB)
      Raid Devices : 2
     Total Devices : 3
       Persistence : Superblock is persistent

       Update Time : Wed May 18 19:58:30 2022
             State : clean
    Active Devices : 2
   Working Devices : 3
    Failed Devices : 0
     Spare Devices : 1

Consistency Policy : resync

              Name : t14s:loopraid  (local to host t14s)
              UUID : 8328504d:27bc6d5d:0cd6079c:7430b724
            Events : 188

    Number   Major   Minor   RaidDevice State
       2       7       11        0      active sync   /dev/loop11
       1       7       10        1      active sync   /dev/loop10

       3       7        2        -      spare   /dev/loop2

$ grep -H '' /sys/class/block/md127/md/{raid_disks,dev*/{slot,state}}
/sys/class/block/md127/md/raid_disks:2
/sys/class/block/md127/md/dev-loop10/slot:1
/sys/class/block/md127/md/dev-loop11/slot:0
/sys/class/block/md127/md/dev-loop2/slot:none
/sys/class/block/md127/md/dev-loop10/state:in_sync
/sys/class/block/md127/md/dev-loop11/state:in_sync
/sys/class/block/md127/md/dev-loop2/state:spare
```

``` shell
$ mdadm --create /dev/md/loopraid --level=mirror --raid-devices=3 /dev/loop7 /dev/loop10 /dev/loop11
mdadm: Note: this array has metadata at the start and
    may not be suitable as a boot device.  If you plan to
    store '/boot' on this device please ensure that
    your boot-loader understands md/v1.x metadata, or use
    --metadata=0.90
Continue creating array? YES
mdadm: Defaulting to version 1.2 metadata
mdadm: array /dev/md/loopraid started.
```

``` shell
$ udevadm info -q all -n /dev/loop7 | grep -P '^E: ID_FS_(TYPE|LABEL)='
E: ID_FS_LABEL=t14s:loopraid
E: ID_FS_TYPE=linux_raid_member

ls -l /dev/disk/by-id/*md*
lrwxrwxrwx 1 root root 11 Apr 27 18:37 /dev/disk/by-id/md-name-t14s:loopraid -> ../../md127
lrwxrwxrwx 1 root root 11 Apr 27 18:37 /dev/disk/by-id/md-uuid-8328504d:27bc6d5d:0cd6079c:7430b724 -> ../../md127
```


### multipath

if multipath support is required during boot (ie. booting from
multipath SAN) it is in SLES present as *dracut* module (*multipath*)
which puts into initramfs multipath-tools binaries, libs,
configuration and udev/systemd files. See [Troubleshooting boot issues
(multipath with lvm)](
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

*NOTE* that if using a keyword in `blacklist` section then the same keyword has
to be used in `blacklist_exceptions` section to whitelist devices.

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


### Logical Volume Manager aka LVM

Specification of LVM metadata is at [LVM Format
Specification](https://github.com/libyal/libvslvm/blob/main/documentation/Logical%20Volume%20Manager%20(LVM)%20format.asciidoc).

``` shell
$ xxd -s $((512+32)) -l 32 /dev/loop0
00000220: 6938 7070 3932 4852 6b66 6939 6f73 4949  i8pp92HRkfi9osII
00000230: 5246 746f 6545 6649 6678 376d 3730 5246  RFtoeEfIfx7m70RF

$ grep -A 1 -m1 pv0 /etc/lvm/backup/testvg
                pv0 {
                        id = "i8pp92-HRkf-i9os-IIRF-toeE-fIfx-7m70RF"
```

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


Restoration of LVM PV, which was on raw disk, after one creates DOS
MBR on the disk by mistake:

``` shell
# remove the mbr
$ dd if=/dev/zero of=/dev/sdb bs=512 count=1

$ ls -l /dev/sdb{,[0-9]*} # the partition device still present?

$ partx -d --nr 1 /dev/sdb

# get pv uuid
$ awk '/^[ \t]*pv0/ { getline; gsub(/"/,""); print $3 }' /etc/lvm/backup/sdbvg 
mcm2Av-hxSA-sbnb-0r8g-YZCL-nwnH-z91Elv

$ pvcreate --uuid mcm2Av-hxSA-sbnb-0r8g-YZCL-nwnH-z91Elv --restorefile /etc/lvm/backup/sdbvg /dev/sdb
  WARNING: Couldn't find device with uuid mcm2Av-hxSA-sbnb-0r8g-YZCL-nwnH-z91Elv.
  Can't open /dev/sdb exclusively.  Mounted filesystem?
  Can't open /dev/sdb exclusively.  Mounted filesystem?

# unmount the filesystem!
# however, still the same issue

$ dmsetup ls --target linear  | grep vg
sdbvg-lv0       (254, 0)

$ dmsetup remove sdbvg-lv0

$ pvcreate --uuid mcm2Av-hxSA-sbnb-0r8g-YZCL-nwnH-z91Elv --restorefile /etc/lvm/backup/sdbvg /dev/sdb
  WARNING: Couldn't find device with uuid mcm2Av-hxSA-sbnb-0r8g-YZCL-nwnH-z91Elv.
  Physical volume "/dev/sdb" successfully created.

$ vgcfgrestore sdbvg
  Restored volume group sdbvg.
$ vgchange -a y sdbvg
  1 logical volume(s) in volume group "sdbvg" now active
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
`/etc/mhvtl/library_contents.<id>`, see `generate_device_conf(1)`,
`generate_library_contents(1)`, `make_vtl_media(1)` man pages, and *mhvtl* RPM
post-install script:

``` shell
rpm --scripts -q mhvtl | sed -n '/^postinstall/,/^preuninstall/{/^preun/q;p}' \
  | sed -n '/"$1" = 1/,$p'
if [ "$1" = 1 ]; then
        /usr/bin/make_vtl_media --force \
                --config-dir=/etc/mhvtl \
                --home-dir=/var/lib/mhvtl \
                --mktape-path=/usr/bin
fi
```

An example:

``` shell
$ grep -Pv '^\s*(#|$)' /etc/mhvtl/device.conf
VERSION: 5
Library: 10 CHANNEL: 00 TARGET: 00 LUN: 00
 Vendor identification: STK
 Product identification: VLSTK
 Unit serial number: VLSTK
 NAA: 30:22:33:44:ab:00:08:00
 Compression: factor 1 enabled 1
 Compression type: lzo
 Home directory: /var/lib/mhvtl
 PERSIST: True
 Backoff: 400
Drive: 11 CHANNEL: 00 TARGET: 1 LUN: 00
 Library ID: 10 Slot: 1
 Vendor identification: STK
 Product identification: MHVTL
 Unit serial number: VDSTK1
 NAA: 30:22:33:44:ab:00:09:00
 Compression: factor 1 enabled 1
 Compression type: lzo
 Backoff: 400
Drive: 12 CHANNEL: 00 TARGET: 2 LUN: 00
 Library ID: 10 Slot: 2
 Vendor identification: STK
 Product identification: MHVTL
 Unit serial number: VDSTK2
 NAA: 30:22:33:44:ab:00:09:00
 Compression: factor 1 enabled 1
 Compression type: lzo

$ grep -Pv '^\s*(#|$)' /etc/mhvtl/library_contents.10
VERSION: 2
Drive 1: VDSTK1
Drive 2: VDSTK2
Picker 1:
MAP 1:
Slot 1: V01001TA
Slot 2: V01002TA
Slot 3: V01003TA
Slot 4: V01004TA
Slot 5: V01005TA
Slot 6: V01006TA
Slot 7: V01007TA
Slot 8:
Slot 9:
Slot 10:
```

Some *mhvtl* operations:

```
# genereate library database from library_content.<id>
$ rm -rf /var/lib/mhvtl/*
$ make_vtl_media -C /etc/mhvtl -H /var/lib/mhvtl >/dev/null 2>&1
$ ls /var/lib/mhvtl/ | wc -l
48
```

Some operations:

``` shell
$ mtx -f /dev/sch0 inquiry
Product Type: Medium Changer
Vendor ID: 'STK     '
Product ID: 'SL150           '
Revision: '0164'
Attached Changer API: No

$ mtx -f /dev/sch0 status | head -6
  Storage Changer /dev/sch0:4 Drives, 43 Slots ( 4 Import/Export )
Data Transfer Element 0:Empty
Data Transfer Element 1:Empty
Data Transfer Element 2:Empty
Data Transfer Element 3:Empty
      Storage Element 1:Full :VolumeTag=E01001L8

$ mtx -f /dev/sch0 load 1 0
Loading media from Storage Element 1 into drive 0...done

$ mtx -f /dev/sch0 status | head -6
  Storage Changer /dev/sch0:4 Drives, 43 Slots ( 4 Import/Export )
Data Transfer Element 0:Full (Storage Element 1 Loaded):VolumeTag = E01001L8
Data Transfer Element 1:Empty
Data Transfer Element 2:Empty
Data Transfer Element 3:Empty
      Storage Element 1:Empty

$ mtx -f /dev/sch0 unload 1 0
Unloading drive 0 into Storage Element 1...done

$ mtx -f /dev/sch0 status | head -6
  Storage Changer /dev/sch0:4 Drives, 43 Slots ( 4 Import/Export )
Data Transfer Element 0:Empty
Data Transfer Element 1:Empty
Data Transfer Element 2:Empty
Data Transfer Element 3:Empty
      Storage Element 1:Full :VolumeTag=E01001L8
```

``` shell
$ lsscsi -itg | grep tape
[1:0:1:0]    tape                                    /dev/st0   -  /dev/sg2
[1:0:2:0]    tape                                    /dev/st1   -  /dev/sg3

$ ls -l /dev/*st0
crw-rw---- 1 root tape 9, 128 Jan 26 13:59 /dev/nst0
crw-rw---- 1 root tape 9,   0 Jan 26 13:59 /dev/st0

$ mt -f /dev/nst0 status
SCSI 2 tape drive:
File number=-1, block number=-1, partition=0.
Tape block size 0 bytes. Density code 0x4a (SDLT600, T10000A).
Soft error count since last status=0
General status bits on (1010000):
 ONLINE IM_REP_EN

# see barcode of tape
$ mtx -f /dev/sch0 status | head -n3
  Storage Changer /dev/sch0:2 Drives, 11 Slots ( 1 Import/Export )
Data Transfer Element 0:Full (Storage Element 1 Loaded):VolumeTag = V01001TA
Data Transfer Element 1:Empty

$ lsscsi -itg | grep tape
[1:0:1:0]    tape                                    /dev/st0   -  /dev/sg2
[1:0:2:0]    tape                                    /dev/st1   -  /dev/sg3

$ ls -l /dev/*st0
crw-rw---- 1 root tape 9, 128 Jan 26 13:59 /dev/nst0
crw-rw---- 1 root tape 9,   0 Jan 26 13:59 /dev/st0

$ tar -cf /dev/st0 /etc
tar: Removing leading `/' from member names
$ du -sh /var/lib/mhvtl/V01001TA/*
12M     /var/lib/mhvtl/V01001TA/data
2.1M    /var/lib/mhvtl/V01001TA/indx
4.0K    /var/lib/mhvtl/V01001TA/meta
```

``` shell
$ lsscsi -itg | egrep '(mediumx|tape)'
[1:0:0:0]    mediumx                                 /dev/sch0  -  /dev/sg1
[1:0:1:0]    tape                                    /dev/st0   -  /dev/sg2
[1:0:2:0]    tape                                    /dev/st1   -  /dev/sg3

$ for i in {1..3}; do
  targetcli /backstores/pscsi create sg$i /dev/sg$i
done

$ targetcli /backstores/pscsi ls
o- pscsi ...................................................................................................... [Storage Objects: 3]
  o- sg1 .................................................................................................... [/dev/sg1 deactivated]
  | o- alua ....................................................................................................... [ALUA Groups: 0]
  o- sg2 .................................................................................................... [/dev/sg2 deactivated]
  | o- alua ....................................................................................................... [ALUA Groups: 0]
  o- sg3 .................................................................................................... [/dev/sg3 deactivated]
    o- alua ....................................................................................................... [ALUA Groups: 0]

$ targetcli /iscsi create
Created target iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.cc9236ede842.
Created TPG 1.

$ targetcli /iscsi/iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.cc9236ede842/tpg1 \
  set attribute \
  authentication=0 demo_mode_discovery=1 \
  demo_mode_write_protect=0 \
  generate_node_acls=1 \
  cache_dynamic_acls=1
Parameter authentication is now '0'.
Parameter demo_mode_discovery is now '1'.
Parameter demo_mode_write_protect is now '0'.
Parameter generate_node_acls is now '1'.
Parameter cache_dynamic_acls is now '1'.

$ for i in {1..3}; do
  targetcli /iscsi/iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.cc9236ede842/tpg1/luns \
    create /backstores/pscsi/sg$i
done
Created LUN 0.
Created LUN 1.
Created LUN 2.

$ targetcli \
  /iscsi/iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.cc9236ede842/tpg1/portals \
  create 192.168.124.1
Using default IP port 3260
Created network portal 192.168.124.1:3260.

$  targetcli /iscsi/iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.cc9236ede842 ls
o- iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.cc9236ede842 ................................................................ [TPGs: 1]
  o- tpg1 ...................................................................................................... [gen-acls, no-auth]
    o- acls .............................................................................................................. [ACLs: 0]
    o- luns .............................................................................................................. [LUNs: 3]
    | o- lun0 ........................................................................................ [pscsi/sg1 (/dev/sg1) (None)]
    | o- lun1 ........................................................................................ [pscsi/sg2 (/dev/sg2) (None)]
    | o- lun2 ........................................................................................ [pscsi/sg3 (/dev/sg3) (None)]
    o- portals ........................................................................................................ [Portals: 1]
      o- 192.168.124.1:3260 ................................................................................................... [OK]
```

A system attaching tape library robot and tapes via iSCSI:

```
$ iscsiadm -m node -T iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.cc9236ede842 -l
Logging in to [iface: default, target: iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.cc9236ede842, portal: 192.168.124.1,3260]
Login to [iface: default, target: iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.cc9236ede842, portal: 192.168.124.1,3260] successful.

$ lsscsi -itg
[6:0:0:0]    mediumx iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.cc9236ede842,t,0x1  /dev/sch0  -  /dev/sg0
[6:0:0:1]    tape    iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.cc9236ede842,t,0x1  /dev/st0   -  /dev/sg1
[6:0:0:2]    tape    iqn.2003-01.org.linux-iscsi.t14s.x8664:sn.cc9236ede842,t,0x1  /dev/st1   -  /dev/sg2

$ tar -cf /tmp/nst1 /etc
tar: Removing leading `/' from member names

# and on iscsi target with mhvtl we see...
$ mt -f /dev/st1 status
SCSI 2 tape drive:
File number=0, block number=0, partition=0.
Tape block size 0 bytes. Density code 0x4a (SDLT600, T10000A).
Soft error count since last status=0
General status bits on (41010000):
 BOT ONLINE IM_REP_EN

$ du -sh /var/lib/mhvtl/V01007TA/*
4.1M    /var/lib/mhvtl/V01007TA/data
732K    /var/lib/mhvtl/V01007TA/indx
4.0K    /var/lib/mhvtl/V01007TA/meta
```

See also:

- https://eoscta.docs.cern.ch/install/mhvtl/#configure-mhvtl
- https://www.cyberciti.biz/hardware/unix-linux-basic-tape-management-commands/
- https://access.redhat.com/solutions/68115
- https://karellen.blogspot.com/2012/01/mhvtl-virtual-tape-library.html


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

Run a command (below starting a systemd unit) when a module is loaded:

``` shell
$ cat /etc/udev/rules.d/99-nfs4_disable_idmapping.rules
ACTION=="add", SUBSYSTEM=="module", KERNEL=="nfs", \
    TAG+="systemd", ENV{SYSTEMD_WANTS}+="nfs-idmapd.service"
```

...or...

```
# Set SecurityFlags to 0x81.
ACTION=="add", SUBSYSTEM=="module", KERNEL=="cifs", RUN+="/bin/sh -c 'echo 0x81 > /proc/fs/cifs/SecurityFlags'"
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

`systemd` as `init` mounts some filesystem itself by defualt in
initramfs, see
[`mount.c`](https://github.com/openSUSE/systemd/blob/SLE15-SP4/src/shared/mount-setup.c#L64)
for example:

``` shell
$ curl -sL https://raw.githubusercontent.com/openSUSE/systemd/SLE15-SP4/src/shared/mount-setup.c | grep -A 10 -m 1 mount_table
static const MountPoint mount_table[] = {
        { "proc",        "/proc",                     "proc",       NULL,                                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER|MNT_FOLLOW_SYMLINK },
        { "sysfs",       "/sys",                      "sysfs",      NULL,                                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER },
        { "devtmpfs",    "/dev",                      "devtmpfs",   "mode=755" TMPFS_LIMITS_DEV,               MS_NOSUID|MS_STRICTATIME,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER },
        { "securityfs",  "/sys/kernel/security",      "securityfs", NULL,                                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,          MNT_NONE                   },
#if ENABLE_SMACK
        { "smackfs",     "/sys/fs/smackfs",           "smackfs",    "smackfsdef=*",                            MS_NOSUID|MS_NOEXEC|MS_NODEV,
```

Some basic commands:

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

systemd could set `PrivateTmp` per unit:

``` shell
$ systemctl show -p PrivateTmp --value named
yes

$ cat /proc/$(systemctl show -p MainPID --value named)/mountinfo | \
    awk '$4 ~ /systemd-private/ && $5 == "/tmp"'
855 987 0:47 /@/tmp/systemd-private-b97214a53a9d46e99d95e1449f64d5ad-named.service-WtH6e6/tmp /tmp rw,relatime shared:556 master:29 - btrfs /dev/mapper/system-root rw,ssd,space_cache,subvolid=259,subvol=/@/tmp

$ nsenter -t $(systemctl show -p MainPID --value named) -m ls -al /tmp
total 0
drwxrwxrwt 1 root root   0 Dec 25 18:02 .
drwxr-xr-x 1 root root 246 Dec 13 12:43 ..

$ nsenter -t $(systemctl show -p MainPID --value named) -m touch /tmp/xxx

$ nsenter -t $(systemctl show -p MainPID --value named) -m ls -al /tmp
total 0
drwxrwxrwt 1 root root   6 Dec 25 19:13 .
drwxr-xr-x 1 root root 246 Dec 13 12:43 ..
-rw-r--r-- 1 root root   0 Dec 25 19:13 xxx

$ cat /proc/$(systemctl show -p MainPID --value named)/mountinfo | \
    awk '$4 ~ /systemd-private/ && $5 == "/tmp" { sub(/\/@/,"",$4); print $4 }'
/tmp/systemd-private-b97214a53a9d46e99d95e1449f64d5ad-named.service-WtH6e6/tmp

$ls -al $(cat /proc/$(systemctl show -p MainPID --value named)/mountinfo | \
    awk '$4 ~ /systemd-private/ && $5 == "/tmp" { sub(/\/@/,"",$4); print $4 }')
total 0
drwxrwxrwt 1 root root 6 Dec 25 19:13 .
drwx------ 1 root root 6 Dec 25 18:02 ..
-rw-r--r-- 1 root root 0 Dec 25 19:13 xxx
```

To run pre-start command with root permissions, that is, prefix with `+`:

```
[Service]
User=abcadm
Group=sapsys
ExecStartPre=+/usr/bin/chmod 700 /etc/hanadb_exporter
ExecStartPre=+/usr/bin/chown -R abcadm:sapsys /etc/hanadb_exporter
ExecStartPre=+/usr/bin/chmod o= /var/log/hanadb_exporter.log
ExecStartPre=+/usr/bin/chown abcadm:sapsys /var/log/hanadb_exporter.log
ExecStart=
ExecStart=/usr/bin/hanadb_exporter --identifier %i --daemon
PrivateTmp=yes
ProtectHome=read-only
ProtectSystem=full
```

#### desktop stuff

``` shell
mkdir /etc/systemd/logind.conf.d
echo 'HandleLidSwitch=ignore' >> \
  /etc/systemd/logind.conf.d/lid.conf
systemctl restart systemd-logind # does not work on SUSE
```

A hack, resetting X11 displays output when using USB-C dock - since
the dock has an ethernet interface, it depends on it's presence and
starts a custom target/service.


``` shell
.config/systemd/user/sys-subsystem-net-devices-enx482ae39a7885.device.wants/thinkpad-usb-c-dock.target:[Unit]
.config/systemd/user/sys-subsystem-net-devices-enx482ae39a7885.device.wants/thinkpad-usb-c-dock.target:Description=Lenovo ThinkPad USB-C Dock
.config/systemd/user/sys-subsystem-net-devices-enx482ae39a7885.device.wants/thinkpad-usb-c-dock.target:Requisite=sys-subsystem-net-devices-enx482ae39a7885.device
.config/systemd/user/sys-subsystem-net-devices-enx482ae39a7885.device.wants/thinkpad-usb-c-dock.target:BindsTo=sys-subsystem-net-devices-enx482ae39a7885.device
.config/systemd/user/sys-subsystem-net-devices-enx482ae39a7885.device.wants/thinkpad-usb-c-dock.target:After=sys-subsystem-net-devices-enx482ae39a7885.device
.config/systemd/user/sys-subsystem-net-devices-enx482ae39a7885.device.wants/thinkpad-usb-c-dock.target:JobTimeoutSec=5
.config/systemd/user/sys-subsystem-net-devices-enx482ae39a7885.device.wants/thinkpad-usb-c-dock.target:
.config/systemd/user/sys-subsystem-net-devices-enx482ae39a7885.device.wants/thinkpad-usb-c-dock.target:[Install]
.config/systemd/user/sys-subsystem-net-devices-enx482ae39a7885.device.wants/thinkpad-usb-c-dock.target:WantedBy=sys-subsystem-net-devices-enx482ae39a7885.device
.config/systemd/user/thinkpad-usb-c-displays.service:[Unit]
.config/systemd/user/thinkpad-usb-c-displays.service:Description=displays connected to Lenovo ThinkPad USB-C Dock
.config/systemd/user/thinkpad-usb-c-displays.service:Requisite=thinkpad-usb-c-dock.target
.config/systemd/user/thinkpad-usb-c-displays.service:After=thinkpad-usb-c-dock.target
.config/systemd/user/thinkpad-usb-c-displays.service:PartOf=thinkpad-usb-c-dock.target
.config/systemd/user/thinkpad-usb-c-displays.service:Conflicts=sleep.target
.config/systemd/user/thinkpad-usb-c-displays.service:Before=sleep.target
.config/systemd/user/thinkpad-usb-c-displays.service:StopWhenUnneeded=yes
.config/systemd/user/thinkpad-usb-c-displays.service:
.config/systemd/user/thinkpad-usb-c-displays.service:[Service]
.config/systemd/user/thinkpad-usb-c-displays.service:Type=oneshot
.config/systemd/user/thinkpad-usb-c-displays.service:ExecStart=%h/bin/thinkpad-usb-c-displays start
.config/systemd/user/thinkpad-usb-c-displays.service:ExecStop=%h/bin/thinkpad-usb-c-displays stop
.config/systemd/user/thinkpad-usb-c-displays.service:RemainAfterExit=true
.config/systemd/user/thinkpad-usb-c-displays.service:
.config/systemd/user/thinkpad-usb-c-displays.service:[Install]
.config/systemd/user/thinkpad-usb-c-displays.service:WantedBy=thinkpad-usb-c-dock.target
.config/systemd/user/thinkpad-usb-c-dock.target:[Unit]
.config/systemd/user/thinkpad-usb-c-dock.target:Description=Lenovo ThinkPad USB-C Dock
.config/systemd/user/thinkpad-usb-c-dock.target:Requisite=sys-subsystem-net-devices-enx482ae39a7885.device
.config/systemd/user/thinkpad-usb-c-dock.target:BindsTo=sys-subsystem-net-devices-enx482ae39a7885.device
.config/systemd/user/thinkpad-usb-c-dock.target:After=sys-subsystem-net-devices-enx482ae39a7885.device
.config/systemd/user/thinkpad-usb-c-dock.target:JobTimeoutSec=5
.config/systemd/user/thinkpad-usb-c-dock.target:
.config/systemd/user/thinkpad-usb-c-dock.target:[Install]
.config/systemd/user/thinkpad-usb-c-dock.target:WantedBy=sys-subsystem-net-devices-enx482ae39a7885.device
.config/systemd/user/thinkpad-usb-c-dock.target.wants/thinkpad-usb-c-displays.service:[Unit]
.config/systemd/user/thinkpad-usb-c-dock.target.wants/thinkpad-usb-c-displays.service:Description=displays connected to Lenovo ThinkPad USB-C Dock
.config/systemd/user/thinkpad-usb-c-dock.target.wants/thinkpad-usb-c-displays.service:Requisite=thinkpad-usb-c-dock.target
.config/systemd/user/thinkpad-usb-c-dock.target.wants/thinkpad-usb-c-displays.service:After=thinkpad-usb-c-dock.target
.config/systemd/user/thinkpad-usb-c-dock.target.wants/thinkpad-usb-c-displays.service:PartOf=thinkpad-usb-c-dock.target
.config/systemd/user/thinkpad-usb-c-dock.target.wants/thinkpad-usb-c-displays.service:Conflicts=sleep.target
.config/systemd/user/thinkpad-usb-c-dock.target.wants/thinkpad-usb-c-displays.service:Before=sleep.target
.config/systemd/user/thinkpad-usb-c-dock.target.wants/thinkpad-usb-c-displays.service:StopWhenUnneeded=yes
.config/systemd/user/thinkpad-usb-c-dock.target.wants/thinkpad-usb-c-displays.service:
.config/systemd/user/thinkpad-usb-c-dock.target.wants/thinkpad-usb-c-displays.service:[Service]
.config/systemd/user/thinkpad-usb-c-dock.target.wants/thinkpad-usb-c-displays.service:Type=oneshot
.config/systemd/user/thinkpad-usb-c-dock.target.wants/thinkpad-usb-c-displays.service:ExecStart=%h/bin/thinkpad-usb-c-displays start
.config/systemd/user/thinkpad-usb-c-dock.target.wants/thinkpad-usb-c-displays.service:ExecStop=%h/bin/thinkpad-usb-c-displays stop
.config/systemd/user/thinkpad-usb-c-dock.target.wants/thinkpad-usb-c-displays.service:RemainAfterExit=true
.config/systemd/user/thinkpad-usb-c-dock.target.wants/thinkpad-usb-c-displays.service:
.config/systemd/user/thinkpad-usb-c-dock.target.wants/thinkpad-usb-c-displays.service:[Install]
.config/systemd/user/thinkpad-usb-c-dock.target.wants/thinkpad-usb-c-displays.service:WantedBy=thinkpad-usb-c-dock.target
```

``` shell
#!/bin/bash

eval $(systemctl --user show-environment | \
           grep -P '(DBUS|DISPLAY|XAUTHORITY|XDG_RUNTIME_DIR)' | \
           sed 's/^/export /')

function displays() {
    # serials taken from `edid-decode'`
    local lserial='H4ZN903596'
    local rserial='H4ZN903767'
    local outputs
    local left
    local right

    outputs=$(xrandr | tail -n +2 | grep -Po '^(\S+)(?=.* connected.*)' \
                  | grep -v eDP)
    for i in $outputs; do
        out=$(~/bin/filter_edid $i | edid-decode)
        grep -q $lserial <<< "${out}" && left=$i
        grep -q $rserial <<< "${out}" && right=$i
    done
    echo $left $right
}

case "$1" in
    start)
        read -r LEFT RIGHT < <(displays)
        xrandr --output ${LEFT} --auto \
               --output ${RIGHT} --primary --auto --right-of ${LEFT} \
               --output eDP --off
        ;;
    stop)
        xrandr --output eDP --primary --auto
        eval 'xrandr' \
             $(printf -- '--output %s --off ' \
                      $(xrandr | tail -n +3 | grep -Po '^\S+'))
        ;;
esac
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
- output to serial console:
  ```
  systemd.log_level=debug systemd.log_target=console systemd.log_location=true systemd.show_status=true loglevel=7 systemd.journald.forward_to_console=1
  ```
- `systemd-analyze set-log-level <level>` - change logging level
- `systemctl show -p LogLevel` - get current logging level
- `kill -SIGRTMIN+22 1` - sets systemd loglevel to debug, see `systemd(1)`
- `kill -SIGRTMIN+23 1` - sets systemd loglevel back to info
  If *SIGRTMIN+22/23* does not exist, just use number, ie. *SIGRTMIN* =
  *34* plus required number.
- *ctrl-alt-del* - how does *systemd* handles *ctrl-alt-del*?
  ``` shell
  $ grep -H '' /proc/sys/kernel/ctrl-alt-del
  /proc/sys/kernel/ctrl-alt-del:0
  ```
  Thus,
  [kernel.html](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#ctrl-alt-del)
  states when the value is '0', then it is "forwarded" to `init`
  (*systemd*) to handle it; non-zero value means immediate reboot
  without syncing its dirty buffers.


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

journalctl --rotate --vacuum-time=0.1s # clean journal
```

## distributions


### Debian

#### APT

APT preferences influencing (version) preference, pinning...

``` shell
$ cat /etc/apt/preferences.d/99salt-pin-3006 
Package: salt-*
Pin: version 3006.*
Pin-Priority: 900
```

The preference `99salt-pin-3006` files create after the `salt-minion`
package (with higher version) was installed:

``` shell
$ apt policy salt-minion
salt-minion:
  Installed: 3007.1
  Candidate: 3007.1
  Version table:
 *** 3007.1 500
        500 https://packages.broadcom.com/artifactory/saltproject-deb stable/main amd64 Packages
        100 /var/lib/dpkg/status
     3007.0 500
        500 https://packages.broadcom.com/artifactory/saltproject-deb stable/main amd64 Packages
     3006.9 900
        500 https://packages.broadcom.com/artifactory/saltproject-deb stable/main amd64 Packages
     3006.8 900
        500 https://packages.broadcom.com/artifactory/saltproject-deb stable/main amd64 Packages
     3006.7 900
        500 https://packages.broadcom.com/artifactory/saltproject-deb stable/main amd64 Packages
     3006.6 900
        500 https://packages.broadcom.com/artifactory/saltproject-deb stable/main amd64 Packages
     3006.5 900
        500 https://packages.broadcom.com/artifactory/saltproject-deb stable/main amd64 Packages
     3006.4 900
        500 https://packages.broadcom.com/artifactory/saltproject-deb stable/main amd64 Packages
     3006.3 900
        500 https://packages.broadcom.com/artifactory/saltproject-deb stable/main amd64 Packages
     3006.2 900
        500 https://packages.broadcom.com/artifactory/saltproject-deb stable/main amd64 Packages
     3006.1 900
        500 https://packages.broadcom.com/artifactory/saltproject-deb stable/main amd64 Packages
     3006.0 900
        500 https://packages.broadcom.com/artifactory/saltproject-deb stable/main amd64 Packages
```

To increase verbosity of APT, here, an example:

``` shell
$ apt -o Debug::pkgAcquire=true install salt-minion=3006.9 salt-common=3006.9
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following packages were automatically installed and are no longer required:
  asymptote-doc dvisvgm ethtool fonts-gfs-artemisia fonts-gfs-baskerville fonts-gfs-bodoni-classic fonts-gfs-didot fonts-gfs-didot-classic fonts-gfs-gazis fonts-gfs-neohellenic
  fonts-gfs-olga fonts-gfs-porson fonts-gfs-solomos fonts-gfs-theokritos hdparm libalgorithm-c3-perl libbit-vector-perl libcarp-clan-perl libclass-c3-perl libclass-c3-xs-perl
  libcommons-logging-java libcrypt-rc4-perl libdate-calc-perl libdate-calc-xs-perl libdevel-globaldestruction-perl libdigest-perl-md5-perl libdist-checkconflicts-perl libeval-closure-perl
  libfontbox-java libgsl27 libgslcblas0 libipc-shareable-perl libjcode-pm-perl liblog-dispatch-perl liblog-log4perl-perl libmime-charset-perl libmro-compat-perl libnamespace-autoclean-perl
  libole-storage-lite-perl libparams-validationcompiler-perl libparse-recdescent-perl libpdfbox-java libpotrace0 libptexenc1 libsombok3 libspecio-perl libspreadsheet-parseexcel-perl
  libspreadsheet-writeexcel-perl libstring-crc32-perl libteckit0 libtexlua53-5 libtexluajit2 libunicode-linebreak-perl libunicode-map-perl libyaml-tiny-perl libzzip-0-13 lmodern
  preview-latex-style ps2eps rfkill tcl tex-common tex-gyre tk xzdec
Use 'apt autoremove' to remove them.
Fetching https://packages.broadcom.com/artifactory/saltproject-deb/pool/salt-common_3006.9_amd64.deb
 to /var/cache/apt/archives/partial/salt-common_3006.9_amd64.deb
 Queue is: https:packages.broadcom.com
Fetching https://packages.broadcom.com/artifactory/saltproject-deb/pool/salt-minion_3006.9_amd64.deb
 to /var/cache/apt/archives/partial/salt-minion_3006.9_amd64.deb
 Queue is: https:packages.broadcom.com
The following packages will be DOWNGRADED:
  salt-common salt-minion
0 upgraded, 0 newly installed, 2 downgraded, 0 to remove and 7 not upgraded.
Need to get 34.3 MB of archives.
After this operation, 10.6 MB disk space will be freed.
Do you want to continue? [Y/n]
```

How not to start a daemon right after a package containing it is installed?
Use _policy-rcd-declarative_ package:

``` shell
$ apt install policy-rcd-declarative

$ grep -Pv '^\s*(#|$)' /etc/service-policy.d/99-allow.pol
.*      start   deny

$ ls -l /usr/sbin/policy-rc.d
lrwxrwxrwx 1 root root 29 Sep 10  2020 /usr/sbin/policy-rc.d -> /etc/alternatives/policy-rc.d

$ ls -l /etc/alternatives/policy-rc.d
lrwxrwxrwx 1 root root 33 Sep 10  2020 /etc/alternatives/policy-rc.d -> /usr/sbin/policy-rc.d-declarative

$ head /usr/sbin/policy-rc.d-declarative 
#!/usr/bin/perl -w
 
use strict;
use warnings;
 
use re::engine::RE2;
 
my @rulefiles = <"/etc/service-policy.d/*.pol">;
 
my $service = shift
```

And, the real situation:

``` shell
$ apt install 389-ds
...
Setting up 389-ds-base (3.1.2+dfsg1-1) ...
/usr/sbin/policy-rc.d returned 101, not running 'start dirsrv-snmp.service'
...
```


##### APT signing keys

``` shell
# only omitting lines with hashes
$ sed '/^SHA/,/BEGIN PGP SIGNATURE/{/BEGIN PGP SIGNATURE/!d}' /var/lib/apt/lists/deb.debian.org_debian_dists_bookworm-updates_InRelease
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Origin: Debian
Label: Debian
Suite: stable-updates
Version: 12-updates
Codename: bookworm-updates
Date: Thu, 20 Feb 2025 02:21:00 UTC
Valid-Until: Thu, 27 Feb 2025 02:21:00 UTC
Acquire-By-Hash: yes
No-Support-for-Architecture-all: Packages
Architectures: all amd64 arm64 armel armhf i386 mips64el mipsel ppc64el s390x
Components: main contrib non-free-firmware non-free
Description: Debian 12 - Updates
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCAAdFiEEpyNohvPMyq0Uiif4DphATThvodkFAme2kacACgkQDphATThv
odmvjQ/+M2SCVokYpBOaZfmgizpN8Ua78MGxC+sR5SPZHknhjGqZM5I2gXASARMu
Xqqrwgux/FAgmB/6r8lFYXIjGLAgweBK7W+zLzO+9YJ86iP3S4znhsQTLiSWy8Bx
kQAojA0x4ViV0YQmvTRZqLKBMl6HtYe2hnMxqxGyjqgwh+IgvxVd7eeTm7+4rGAS
4XA8QN7wbfS8izdcEtcV7ezfxhTwoCM7jWv5vb40peCcWYmJk0tZVYKR5LfG4Y3a
KePikb5vQjFpMB7bqULSNFZNbQHvoXxVzVQ7zv//X9bX272tHtF/TbG7RK2XKqdE
CtuGns4RggPkQTtVKdIcmpoSzJbezQx6flaBHnCyEE44n6ujTjBI2hqJPM42B4KI
ZHecAZ84fSJJ6+PZTLQWV13FxrhLzwC7m2uphmu55ZnV8deU0aBdNbUWWSCGH3Rq
LhYrp601x0T/Yp77twPyUX8XRws23NXTzU9x+KbfncJyBZjJcJePSqZNyYE8lqii
l4SaRP1zVEQZGr0MQ2Xs4u8VnlytWWpg93vfgjkeUWW1S1ilDUmMwFnb+y/raXsR
U74fnbsLO7OqGZYQpqfmNp012VfC1RzL851+/Vqe5a1fcxsStgg9WC+Q3z0UI79d
8133toRgnIjgY8LSZmkfZ71h0LjdkJw5oLmk91Cmg6Vb55QqCMKJAjMEAQEIAB0W
IQRMtQGQIHtHWKP3Onlu0Oe4JkPhMQUCZ7aRxQAKCRBu0Oe4JkPhMZYfD/0csB76
lOTpEn18+3A6VvEfBEVD5O3BsY5pDdGbQeQeXf1FzU21zBgOePtBoqiyjU5WLkxo
3j0AYJJKsSZ9HPM8+oa0ulfvIuZTBa/rQqMsr05egK6vyBEq/h+Q4+IlcQ50sSmW
/EzNPf0ns/79Nn3qnJKupz1LAze7t5g4tra/sRY3OjKMYqGVR80P9ahrBo6Xna11
xQWrSBTw2aGoh0IySnuJKBv4JNT6uN/TFYngXDnfg26aPPDXjKnTIk5IuOWNq2Rr
lLx9CPLfwgxeYEIMnGZm61+RXaKE1sHO60KLAuHnAFALw1ZZ/4OpWYNiYQQLF7j8
SoradnOCTFPKty+1LwqfC+J8gQe/qGaR5upzmfbHbUOneWvpBdEVxhmjrfsgykR7
YtEX+Ggm9YCC63IZqs/ZmGY2dD4aoyQw2sAvbg48Vfb9DxrmF2MNsUbqeSIzQhfj
WBOHs4akdIuDZY7914xFGh+fNE15N1JFu+99XC/dkFXUx3PMbxwXj/u6GGElY1jt
vbLEkfLZvBu40m2rcl00sy5KaARWBavDgXd9IvnSbTVxgS37c4GTbkAJ9IYtB4U6
41EU8xkRtnrnyyPIqlFznvvNwiYHLceeSaHgFq5tyAserRJjuOB39Sec3zEqN36E
tELsiGmJW7F+OcMAEycTLYpnDsk6KcOusb7bug==
=YT4a
-----END PGP SIGNATURE-----

$ sed -n '/BEGIN PGP SIGNATURE/,$p' /var/lib/apt/lists/deb.debian.org_debian_dists_bookworm-updates_InRelease | \
    gpg -n --list-packets
# off=0 ctb=89 tag=2 hlen=3 plen=563
:signature packet: algo 1, keyid 0E98404D386FA1D9
        version 4, created 1740018087, md5len 0, sigclass 0x01
        digest algo 8, begin of digest af 8d
        hashed subpkt 33 len 21 (issuer fpr v4 A7236886F3CCCAAD148A27F80E98404D386FA1D9)
        hashed subpkt 2 len 4 (sig created 2025-02-20)
        subpkt 16 len 8 (issuer key ID 0E98404D386FA1D9)
        data: [4094 bits]
# off=566 ctb=89 tag=2 hlen=3 plen=563
:signature packet: algo 1, keyid 6ED0E7B82643E131
        version 4, created 1740018117, md5len 0, sigclass 0x01
        digest algo 8, begin of digest 96 1f
        hashed subpkt 33 len 21 (issuer fpr v4 4CB50190207B4758A3F73A796ED0E7B82643E131)
        hashed subpkt 2 len 4 (sig created 2025-02-20)
        subpkt 16 len 8 (issuer key ID 6ED0E7B82643E131)
        data: [4093 bits]
```

See `signature`, `keyid` and `issuer fpr` (this is full keyid, see
last 16 digits). Thus, it has two signatures, by two keys.

``` shell
$ curl -s "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x0E98404D386FA1D9" | gpg -n 2>/dev/null
pub   rsa4096 2021-01-17 [SC] [expires: 2029-01-15]
      1F89983E0081FDE018F3CC9673A4F27B8DD47936
uid           Debian Archive Automatic Signing Key (11/bullseye) <ftpmaster@debian.org>
sub   rsa4096 2021-01-17 [S] [expires: 2029-01-15]

$ curl -s "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x6ED0E7B82643E131" | gpg -n 2>/dev/null
pub   rsa4096 2023-01-21 [SC] [expires: 2031-01-19]
      B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8
uid           Debian Archive Automatic Signing Key (12/bookworm) <ftpmaster@debian.org>
sub   rsa4096 2023-01-21 [S] [expires: 2031-01-19]

$ export GNUPGHOME=$(mktemp -d)

$ gpg --keyserver keyserver.ubuntu.com --search-keys 0E98404D386FA1D9
gpg: data source: http://185.125.188.27:11371
(1)     Debian Archive Automatic Signing Key (11/bullseye) <ftpmaster@debian.o
          4096 bit RSA key 73A4F27B8DD47936, created: 2021-01-17
Keys 1-1 of 1 for "0E98404D386FA1D9".  Enter number(s), N)ext, or Q)uit >

$ gpg --keyserver keyserver.ubuntu.com --search-keys 6ED0E7B82643E131
gpg: data source: http://185.125.188.27:11371
(1)     Debian Archive Automatic Signing Key (12/bookworm) <ftpmaster@debian.o
          4096 bit RSA key B7C5D7D6350947F8, created: 2023-01-21
Keys 1-1 of 1 for "6ED0E7B82643E131".  Enter number(s), N)ext, or Q)uit >
```


#### Building Debian package from its source

An example with Scribus:

``` shell
$ curl -Ls http://deb.debian.org/debian/pool/main/s/scribus/ | \
    w3m -T text/html -dump | grep -Po 'scribus_.*\.dsc' | sort -V
scribus_1.4.8+dfsg-1.dsc
scribus_1.5.6.1+dfsg-2.dsc
scribus_1.5.8+dfsg-2~bpo11+1.dsc
scribus_1.5.8+dfsg-4.dsc
scribus_1.6.2+dfsg-1.dsc

$ dget -ux http://deb.debian.org/debian/pool/main/s/scribus/scribus_1.6.2+dfsg-1.dsc
...
dpkg-source: info: extracting scribus in scribus-1.6.2+dfsg
dpkg-source: info: unpacking scribus_1.6.2+dfsg.orig.tar.xz
dpkg-source: info: unpacking scribus_1.6.2+dfsg-1.debian.tar.xz
dpkg-source: info: using patch list from debian/patches/series
dpkg-source: info: applying remove_non-free_file.patch

$ $ ls -1F scribus-1.6.2+dfsg/
AppImage-package/
AUTHORS
BUILDING
BUILDING_win32_cmake.txt
BUILDING_win32_msvc.txt
bundle.sh
ChangeLog
cmake/
CMakeLists_Apple.cmake
CMakeLists_Dependencies.cmake
CMakeLists_Directories.cmake
CMakeLists.txt
cmake_uninstall.cmake.in
config.h.cmake
configure*
ConfigureChecks.cmake
COPYING
debian/
devel-doc/
dtd/
fparser.txt
LINKS
NEWS
PACKAGING
README
README_150Manual
README.MacOSX
README.md
resources/
scribus/
Scribus.app/
scribus.appdata.xml.in
scribus.desktop.in
scribus.install.targets
scribus.kdevprj
scribus.lsm
Scribus.pro
scribus.xml
TODO
TRANSLATION
```

### RHEL

#### sosreport

- `sos_commands/systemd/journalctl_--list-boots`
- `sos_commands/block/lsblk{,_-f_-a_-l}`
- `etc/fstab`
- `{free,proc/meminfo}`


### SLES


#### autoyast

AutoYaST schema is in *yast2-schema-default* package. The schema is Relax-NG.

``` shell
# broken xml file

$ xmllint --encode utf-8 --noout --relaxng /usr/share/YaST2/schema/autoyast/rng/profile.rng /tmp/sles15sp5.xml.new ; echo $?
Relax-NG validity error : Extra element runlevel in interleave
/tmp/sles15sp5.xml.new:131: element runlevel: Relax-NG validity error : Element profile failed to validate content
/tmp/sles15sp5.xml.new fails to validate
3

$ jing /usr/share/YaST2/schema/autoyast/rng/profile.rng /tmp/sles15sp5.xml.new
/tmp/sles15sp5.xml.new:117:17: error: element "image" not allowed here; expected the element end-tag or element "do_online_update", "install_recommended", "instsource", "kernel", "packages", "patterns", "post-packages", "post-patterns", "products", "remove-packages", "remove-patterns" or "remove-products"
/tmp/sles15sp5.xml.new:132:18: error: element "default" not allowed here; expected element "runlevel"
/tmp/sles15sp5.xml.new:133:38: error: element "services" not allowed here; expected element "runlevel"
/tmp/sles15sp5.xml.new:139:16: error: element "runlevel" incomplete; missing required element "runlevel"
/tmp/sles15sp5.xml.new:159:18: error: element "pre-scripts" missing one or more required attributes; expected attribute "config:type", "t" or "type"
```

When using RMT for registration, the RMT TLS cert must be trusted; or,
the workaround are the following boot params:

```
ptoptions=+reg_ssl_verify reg_ssl_verify=0
```

That is, do NOT expect that `reg_server_cert_finterprint` makes the TLS cert trusted!!!


AutoYaST can use ERB templates that are used for embedding Ruby inside them.

``` shell
$ grep -C 5 -m 1 '<%' autoinst.xml.erb
    </ntp_servers>
    <ntp_sync>systemd</ntp_sync>
  </ntp-client>
  <partitioning t="list">
    <drive t="map">
      <% disk = disks.reject { |d| d[:device] =~ %r{^zram} }.sort_by { |d| d[:size] }.first %>
      <device>/dev/<%= disk[:device] %></device>
      <type t="symbol">CT_DISK</type>
      <use>all</use>
    </drive>
  </partitioning>
```

These templates **must** have `.erb` suffix!!!

An example from an installation env:

``` shell
0:Linux-SLES15SP6-Minimal:~ # grep -C 5 -m1 '<device>' /download/autoinst.xml 
    <ntp_sync>systemd</ntp_sync>
  </ntp-client>
  <partitioning t="list">
    <drive t="map">
      <% disk = disks.reject { |d| d[:device] =~ %r{^zram} }.sort_by { |d| d[:size] }.first %>
      <device><%= disk[:udev_names].first %></device>
      <type t="symbol">CT_DISK</type>
      <use>all</use>
    </drive>
  </partitioning>
  <proxy t="map">

0:Linux-SLES15SP6-Minimal:~ # grep -C 5 -m1 '<device>' /tmp/profile/autoinst.xml 
    <ntp_sync>systemd</ntp_sync>
  </ntp-client>
  <partitioning t="list">
    <drive t="map">
      
      <device>vdb</device>
      <type t="symbol">CT_DISK</type>
      <use>all</use>
    </drive>
  </partitioning>
  <proxy t="map">
```


**NOTE**: SLES installation can be paused with *Shift-F8* key combo!!!

Troubleshooting AutoYaST can be done via `irb`:

``` shell
0:Linux-SLES15SP6-Minimal:~ # irb -ryast -rautoinstall/y2erb
WARNING: Nokogiri was built against LibXML version 2.9.14, but has dynamically loaded 2.10.3

irb(main):001:0> env = Y2Autoinstallation::Y2ERB::TemplateEnvironment.new
=> #<Y2Autoinstallation::Y2ERB::TemplateEnvironment:0x00005616c11a9720>

irb(main):002:0> env.disks
=> [{:vendor=>nil, :device=>"zram1", :udev_names=>["/dev/zram1"], :model=>"Unknown", :serial=>"Unknown", :size=>2097152}, {:vendor=>nil, :device=>"vdb", :udev_names=>["/dev/vdb", "/dev/disk/by-path/pci-0000:08:00.0", "/dev/disk/by-diskseq/69", "/dev/disk/by-path/virtio-pci-0000:08:00.0"], :model=>"Unknown", :serial=>"", :size=>52428800}, {:vendor=>nil, :device=>"zram0", :udev_names=>["/dev/zram0"], :model=>"Unknown", :serial=>"Unknown", :size=>2097152}, {:vendor=>nil, :device=>"vda", :udev_names=>["/dev/vda", "/dev/disk/by-path/virtio-pci-0000:04:00.0", "/dev/disk/by-path/pci-0000:04:00.0", "/dev/disk/by-diskseq/68"], :model=>"Unknown", :serial=>"", :size=>52428800}]

irb(main):003:0> env. disks.reject { |d| d[:device] =~ %r{^zram} }.sort_by { |d| d[:size] }.first
=> {:vendor=>nil, :device=>"vdb", :udev_names=>["/dev/vdb", "/dev/disk/by-path/pci-0000:08:00.0", "/dev/disk/by-diskseq/69", "/dev/disk/by-path/virtio-pci-0000:08:00.0"], :model=>"Unknown", :serial=>"", :size=>52428800}
```


#### SLES linuxrc

`linuxrc`'s `ptoptions` boot parameter causes addition/removal from
`/etc/install.inf` in the installer environment:

``` shell
# grep rdinit /etc/install.inf
Cmdline: splash=silent rdinit=/vtoy/vtoy
```

- customized boot with `ptoptions=+rdinit'

``` shell
# grep rdinit /etc/install.inf
rdinit: /vtoy/vtoy
```

As can be seen, `rdinit` was removed from `Cmdline`, that's cool
because such a parameter impacts the final boot after the installation
is completed.


#### usb installation

Hack to make a bootable USB from an ISO:

``` shell
$ fdisk /dev/sda # create partition and set it active
$ mkfs.ext4 /dev/sda1
$ mount /dev/sda1 /mnt
$ mkdir /tmp/iso
$ mount -o loop <iso> /tmp/iso
$ rsync -vvv -a --exclude 'Module-Desktop-Applications**.rpm' \
    --exclude 'Module-Development-Tools**.rpm' \
    --exclude 'Module-HPC**.rpm' \
    --exclude 'Module-Legacy**.rpm' \
    --exclude 'Module-Legacy**.rpm' \
    --exclude 'Module-Live-Patching**.rpm' \
    --exclude 'Module-RT**.rpm' \
    --exclude 'Module-SUSE-Manager**.rpm' \
    --exclude 'Module-Transactional-Server**.rpm' \
    --exclude 'Module-Web-Scripting**.rpm' \
    /tmp/iso/ /mnt/
$ grub2-install --target=i386-pc --recheck --debug --boot-directory=/mnt/boot /dev/sda
$ cat > /mnt/boot/grub2/grub.cfg <<EOF
serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1
set timeout=60
default=0
menuentry 'Installation' --class opensuse --class gnu-linux --class gnu --class os {
  echo 'Loading kernel ...'
  linux /boot/x86_64/loader/linux textmode=1 console=ttyS0,115200n81
  echo 'Loading initial ramdisk ...'
  initrd /boot/x86_64/loader/initrd
}
EOF
$ umount /mnt
$ umount /tmp/iso

# one can test with qemu

$ qemu-system-x86_64 -m 1024 -smp 2 -drive file=/dev/sdb,format=raw -vga none \
  -nographic
```

*linuxrc* is *init* instead of *systemd*

An example of `linuxrc` options for using bonding:

``` shell
insmod=bonding ifcfg="bond0=dhcp,BONDING_MASTER=yes,BONDING_SLAVE1=eth0,BONDING_MODULE_OPTS=mode=1 miimon=100" ifcfg="eth*=BOOTPROTO=none,STARTMODE=hotplug" hwprobe=+200:*:*:bond0
```

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

## security


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

#### ssh login example

##### logging in

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

##### logging out

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

### linux security module (lsm)

A list of active modules:

``` shell
# Debian Bookworm

$ xargs -0 < /sys/kernel/security/lsm 
lockdown,capability,landlock,yama,apparmor,tomoyo,bpf,ipe,ima,evm

$ zgrep -iP '^CONFIG_DEFAULT_SECURITY' /boot/config-$(uname -r)
CONFIG_DEFAULT_SECURITY_APPARMOR=y

$ zgrep -iP '^CONFIG_(LSM|SECURITY_[A-Z]+)=' /boot/config-$(uname -r)
CONFIG_SECURITY_NETWORK=y
CONFIG_SECURITY_PATH=y
CONFIG_SECURITY_SELINUX=y
CONFIG_SECURITY_TOMOYO=y
CONFIG_SECURITY_APPARMOR=y
CONFIG_SECURITY_YAMA=y
CONFIG_SECURITY_LANDLOCK=y
CONFIG_SECURITY_IPE=y
CONFIG_LSM="landlock,lockdown,yama,loadpin,safesetid,integrity,apparmor,selinux,smack,tomoyo,bpf,ipe"

# SLES 15-SP6

$ xargs -0 < /sys/kernel/security/lsm
lockdown,capability,apparmor,bpf

$ zgrep -iP '^CONFIG_DEFAULT_SECURITY' /boot/config-$(uname -r)
CONFIG_DEFAULT_SECURITY_APPARMOR=y

$ zgrep -iP '^CONFIG_(LSM|SECURITY_[A-Z]+)=' /boot/config-$(uname -r)
CONFIG_SECURITY_NETWORK=y
CONFIG_SECURITY_INFINIBAND=y
CONFIG_SECURITY_PATH=y
CONFIG_SECURITY_SELINUX=y
CONFIG_SECURITY_TOMOYO=y
CONFIG_SECURITY_APPARMOR=y
CONFIG_SECURITY_YAMA=y
CONFIG_SECURITY_LANDLOCK=y
CONFIG_LSM="integrity,apparmor,selinux,bpf
```


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

Understanding how "disabled" or "complaining" profiles work:

``` shell
$  find /etc/apparmor.d/ -name '*php-fpm'
/etc/apparmor.d/local/php-fpm
/etc/apparmor.d/php-fpm

$ find /etc/apparmor.d/ -name '*php-fpm' | grep /local/ | xargs grep -HPv '^\s*(#|$)'

# test PHP script
$ tac /var/log/messages | grep -m1 -Pi 'denied.*php-fpm'
2024-08-26T15:46:09.250094+02:00 example01 kernel: [2690701.272617][   T29] audit: type=1400 audit(1724679969.233:13387): apparmor="DENIED" operation="open" profile="php-fpm" name="/tmp/phptest.php" pid=2240513 comm="php-fpm" requested_mask="r" denied_mask="r" fsuid=465 ouid=0

$ aa-disable /etc/apparmor.d/php-fpm
Disabling /etc/apparmor.d/php-fpm.

$ find /etc/apparmor.d/ -name '*php-fpm' -ls
   594034      4 lrwxrwxrwx   1 root     root           23 Aug 26 15:49 /etc/apparmor.d/disable/php-fpm -> /etc/apparmor.d/php-fpm
   594024      4 -rw-r--r--   1 root     root          224 Aug 26 15:37 /etc/apparmor.d/local/php-fpm
   451524      4 -rw-r--r--   1 root     root         1704 Oct  2  2023 /etc/apparmor.d/php-fpm

# working now!
$ SCRIPT_NAME=/tmp/phptest.php SCRIPT_FILENAME=/tmp/phptest.php REQUEST_METHOD=GET QUERY_STRING=full cgi-fcgi -bind -connect 127.0.0.1:9000 | head
X-Powered-By: PHP/8.0.30
Content-type: text/html; charset=UTF-8

Hello World!
<pre>total 160308
-rw-r--r-- 1 root root     309518 Dec 18  2023 1218113_journal.out
drwx------ 1 root root          0 Oct 19  2023 Temp-133ad4d5-6d9a-4f2f-ad33-40027d405718
drwx------ 1 root root         32 Feb 15  2023 YaST2-02086-S91qJT
-rw------- 1 root root          0 Apr 28  2023 aurules.8xzo9Gyh
srwxrwxrwx 1 gdm  gdm           0 Feb 28 10:27 dbus-RBcxVCLi3d

# back to enforce mode
$  aa-enforce /etc/apparmor.d/php-fpm
Setting /etc/apparmor.d/php-fpm to enforce mode.

$ find /etc/apparmor.d/ -name '*php-fpm' -ls
   594024      4 -rw-r--r--   1 root     root          224 Aug 26 15:37 /etc/apparmor.d/local/php-fpm
   594035      4 -rw-r--r--   1 root     root         1704 Aug 26 15:51 /etc/apparmor.d/php-fpm

# IIUC, they need to be re-executed
$ aa-unconfined  | grep -Po '^(\d+)(?=.*php-fpm)' | xargs -n1 kill

# after php-fpm restart
$ aa-unconfined | grep php-fpm
2241663 /usr/sbin/php-fpm (php-fpm: master process (/etc/php8/fpm/php-fpm.conf)) confined by 'php-fpm (enforce)'
2241664 /usr/sbin/php-fpm confined by 'php-fpm (enforce)'
2241665 /usr/sbin/php-fpm confined by 'php-fpm (enforce)'

# complain mode
$ grep -m1 profile /etc/apparmor.d/php-fpm
profile php-fpm /usr/sbin/php-fpm* flags=(attach_disconnected) {

$ aa-complain /etc/apparmor.d/php-fpm

$ aa-unconfined | grep php-fpm
2241663 /usr/sbin/php-fpm (php-fpm: master process (/etc/php8/fpm/php-fpm.conf)) confined by 'php-fpm (complain)'
2241664 /usr/sbin/php-fpm confined by 'php-fpm (complain)'
2241665 /usr/sbin/php-fpm confined by 'php-fpm (complain)'

# however, complain mode works via changing the "master" profile
$ grep -m1 profile /etc/apparmor.d/php-fpm
profile php-fpm /usr/sbin/php-fpm* flags=(attach_disconnected, complain) {
```


### PAM


#### pam_limits

Note that `*` (asterisk) in `limits.conf(5)` does not work for *root* user!

``` shell
---%>---
NOTE: group and wildcard limits are not applied to the root user. To set a limit for the root user, this field
must contain the literal username root.
---%<---
```


### passwords

to generate encrypted/salted password use `mkpasswd`

``` shell
mkpasswd -m sha-512 -s <<< 'pass123'
$6$AOYSAh/LyR4A.Dz.$A/HSpublK0yEObt9h7MQVOMOp7AKTrA0QxYjHfH/fIM27Zv0yIT1bxoIxPSZWxd8yB6O9OqUYyjDoGt2MyAgd1

python3 -c 'import crypt; print(crypt.crypt("pass123", crypt.mksalt(crypt.METHOD_SHA512)))'
$6$zyuGj55qkPCh/zht$PDk60osb/mzE6xCvJx/X3uDWtU/8jGRefSQHIjCDdYsDEiKcZE3XmX/0dW7Eyz6VUIujn5aJLVslsbywA7su0.
```

### Secure Boot

``` shell
$ modinfo -F sig_key dm_multipath | tr -d ':'
CAFCB5D75EC58982

$ modinfo -F signature dm_multipath | tr -d ':'
A0F43D0C386B0DEA460D1829F524868C696B04ED
                35CB899CAB3DE71EADF2869B1154B0873D266855
                0FEB51B1F21702769E387FC5E5A48524AD1DECAB
                3BD71472E80425B4EFC4E7F1C0B2E23B0D91263D
                EA2DB912603C4DC3A2841D027FE1EC7438B53115
                0ED4C78BE0FB9600BB03997F92D8ED8ADD4D0FE3
                E2A5C8074E90ACD753A35FAD6A94D1D896E0A915
                0F54D669BE52D5DDA2AC8E9616B0E43A69BEBD71
                A6E2C3BCA310069739CB822A597C0681E3D86FFF
                6C68E9468FCA2AD93C763000846E8B153DA61DA2
                3BCA529C59F66D905FD3C8FC68E54A6DA940A09C
                BE769270DBB5294662702DAA0ED9BF3FEBBADCE3
                850B95A1B84914DE3746FF0777A9F6FF

# getting signature from the module

$ modinfo -F signature dm_multipath | tr -d ':' | tr -d '[[:blank:]]' | tr -d '\n' | tr 'A-Z' 'a-z' | xargs -n1
a0f43d0c386b0dea460d1829f524868c696b04ed35cb899cab3de71eadf2869b1154b0873d2668550feb51b1f21702769e387fc5e5a48524ad1decab3bd71472e80425b4efc4e7f1c0b2e23b0d91263dea2db912603c4dc3a2841d027fe1ec7438b531150ed4c78be0fb9600bb03997f92d8ed8add4d0fe3e2a5c8074e90acd753a35fad6a94d1d896e0a9150f54d669be52d5dda2ac8e9616b0e43a69bebd71a6e2c3bca310069739cb822a597c0681e3d86fff6c68e9468fca2ad93c763000846e8b153da61da23bca529c59f66d905fd3c8fc68e54a6da940a09cbe769270dbb5294662702daa0ed9bf3febbadce3850b95a1b84914de3746ff0777a9f6ff

# inspetting signature directly from the module file

$ zstdcat $(modinfo -F filename dm_multipath) | tail -c $(((18*16)+8)) | head -c $((16*16)) | xxd -p | tr -d '\n' | xargs -n1
a0f43d0c386b0dea460d1829f524868c696b04ed35cb899cab3de71eadf2869b1154b0873d2668550feb51b1f21702769e387fc5e5a48524ad1decab3bd71472e80425b4efc4e7f1c0b2e23b0d91263dea2db912603c4dc3a2841d027fe1ec7438b531150ed4c78be0fb9600bb03997f92d8ed8add4d0fe3e2a5c8074e90acd753a35fad6a94d1d896e0a9150f54d669be52d5dda2ac8e9616b0e43a69bebd71a6e2c3bca310069739cb822a597c0681e3d86fff6c68e9468fca2ad93c763000846e8b153da61da23bca529c59f66d905fd3c8fc68e54a6da940a09cbe769270dbb5294662702daa0ed9bf3febbadce3850b95a1b84914de3746ff0777a9f6ff

$ openssl x509 -serial -noout <<EOF
-----BEGIN CERTIFICATE-----
MIIFBDCCA+ygAwIBAgIJAMr8tddexYmCMA0GCSqGSIb3DQEBCwUAMIGmMS0wKwYD
VQQDDCRTVVNFIExpbnV4IEVudGVycHJpc2UgU2VjdXJlIEJvb3QgQ0ExCzAJBgNV
BAYTAkRFMRIwEAYDVQQHDAlOdXJlbWJlcmcxITAfBgNVBAoMGFNVU0UgTGludXgg
UHJvZHVjdHMgR21iSDETMBEGA1UECwwKQnVpbGQgVGVhbTEcMBoGCSqGSIb3DQEJ
ARYNYnVpbGRAc3VzZS5kZTAeFw0yMzAzMDExMzU2NTlaFw0zMzA5MjgxMzU2NTla
MIGrMTIwMAYDVQQDDClTVVNFIExpbnV4IEVudGVycHJpc2UgU2VjdXJlIEJvb3Qg
U2lnbmtleTELMAkGA1UEBhMCREUxEjAQBgNVBAcMCU51cmVtYmVyZzEhMB8GA1UE
CgwYU1VTRSBMaW51eCBQcm9kdWN0cyBHbWJIMRMwEQYDVQQLDApCdWlsZCBUZWFt
MRwwGgYJKoZIhvcNAQkBFg1idWlsZEBzdXNlLmRlMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAwgAicO+QnMo6EvHxohaLlFQq2c5hULzSwjuZzI7mHIFZ
5fyKOnhT/XFhqK8LI8Bbn9pD58nUhLXl9++a+wHunRApx/hu7pFgFwBDVtHT7a2x
VS++CuY4v5tDYfd6T81IdLKiHuUMT8SB3zqNV6/1EPVX7nR1GcRJq6RwC+Gg78re
rE4K6tZBh//nh+/i/Rla6eUkuWXOPLH6P/iPQZNw4XKGoCmeWGv6gShjgJDePaxh
5fDt34ZrJiAFtqhNw1+VFHdKQvUr7JMMjgS2IxJWs7LgH5yXR+o6HXJYAw324JX5
AC+zsferybkCa6WKY39m3T8YFZzrvg38z53WejroawIDAQABo4IBLDCCASgwDAYD
VR0TAQH/BAIwADAdBgNVHQ4EFgQUp0a2S2y3HxM4VjgFX0YWK6xjKs0wgdMGA1Ud
IwSByzCByIAU7KsNQsRWz3cENrlzmThill6HJi+hgaykgakwgaYxLTArBgNVBAMM
JFNVU0UgTGludXggRW50ZXJwcmlzZSBTZWN1cmUgQm9vdCBDQTELMAkGA1UEBhMC
REUxEjAQBgNVBAcMCU51cmVtYmVyZzEhMB8GA1UECgwYU1VTRSBMaW51eCBQcm9k
dWN0cyBHbWJIMRMwEQYDVQQLDApCdWlsZCBUZWFtMRwwGgYJKoZIhvcNAQkBFg1i
dWlsZEBzdXNlLmRlggEBMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEF
BQcDAzANBgkqhkiG9w0BAQsFAAOCAQEAp7eGuRLpkhIXak6AfGyCJQGKGH6/lPLg
V3GWE5z27JdlvGH/GJ2ileitX3CEg7f7NSInvcnJATnBoKSmcQWgRe4Fc56+LAjq
c8uyMfPQLT3fgFXfVBKUCJJoOvdb2LhQP+dyZ7CcEfFYMqJTOJHzs56K3gRMRBWV
IMHlUjhavmO9szW7RSGMLZC7I9CynQn0Fr3prncnLfI9ifCkg56W29RjV1J1CvHf
pqUiMuwWqTbVpK45lxuVuQDEfKmQxCzqmn+3yTqED1R4F9Yyv0bxEQ4AJnfN7gTn
RKaFwjrFaU52atAQgt8O1dGLoRs2xtbJA0JL2+mXQKYb3OOXuih/pg==
-----END CERTIFICATE-----
EOF
serial=CAFCB5D75EC58982
```

The above 'serial' confirms it was this key used to sign the module.


### SELinux

How to remove a custom module:

``` shell
$ semodule -l | grep mycustompolicy

$ semodule -r mycustompolicy

$ semodule -l | grep mycustompolicy
```

How to define a custom module:

``` shell
$ cat > sssd_override.te <<EOF
module sssd_override 1.0;

require {
    type sssd_t;
        type net_conf_t;
	    class dir watch;
	    }

# Allow sssd_t to watch net_conf_t directories
allow sssd_t net_conf_t:dir watch;
EOF

$ checkmodule -M -m -o sssd_override.mod sssd_override.te
$ semodule_package -o sssd_override.pp -m sssd_override.mod
$ semodule -i sssd_override.pp

$ sesearch --allow -s sssd_t -t net_conf_t -c dir | grep watch
```

SELinux status:

``` shell
$ getenforce
Enforcing

$ sestatus
SELinux status:                 enabled
SELinuxfs mount:                /sys/fs/selinux
SELinux root directory:         /etc/selinux
Loaded policy name:             targeted
Current mode:                   enforcing
Mode from config file:          enforcing
Policy MLS status:              enabled
Policy deny_unknown status:     allowed
Memory protection checking:     requested (insecure)
Max kernel policy version:      33

$ grep -H '' /sys/fs/selinux/enforce
/sys/fs/selinux/enforce:1
```

## system troubleshooting and performance

What is attached to my network interface?

``` shell
$ grep ^iff: /proc/*/fdinfo/* 2>/dev/null
/proc/26241/fdinfo/7:iff:       tun0

$ ps -eo user,pid,comm | grep '[2]6241'
nm-open+ 26241 openvpn
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

### kvm

How to detect if a system is KVM VM? This could give a hint:

``` shell
$ dmesg | grep kvm-clock
[    0.000000] kvm-clock: Using msrs 4b564d01 and 4b564d00
[    0.000000] kvm-clock: cpu 0, msr 35601001, primary cpu clock
[    0.000000] kvm-clock: using sched offset of 4277437370 cycles
[    0.000002] clocksource: kvm-clock: mask: 0xffffffffffffffff max_cycles: 0x1cd42e4dffb, max_idle_ns: 881590591483 ns
[    0.122327] kvm-clock: cpu 1, msr 35601041, secondary cpu clock
[    0.926531] clocksource: Switched to clocksource kvm-clock
```

``` shell
$ lscpu | grep '^Hypervisor'
Hypervisor vendor:               KVM
```

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

Changing path of backing file:

``` shell
$ qemu-img info s125admem01.qcow2
image: s125admem01.qcow2
file format: qcow2
virtual size: 21 GiB (22548578304 bytes)
disk size: 8.64 GiB
cluster_size: 65536
backing file: /var/lib/libvirt/images/sles12sp5-template.qcow2
backing file format: qcow2
Snapshot list:                                                                                                                                                                                                                                 ID        TAG               VM SIZE                DATE     VM CLOCK     ICOUNT
1         test01                0 B 2022-02-15 16:22:47 00:00:00.000          0
Format specific information:
    compat: 1.1
    compression type: zlib
    lazy refcounts: true
    refcount bits: 16
    corrupt: false
    extended l2: false

# sles12sp5-template.qcow2 was renamed to _s125.qcow2

$ qemu-img rebase -f qcow2 -u -b _s125.qcow2 -F qcow2 s125admem01.qcow2

$ qemu-img info s125admem01.qcow2
image: s125admem01.qcow2
file format: qcow2
virtual size: 21 GiB (22548578304 bytes)
disk size: 8.64 GiB
cluster_size: 65536
backing file: _s125.qcow2
backing file format: qcow2
Snapshot list:
ID        TAG               VM SIZE                DATE     VM CLOCK     ICOUNT
1         test01                0 B 2022-02-15 16:22:47 00:00:00.000          0
Format specific information:
    compat: 1.1
    compression type: zlib
    lazy refcounts: true
    refcount bits: 16
    corrupt: false
    extended l2: false
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


##### ppc64

How to emulate pSeries/POWER ? Below, with multipath as well:

``` shell
$ qemu-system-ppc64le \
-m 4g \
-machine pseries,cap-cfpc=broken,cap-sbbc=broken,cap-ibs=broken \
-smp 8 \
-nodefaults \
-monitor pty \
-serial mon:stdio \
-device virtio-rng-pci \
-monitor telnet:127.0.0.1:55555,server,nowait \
-device virtio-net,netdev=net0 \
-netdev user,id=net0 \
-nic user,hostfwd=tcp::5022-:22 \
-vga none \
-nographic \
-boot c \
-device spapr-vscsi,id=vscsi0 \
-drive file=/dev/system/test,format=raw,id=hdisk0,if=none,file.locking=off \
-device scsi-hd,drive=hdisk0,scsi-id=0,wwn=0x5000039afc38015c \
-drive file=/dev/system/test,format=raw,id=hdisk1,if=none,file.locking=off \
-device scsi-hd,drive=hdisk1,scsi-id=1,wwn=0x5000039afc38015c \
-drive file=/dev/system/test,format=raw,id=hdisk2,if=none,file.locking=off \
-device scsi-hd,drive=hdisk2,scsi-id=1,wwn=0x5000039afc38015c \
-drive file=/dev/system/test,format=raw,id=hdisk3,if=none,file.locking=off \
-device scsi-hd,drive=hdisk3,scsi-id=1,wwn=0x5000039afc38015c \
-drive file=/dev/system/test,format=raw,id=hdisk4,if=none,file.locking=off \
-device scsi-hd,drive=hdisk4,scsi-id=1,wwn=0x5000039afc38015c \
-drive file=/dev/system/test,format=raw,id=hdisk5,if=none,file.locking=off \
-device scsi-hd,drive=hdisk5,scsi-id=1,wwn=0x5000039afc38015c \
-drive file=/dev/system/test,format=raw,id=hdisk6,if=none,file.locking=off \
-device scsi-hd,drive=hdisk6,scsi-id=1,wwn=0x5000039afc38015c \
-drive file=/dev/system/test,format=raw,id=hdisk7,if=none,file.locking=off \
-device scsi-hd,drive=hdisk7,scsi-id=1,wwn=0x5000039afc38015c \
-prom-env "boot-command=boot disk: -s verbose"
```

Booting alpinelinux/ppc64 works with the following:

``` shell
$ qemu-system-ppc64 \
-m 4g \
-machine pseries,cap-cfpc=broken,cap-sbbc=broken,cap-ibs=broken \
-smp 8 \
-nodefaults \
-monitor pty \
-serial mon:stdio \
-device virtio-rng-pci \
-monitor telnet:127.0.0.1:55555,server,nowait \
-device virtio-net,netdev=net0 \
-netdev user,id=net0 \
-nic user,hostfwd=tcp::5022-:22 \
-vga none \
-nographic \
-prom-env "boot-command=boot cdrom:" \
-device spapr-vscsi,id=vscsi0 \
-drive file=./alpine-standard-3.20.3-ppc64le.iso,format=raw,id=cdrom0,if=none \
-device scsi-cd,drive=cdrom0,scsi-id=1
```


#### qemu-nbd

``` shell
qemu-nbd --connect=/dev/nbd0 <qemu_image> # connect eg. a qcow2 image
qemu-nbd -d /dev/nbd0
```

#### snapshots

``` shell
$ virsh snapshot-create-as s125admem01 test01 # create internal snapshot
Domain snapshot test01 created

$ qemu-img snapshot -l s125admem01.qcow2
Snapshot list:
ID        TAG               VM SIZE                DATE     VM CLOCK     ICOUNT
1         test01                0 B 2022-02-08 19:09:44 00:00:00.000          0

$ virsh snapshot-delete s125admem01 test01
Domain snapshot test01 deleted

$ qemu-img snapshot -l s125admem01.qcow2
```

### libguestfs

#### guestfish

``` shell
$ guestfish -a sles12sp4-template.qcow2 -m /dev/sda2:/::btrfs

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

``` shell
><fs> sh "rpm -qa --qf '%{NAME}-%{VERSION}\n' *tools* *snmp*| sort"
compat-usrmerge-tools-84.87
dbus-1-tools-1.14.10
dosfstools-4.2
glib2-tools-2.78.6
kexec-tools-2.0.27
libpwquality-tools-1.4.5
libqmi-tools-1.32.4
libsolv-tools-base-0.7.34
libvmtools0-13.0.0
libxml2-tools-2.11.6
microos-tools-2.21+git24
net-tools-2.10
open-vm-tools-13.0.0
p11-kit-tools-0.25.3
python311-setools-4.4.3
python311-setuptools-70.0.0
selinux-tools-3.5
suse-module-tools-16.0.43
suse-module-tools-scriptlets-16.0.43
thin-provisioning-tools-0.9.0
tpm2.0-tools-5.7
```

Or...

``` shell
$ guestfish --ro -a Linux-SLES15SP6-Minimal.qcow2

Welcome to guestfish, the guest filesystem shell for
editing virtual machine filesystems and disk images.

Type: ‘help’ for help on commands
      ‘man’ to read the manual
      ‘quit’ to quit the shell

><fs> run
 100% ⟦▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒⟧ 00:00
><fs> list-filesystems
/dev/sda1: vfat
/dev/sda2: ext4
/dev/sysvg/lv_log: ext4
/dev/sysvg/lv_opt: ext4
/dev/sysvg/lv_root: ext4
/dev/sysvg/lv_tmp: ext4
><fs> mount /dev/sysvg/lv_root /
><fs> cat /etc/sysconfig/network/ifcfg-eth0
BOOTPROTO='dhcp'
STARTMODE='auto'
```

What about if local host does not support, for example, filesystem use
in the image (eg. EL not supporting BTRFS)?

``` shell
# download appliance from:
# https://download.libguestfs.org/binaries/appliance/

$ export LIBGUESTFS_PATH=<path_to_applicance> guestfish ...
```

Or you can rebuild _supermin_ appliance yourself, but the above is
much quicker solution.

There are more tools - to list filesystems, copy in/out, cat files, list paths...

``` shell
$ virt-ls -l -d micro55qe01 -m /dev/sda3:/:subvol=@/boot/writable /
total 4
drwxr-xr-x.  1 root root   36 Sep 24 13:01 .
drwxr-xr-x  20 root root 4096 Sep 25 06:46 ..
-rw-r--r--.  1 root root    0 Sep 24 13:01 firstboot_happened
```


### libvirt

#### auth-SASL

NOTE, this is not very secure!!!

``` shell
$  grep -RHPv '^\s*(#|$)' /etc/libvirt/libvirtd.conf /etc/sasl2/libvirt.conf
/etc/libvirt/libvirtd.conf:listen_tcp = 1
/etc/libvirt/libvirtd.conf:auth_tcp = "sasl"
/etc/libvirt/libvirtd.conf:log_level = 1
/etc/sasl2/libvirt.conf:mech_list: digest-md5
/etc/sasl2/libvirt.conf:sasldb_path: /etc/libvirt/passwd.db

$ sasldblistusers2 -f /etc/libvirt/passwd.db
foo@avocado.example.com: userPassword
```


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

An example for SASL (NOTE, that it is not very secure!!!) authentication:

``` shell
$ grep -H '' .config/libvirt/{libvirt,auth}.conf
.config/libvirt/libvirt.conf:uri_aliases = [
.config/libvirt/libvirt.conf:  "avocado=qemu+tcp://10.156.233.50:16509/system",
.config/libvirt/libvirt.conf:]
.config/libvirt/auth.conf:[auth-libvirt-avocado]
.config/libvirt/auth.conf:credentials=avocado
.config/libvirt/auth.conf:
.config/libvirt/auth.conf:[credentials-avocado]
.config/libvirt/auth.conf:authname=foo
.config/libvirt/auth.conf:realm=avocado.example.com
.config/libvirt/auth.conf:password=bar
```

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

Updating VM/domain memory online:

``` shell
$ virsh dominfo s154qb01 | grep memory
Max memory:     4194304 KiB
Used memory:    1048576 KiB

$ virsh virsh setmem s154qb01 4194304

$ virsh dominfo s154qb01 | grep memory
Max memory:     4194304 KiB
Used memory:    4194304 KiB
```

`virsh` also allows to do [backup](https://libvirt.org/kbase/live_full_disk_backup.html) of libvirt domain's block devices.

``` shell
$  cat > /tmp/in <<EOF
> <domainbackup mode='push'>
>   <disks>
>     <disk name='vda' type='file' backupmode='full'>
>       <driver type='qcow2'/>
>       <target file='/var/lib/libvirt/images/s125qb01.qcow2.testbackup'/>
>     </disk>
>   </disks>
> </domainbackup>
> EOF

$ virsh backup-begin s125qb01 --backupxml /tmp/in
Backup started

$ virsh domjobinfo s125qb01
Job type:         Unbounded
Operation:        Backup
Time elapsed:     31905        ms
File processed:   2.007 GiB
File remaining:   18.993 GiB
File total:       21.000 GiB
```

``` shell
$ virt-xml-validate - domainbackup <<EOF
> <domainbackup mode='push'>
>   <disks>
>     <disk name='vda' backup='yes' type='file' backupmode='full' index='3'>
>       <driver type='qcow2'/>
>       <target file='/var/lib/libvirt/images/s125qb01.qcow2.foo'/>
>     </disk>
>   </disks>
> </domainbackup>
> EOF
Relax-NG validity error : Extra element disks in interleave
-:2: element disks: Relax-NG validity error : Element domainbackup failed to validate content
- fails to validate

$ virt-xml-validate - domainbackup <<EOF
> <domainbackup mode='push'>
>   <disks>
>     <disk name='vda' backup='yes' type='file' backupmode='full'>
>       <driver type='qcow2'/>
>       <target file='/var/lib/libvirt/images/s125qb01.qcow2.foo'/>
>     </disk>
>   </disks>
> </domainbackup>
> EOF
- validates

$ grep -c index /usr/share/libvirt/schemas/domainbackup.rng
0
```

`virsh` and QEMU Guest Agent integration:

``` shell
$ $ virsh qemu-agent-command jbelka-jbw2k22qe01 --cmd '{"execute":"guest-ping"}'
{"return":{}}

$ virsh qemu-agent-command jbelka-jbw2k22qe01 --cmd '{"execute":"guest-info"}' | jq '.' | head
{
  "return": {
    "version": "107.0.1",
    "supported_commands": [
      {
        "enabled": true,
        "name": "guest-get-cpustats",
        "success-response": true
      },
      {

```

See below that if the VM is up and QEMU GA is alive, it shows *connected*.

``` shell
$ virsh dumpxml jbw2k22qe01 --xpath '//channel'
<channel type="unix">
  <source mode="bind" path="/var/lib/libvirt/qemu/channel/target/domain-37-jbw2k22qe01/org.qemu.guest_agent.0"/>
  <target type="virtio" name="org.qemu.guest_agent.0" state="connected"/>
  <alias name="channel0"/>
  <address type="virtio-serial" controller="0" bus="0" port="1"/>
</channel>
```

``` shell
$ virsh domfsinfo jbw2k22qe01
 Mountpoint        Name                                                Type    Target
---------------------------------------------------------------------------------------
 C:\               \\?\Volume{bba45489-3697-4c75-a5b9-c9a1a552cea8}\   NTFS
 System Reserved   \\?\Volume{88d20f38-79bd-4411-9023-20e52883e124}\   NTFS
 System Reserved   \\?\Volume{339d018f-c6a1-47c2-8270-dd37afa8809d}\   FAT32
 D:\               \\?\Volume{4dba0c41-abae-11ed-8a0a-806e6f6e6963}\   CDFS
```

Resizing *online* block device of a VM:

``` shell
# (KVM host) 'sdb' is what interests me for the VM (jb155sapqe02)
$ virsh domblklist jb155sapqe02 | grep sdb
 sdb      /dev/mapper/sll--system-jb125qb01

# (KVM host) size in bytes

$ lvs --unit b | grep jb125qb01
  jb125qb01      sll-system -wi-ao----  23622320128B

# (KVM host) size changed
$ lvextend -L +1G sll-system/jb125qb01
  Size of logical volume sll-system/jb125qb01 changed from 23.00 GiB (5888 extents) to 24.00 GiB (6144 extents).
  Logical volume sll-system/jb125qb01 successfully resized.
$ lvs --unit b | grep jb125qb01
  jb125qb01      sll-system -wi-ao----  25769803776B

# (VM)
$ lsscsi -is | grep /dev/sde
[0:0:0:1]    disk    QEMU     QEMU HARDDISK    2.5+  /dev/sde   0QEMU_QEMU_HARDDISK_drive-scsi0-0-0-1  23.6GB

# (KVM host) query from KVM host for QEMU view on the VM's block devices
$ virsh qemu-monitor-command jb155sapqe02 --hmp 'info block -n -v' | grep -m1 -A3 -P 'image: .*jb125qb01'
image: /dev/mapper/sll--system-jb125qb01
file format: raw
virtual size: 22 GiB (23622320128 bytes)
disk size: 0 B

# (KVM host) resizing QEMU view of block devices (size is from `lvs' after resize)
$ virsh blockresize --domain jb155sapqe02 --path /dev/mapper/sll--system-jb125qb01 --size 25769803776B
Block device '/dev/mapper/sll--system-jb125qb01' is resized

# (VM)
$  lsscsi -s | grep /dev/sde
[0:0:0:1]    disk    QEMU     QEMU HARDDISK    2.5+  /dev/sde   25.7GB
```

The same via `virsh qemu-monitor-command` directly:

``` shell
$ virsh qemu-monitor-command jb155sapqe02 --cmd '{"execute": "block_resize", "arguments": { "node-name": "libvirt-4-format", "size": 26843545600 } }'
{"return":{},"id":"libvirt-21003"}
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

Attaching disk online:

``` shell
$ virsh domblklist s153cl1
 Target   Source
-----------------------------------------------
 vda      /home/vms/s153cl1.qcow2
 sda      iqn.2022-06.com.example.t14s:san1/0
 sdb      iqn.2022-06.com.example.t14s:san1/1
 sdc      iqn.2022-06.com.example.t14s:san1/0
 sdd      iqn.2022-06.com.example.t14s:san1/1
 sde      iqn.2022-06.com.example.t14s:san2/0
 sdf      iqn.2022-06.com.example.t14s:san2/1
 sdg      iqn.2022-06.com.example.t14s:san2/0
 sdh      iqn.2022-06.com.example.t14s:san2/1
 sdi      -

$ cat /tmp/disk.xml
<disk type="file" device="disk">
          <driver name="qemu" type="qcow2"/>
            <source file="/home/vms/s153cl2-drbd.qcow2"/>
              <target dev="sdj" bus="scsi"/>
              <address type='drive' controller='0' bus='0' target='0' unit='6'/>
      </disk>

$ virsh attach-device s153cl1 /tmp/disk.xml --live
Device attached successfully
```

#### troubleshooting

``` shell
env VIRSH_DEBUG=0 LIBVIRT_DEBUG=1 virsh # or any other libvirt tool
```

Block device unavailability impacts start of the VM:

``` shell
# comment inline
$ sed -n '/09:48:48.853+0000: starting up/,$p' /var/log/libvirt/qemu/s153cl1.log  | sed -n -e '1p' -e '/blockdev.*iscsi/p' -e '/Failed/p' -e '/shutting/p'
2023-01-13 09:48:48.853+0000: starting up libvirt version: 8.10.0, qemu version: 7.1.0openSUSE Tumbleweed, kernel: 6.1.4-1.g4b9b43c-default, hostname: t14s
-blockdev '{"driver":"iscsi","portal":"192.168.0.1:3260","target":"iqn.2022-06.com.example.t14s:san1","lun":0,"transport":"tcp","initiator-name":"iqn.2022-06.com.example.s153cl1:eth0","node-name":"libvirt-9-storage","cache":{"direct":true,"no-flush":false},"auto-read-only":true,"discard":"unmap"}' \
                                       ^---+--- iSCSI target on this IP is not available
-blockdev '{"driver":"iscsi","portal":"192.168.122.1:3260","target":"iqn.2022-06.com.example.t14s:san1","lun":1,"transport":"tcp","initiator-name":"iqn.2022-06.com.example.s153cl1:eth0","node-name":"libvirt-8-storage","cache":{"direct":true,"no-flush":false},"auto-read-only":true,"discard":"unmap"}' \
-blockdev '{"driver":"iscsi","portal":"192.168.123.1:3261","target":"iqn.2022-06.com.example.t14s:san1","lun":0,"transport":"tcp","initiator-name":"iqn.2022-06.com.example.s153cl1:eth1","node-name":"libvirt-7-storage","cache":{"direct":true,"no-flush":false},"auto-read-only":true,"discard":"unmap"}' \
-blockdev '{"driver":"iscsi","portal":"192.168.123.1:3261","target":"iqn.2022-06.com.example.t14s:san1","lun":1,"transport":"tcp","initiator-name":"iqn.2022-06.com.example.s153cl1:eth1","node-name":"libvirt-6-storage","cache":{"direct":true,"no-flush":false},"auto-read-only":true,"discard":"unmap"}' \
-blockdev '{"driver":"iscsi","portal":"192.168.122.1:3261","target":"iqn.2022-06.com.example.t14s:san2","lun":0,"transport":"tcp","initiator-name":"iqn.2022-06.com.example.s153cl1:eth0","node-name":"libvirt-5-storage","cache":{"direct":true,"no-flush":false},"auto-read-only":true,"discard":"unmap"}' \
-blockdev '{"driver":"iscsi","portal":"192.168.122.1:3261","target":"iqn.2022-06.com.example.t14s:san2","lun":1,"transport":"tcp","initiator-name":"iqn.2022-06.com.example.s153cl1:eth0","node-name":"libvirt-4-storage","cache":{"direct":true,"no-flush":false},"auto-read-only":true,"discard":"unmap"}' \
-blockdev '{"driver":"iscsi","portal":"192.168.123.1:3260","target":"iqn.2022-06.com.example.t14s:san2","lun":0,"transport":"tcp","initiator-name":"iqn.2022-06.com.example.s153cl1:eth1","node-name":"libvirt-3-storage","cache":{"direct":true,"no-flush":false},"auto-read-only":true,"discard":"unmap"}' \
-blockdev '{"driver":"iscsi","portal":"192.168.123.1:3260","target":"iqn.2022-06.com.example.t14s:san2","lun":1,"transport":"tcp","initiator-name":"iqn.2022-06.com.example.s153cl1:eth1","node-name":"libvirt-2-storage","cache":{"direct":true,"no-flush":false},"auto-read-only":true,"discard":"unmap"}' \
2023-01-13T09:50:58.764202Z qemu-system-x86_64: -blockdev {"driver":"iscsi","portal":"192.168.0.1:3260","target":"iqn.2022-06.com.example.t14s:san1","lun":0,"transport":"tcp","initiator-name":"iqn.2022-06.com.example.s153cl1:eth0","node-name":"libvirt-9-storage","cache":{"direct":true,"no-flush":false},"auto-read-only":true,"discard":"unmap"}: iSCSI: Failed to connect to LUN : iscsi_service failed with : iscsi_service_reconnect_if_loggedin. Can not reconnect right now.
2023-01-13T09:50:58.764202Z qemu-system-x86_64: -blockdev {"driver":"iscsi","portal":"192.168.0.1:3260","target":"iqn.2022-06.com.example.t14s:san1","lun":0,"transport":"tcp","initiator-name":"iqn.2022-06.com.example.s153cl1:eth0","node-name":"libvirt-9-storage","cache":{"direct":true,"no-flush":false},"auto-read-only":true,"discard":"unmap"}: iSCSI: Failed to connect to LUN : iscsi_service failed with : iscsi_service_reconnect_if_loggedin. Can not reconnect right now.
2023-01-13 09:50:59.021+0000: shutting down, reason=failed
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
