# LDAP & Kerberos cheatsheet

## 389 Directory Server

One can create 389 DS instance via:

- a custom config file
- from a template

But basically `dscreate create-template` just generate a default
config file, so there's not really a difference which mode you would
use!

### 389 DS server instance creation using a custom config file

``` shell
$ pwdhash -s PBKDF2-SHA512 password
{PBKDF2-SHA512}100000$aVzevnU/i2KGIRiCaVaEmQv4ilKYTMwv$qIw3xrCTKDJ0ucAPyDHNgflen88DY++yiuIssaLc3VH8riY0DxXRKWmlyL1EyXr1qda4fE2scSUh6Z0s+G1yNg==
```

``` shell
$ cat > ${XDG_RUNTIME_DIR}/389ds.inf <<-EOF
[general]
full_machine_name = jb154sapqe01.example.com
start = False
strict_host_checking = False
[slapd]
instance_name = EXAMPLECOM
port = 3899
secure_port = 6366
root_password = {PBKDF2-SHA512}100000$aVzevnU/i2KGIRiCaVaEmQv4ilKYTMwv$qIw3xrCTKDJ0ucAPyDHNgflen88DY++yiuIssaLc3VH8riY0DxXRKWmlyL1EyXr1qda4fE2scSUh6Z0s+G1yNg==
self_sign_cert = True
# for LMDB backend, see https://tinyurl.com/523nte85
db_lib = mdb
mdb_max_size = 21474836480
[backend-userroot]
create_suffix_entry = True
sample_entries = yes
suffix = dc=example,dc=com
EOF

$ dscreate from-file ${XDG_RUNTIME_DIR}/389ds.inf | tee ${XDG_RUNTIME_DIR}/389ds-tmpl.log
Starting installation ...
Validate installation settings ...
Create file system structures ...
selinux is disabled, will not relabel ports or files.
Create database backend: dc=example,dc=com ...
Perform post-installation tasks ...
Completed installation for instance: slapd-EXAMPLECOM

# I defined it as not autostarted AFTER the installation

$ dsctl EXAMPLECOM status
Instance "EXAMPLECOM" is not running

$ dsctl EXAMPLECOM start
Instance "EXAMPLECOM" has been started

$ dsctl EXAMPLECOM status
Instance "EXAMPLECOM" is running

$ systemctl is-enabled dirsrv@EXAMPLECOM.service
enabled

$ systemctl is-active dirsrv@EXAMPLECOM.service
active

# name instances

$ dsctl -l
slapd-EXAMPLECOM
```


### default .dsrc for sysadmins

`.dsrc` is like `ldap.conf(5)`, so it save typing same options all the time.

``` shell
$ ( umask 066; cat > ~/.dsrc <<EOF
[EXAMPLECOM]
uri = ldapi://%%2fvar%%2frun%%2fslapd-EXAMPLECOM.socket
basedn = dc=example,dc=com
binddn = cn=Directory Manager
EOF
)
```

But it's probably easier to use `dsctl` tool:

``` shell
$ dsctl EXAMPLECOM dsrc create \
  --uri ldapi://%%2fvar%%2frun%%2fslapd-EXAMPLECOM.socket \
  --basedn dc=example,dc=com \
  --binddn cn='Directory Manager' \
  --pwdfile /root/.dspasswd
```


### 389ds management

- `dsconf`
- `dsctl`
- `dsidm`


``` shell
$ dsidm EXAMPLECOM client_config sssd.conf | grep -Pv '^\s*($|#)'
[domain/ldap]
cache_credentials = True
id_provider = ldap
auth_provider = ldap
access_provider = ldap
chpass_provider = ldap
ldap_schema = rfc2307
ldap_search_base = dc=example,dc=com
ldap_uri = ldapi://%2fvar%2frun%2fslapd-EXAMPLECOM.socket
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


### external TLS in 389ds

**WARNING**: not sure if this is the best way to do it!


What is the current cert used?

``` shell
$ : | openssl s_client -connect 127.0.0.1:636 -showcerts 2>/dev/null | \
    awk -v cmd='openssl x509 -noout -subject -startdate -enddate -ext subjectAltName -noout' '/BEGIN/ {close(cmd)}; { print | cmd }' 2>/dev/null
subject=C = AU, ST = Queensland, L = 389ds, O = testing, GN = 727d7e30-1141-45f9-87e0-f6cb82d875b8, CN = s153cl1.example.com
notBefore=Feb 13 08:13:46 2023 GMT
notAfter=Feb 13 08:13:46 2025 GMT
X509v3 Subject Alternative Name:
    DNS:s153cl1.example.com
subject=C = AU, ST = Queensland, L = 389ds, O = testing, CN = ssca.389ds.example.com
notBefore=Nov 11 09:39:44 2022 GMT
notAfter=Nov 11 09:39:44 2024 GMT
```

Listing current certs in NSS db:

``` shell
$ certutil -L -d /etc/dirsrv/slapd-TEST/

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

Self-Signed-CA                                               CT,,
Server-Cert                                                  u,u,u
```

Listing current keys in NSS db:

``` shell
$ certutil -K -d /etc/dirsrv/slapd-TEST/ -f <(awk -F: '{ print $2 }' /etc/dirsrv/slapd-TEST/pin.txt)
certutil: Checking token "NSS Certificate DB" in slot "NSS User Private Key and Certificate Services"
< 0> rsa      7d5305c53f112fe3a659570eee6c27b72307610f   NSS Certificate DB:Server-Cert
```

What is this 'Self-Signed-CA' ?

``` shell
$ certutil -L -d /etc/dirsrv/slapd-TEST/ -n 'Self-Signed-CA' -a  | openssl x509 -subject -noout
subject=C = AU, ST = Queensland, L = 389ds, O = testing, CN = ssca.389ds.example.com

s154cl1:~ # dsconf -D 'cn=Directory Manager' ldap://127.0.0.1 security ca-certificate list
Enter password for cn=Directory Manager on ldap://127.0.0.1:
Certificate Name: Self-Signed-CA
Subject DN: CN=ssca.389ds.example.com,O=testing,L=389ds,ST=Queensland,C=AU
Issuer DN: CN=ssca.389ds.example.com,O=testing,L=389ds,ST=Queensland,C=AU
Expires: 2024-11-11 09:39:44
Trust Flags: CT,,
```

What is the connection between 389DS instance and '*Server-Cert*'"nickname" or alias?

``` shell
$ grep nsSSLPersonalitySSL /etc/dirsrv/slapd-TEST/dse.ldif
nsSSLPersonalitySSL: Server-Cert
```

Importing external CA (a simulation with CloudFlare Origin Server
CA/cert/key as I don't have real cert signed by a trusted public CA):

``` shell
$ dsconf -D 'cn=Directory Manager' ldap://127.0.0.1 security ca-certificate add \
    --file /tmp/origin_ca_rsa_root.pem --name 'CloudFlare Origin SSL Certificate Authority'
Enter password for cn=Directory Manager on ldap://127.0.0.1:
Successfully added CA certificate (CloudFlare Origin SSL Certificate Authority)
```

Listing CA list after the import:

``` shell
$ certutil -L -d /etc/dirsrv/slapd-TEST/ | grep CloudFlare
CloudFlare Origin SSL Certificate Authority                  CT,,
```

Import external cert/key:

``` shell
$ dsctl TEST tls import-server-key-cert /tmp/cert /tmp/key
```

Listing 389DS instance tls cert for 'Server-Cert':

``` shell
$ dsctl TEST tls show-cert 'Server-Cert' | head -n 20
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            4c:b1:6d:60:84:99:82:03:92:6d:60:6a:f3:ee:04:65:
            8f:0b:f3:71
        Signature Algorithm: PKCS #1 SHA-256 With RSA Encryption
        Issuer: "ST=California,L=San Francisco,OU=CloudFlare Origin SSL Certi
            ficate Authority,O="CloudFlare, Inc.",C=US"
        Validity:
            Not Before: Sun Nov 21 17:17:00 2021
            Not After : Mon Nov 17 17:17:00 2036
        Subject: "CN=CloudFlare Origin Certificate,OU=CloudFlare Origin CA,O=
            "CloudFlare, Inc.""
        Subject Public Key Info:
            Public Key Algorithm: PKCS #1 RSA Encryption
            RSA Public Key:
                Modulus:
                    c1:4d:96:a9:7a:45:c0:a0:71:52:81:70:a4:01:d0:f3:
                    03:bb:f5:a1:a3:52:e9:ec:a4:05:e2:c4:6a:71:9b:01:
```

Let's validate, that it is imported correctly, while "exporting"
'Server-Cert' form NSS DB and comparing md5 checksum of the key on the
filesystem:

``` shell
$ pk12util -o /dev/stdout -n 'Server-Cert' -d /etc/dirsrv/slapd-TEST/ -k <(awk -F: '{ print $2 }' /etc/dirsrv/slapd-TEST/pin.txt) | \
    openssl pkcs12 -nocerts -nodes | openssl rsa -modulus -noout | openssl md5
Enter password for PKCS12 file:
Re-enter password:
Enter Import Password:
(stdin)= 062e714d1ad4d90504de051499382782

$ openssl rsa -in /tmp/key -modulus -noout | openssl md5
(stdin)= 062e714d1ad4d90504de051499382782
```

Let's restart and validate it (I needed to obfuscate subjectAltName value!):

``` shell
$ systemctl status dirsrv@TEST.service

$ : | openssl s_client -connect 127.0.0.1:636 -showcerts 2>/dev/null | \
    awk -v cmd='openssl x509 -noout -subject -startdate -enddate -ext subjectAltName' '/BEGIN/{close(cmd)}; { print | cmd }' 2>/dev/null
subject=O = "CloudFlare, Inc.", OU = CloudFlare Origin CA, CN = CloudFlare Origin Certificate
notBefore=Nov 21 17:17:00 2021 GMT
notAfter=Nov 17 17:17:00 2036 GMT
X509v3 Subject Alternative Name:
    DNS:*.XXXXXXXXX.info, DNS:XXXXXXX.info
subject=C = US, O = "CloudFlare, Inc.", OU = CloudFlare Origin SSL Certificate Authority, L = San Francisco, ST = California
notBefore=Aug 23 21:08:00 2019 GMT
notAfter=Aug 15 17:00:00 2029 GMT
```


### plugins

``` shell
$ dsconf EXAMPLECOM plugin list | grep -i memberof
MemberOf Plugin

$ dsconf EXAMPLECOM plugin memberof status
Plugin 'MemberOf Plugin' is disabled

$ dsconf EXAMPLECOM plugin memberof show
dn: cn=MemberOf Plugin,cn=plugins,cn=config
cn: MemberOf Plugin
memberofattr: memberOf
memberofgroupattr: member
nsslapd-plugin-depends-on-type: database
nsslapd-pluginDescription: none
nsslapd-pluginEnabled: off
nsslapd-pluginId: none
nsslapd-pluginInitfunc: memberof_postop_init
nsslapd-pluginPath: libmemberof-plugin
nsslapd-pluginType: betxnpostoperation
nsslapd-pluginVendor: none
nsslapd-pluginVersion: none
objectClass: top
objectClass: nsSlapdPlugin
objectClass: extensibleObject

$ dsconf EXAMPLECOM plugin memberof enable

$ dsctl EXAMPLECOM restart
```


### policy: password policy

``` shell
$ dsconf EXAMPLECOM pwpolicy get | grep exp
passwordexp: off
passwordsendexpiringtime: off

$ dsconf EXAMPLECOM pwpolicy set --help | grep -P -- '^\s+--.*exp'
  --pwdexpire PWDEXPIRE
  --pwdsendexpiring PWDSENDEXPIRING
  --pwptprdelayexpireat PWPTPRDELAYEXPIREAT

$ dsconf EXAMPLECOM pwpolicy set --help | grep -PA1 -- '^\s+--pwdexpire'
  --pwdexpire PWDEXPIRE
                        Set to "on" to enable password expiration

$ dsconf EXAMPLECOM pwpolicy set --pwdexpire on
Successfully updated global password policy

$ dsconf EXAMPLECOM pwpolicy get | grep exp
passwordexp: on
passwordsendexpiringtime: off
```

Or...

``` shell
$ dsconf EXAMPLECOM pwpolicy set --pwdwarning 864000 --pwdmaxage 2592000 --pwdexpire o
```


### PAM Pass Through

Most useful in AD or Kerberos integration... In the latter, 389DS uses
*PAM Pass Through Authencation* plugin and talks to PAM for binds
authentication.

OK, I can't figure out how to make this working for a suffix..., so
modifying globally, the mapping from principal will be done via ldap
*ENTRY* and specific attribute, value of *pamIDAttr*; why? If
`use_fully_qualified_names` is used in SSSD, leftmost RDN in the bind
DN won't work... (*mail* is probably not the best attribute here but
it works for testing).

``` shell
$ ldapmodify -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-EXAMPLECOM.socket << EOF
dn: cn=PAM Pass Through Auth,cn=plugins,cn=config
changetype: modify
replace: pamIDMapMethod
pamIDMapMethod: ENTRY
-
replace: pamIDAttr
pamIDAttr: mail
-
replace: pamService
pamService: ldapserver

dn: uid=demo_user,ou=people,dc=example,dc=com
changetype: modify
replace: mail
mail: demo_user@example.com
EOF
```

``` shell
# some defaults do not need to be explicitly set
$ grep -P '(krb5|use_f)' /etc/sssd/sssd.conf
auth_provider = krb5
krb5_realm = EXAMPLE.COM
krb5_validate = false
krb5_ccachedir = /tmp
krb5_server = 127.0.0.1
krb5_ccname_template = FILE:/tmp/krb5cc_%{uid}
krb5_use_kdcinfo = false
use_fully_qualified_names
```

``` shell
$ /usr/lib/mit/sbin/kadmin.local -q 'addprinc -x dn="uid=demo_user,ou=people,dc=example,dc=com" demo_user@EXAMPLE.COM'
...
```

Here, no *userPassword*:

``` shell
$ ldapsearch -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-EXAMPLECOM.socket -b uid=demo_user,ou=people,dc=example,dc=com userPassword krbPrincipalKey
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
dn: uid=demo_user,ou=people,dc=example,dc=com
krbPrincipalKey:: MIG2oAMCAQGhAwIBAaIDAgEBowMCAQGkgZ8wgZwwVKAHMAWgAwIBAKFJMEeg
 AwIBEqFABD4gAPViraxt01bqYggst4thWryAEMHt7cKrVDCd6vOYnqunkT19Kuip/1RR4MHFfl6Az
 WfH6y4VF0zkoFXu2TBEoAcwBaADAgEAoTkwN6ADAgERoTAELhAA9JyIMCbSrCuDARwOid8CcnEW7o
 gFuzm57t27KVntGUJ7els3HUgHMp7B7qc=
```

However, the bind passes!

```
2025-04-30T15:07:51.065791+00:00 jb155sapqe01 ns-slapd: pam_unix(ldapserver:auth): authentication failure; logname= uid=177 euid=177 tty= ruser= rhost=  user=demo_user
2025-04-30T15:07:51.402648+00:00 jb155sapqe01 ns-slapd: pam_sss(ldapserver:auth): authentication success; logname= uid=177 euid=177 tty= ruser= rhost= user=demo_user
```


### user, group management

If you create an instance without sample entries, you need OU:

``` shell
$ dsidm EXAMPLECOM organizationalunit create --ou people
Successfully created people

$ dsidm EXAMPLECOM organizationalunit list
people
```

``` shell
$ dsidm EXAMPLECOM user create \
   --cn mrnobody \
   --uid mrnobody \
   --displayName 'Mr. Nobody' \
   --uidNumber 100002 \
   --gidNumber 100002 \
   --homeDirectory /home/EXAMPLECOM/mrnobody
Successfully created mrnobody

$ dsidm EXAMPLECOM user get mrnobody
dn: uid=mrnobody,ou=people,dc=example,dc=com
cn: mrnobody
displayName: Mr. Nobody
gidNumber: 100002
homeDirectory: /home/EXAMPLECOM/mrnobody
objectClass: top
objectClass: nsPerson
objectClass: nsAccount
objectClass: nsOrgPerson
objectClass: posixAccount
uid: mrnobody
uidNumber: 100002

$ dsidm EXAMPLECOM account reset_password "uid=mrnobody,ou=people,dc=example,dc=com"
Enter new password for uid=mrnobody,ou=people,dc=example,dc=com :
CONFIRM - Enter new password for uid=mrnobody,ou=people,dc=example,dc=com :

$ dsidm EXAMPLECOM user get mrnobody
dn: uid=mrnobody,ou=people,dc=example,dc=com
cn: mrnobody
displayName: Mr. Nobody
gidNumber: 100002
homeDirectory: /home/EXAMPLECOM/mrnobody
objectClass: top
objectClass: nsPerson
objectClass: nsAccount
objectClass: nsOrgPerson
objectClass: posixAccount
uid: mrnobody
uidNumber: 100002
userPassword: {PBKDF2-SHA512}10000$klQ+Mn4ELp6EB+OXKcf3GdaLAKM20fAn$PTHGTkDcDl7HVNncBbnK4yClkmgo20DnUXBmLOAiE2eJCabncwbFotLmvTjhkA5LmcE7ZGjR42/uY+KpApzl8w==

$ dsidm EXAMPLECOM account entry-status uid=mrnobody,ou=people,dc=example,dc=com
Entry DN: uid=mrnobody,ou=people,dc=example,dc=com
Entry Creation Date: 20230217141918Z (2023-02-17 14:19:18)
Entry Modification Date: 20230217142024Z (2023-02-17 14:20:24)
Entry State: activated

$ getent passwd mrnobody
mrnobody:*:100002:100002:mrnobody:/home/EXAMPLECOM/mrnobody:
```

``` shell
$ dsidm EXAMPLECOM user create \
  --uid=testovic \
  --cn="testovic" \
  --uidNumber=10000 \
  --gidNumber=10000 \
  --homeDirectory=/home/EXAMPLECOM/testovic \
  --displayName='Test Testovic'
Successfully created testovic

$ dsidm EXAMPLECOM user get testovic
dn: uid=testovic,ou=people,dc=example,dc=com
cn: testovic
displayName: Test Testovic
gidNumber: 10000
homeDirectory: /home/EXAMPLECOM/testovic
objectClass: top
objectClass: nsPerson
objectClass: nsAccount
objectClass: nsOrgPerson
objectClass: posixAccount
uid: testovic
uidNumber: 10000

$ dsidm EXAMPLECOM account reset_password "uid=testovic,ou=People,dc=example,dc=com" testovic123
reset password for uid=testovic,ou=People,dc=example,dc=com
```

``` shell
$ ldapsearch -x uid=testovic
# extended LDIF
#
# LDAPv3
# base <dc=example,dc=com> (default) with scope subtree
# filter: uid=testovic
# requesting: ALL
#

# testovic, people, example.com
dn: uid=testovic,ou=people,dc=example,dc=com
objectClass: top
objectClass: nsPerson
objectClass: nsAccount
objectClass: nsOrgPerson
objectClass: posixAccount
uid: testovic
cn: testovic
displayName: Test Testovic
uidNumber: 10000
gidNumber: 10000
homeDirectory: /home/EXAMPLECOM/testovic

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

To expire an account password:

``` shell
$ ldapmodify -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-EXAMPLECOM.socket <<EOF
dn: uid=testovic,ou=People,dc=example,dc=com
changetype: modify
replace: passwordExpirationTime
passwordExpirationTime: $(date -d now -u +"%Y%m%d%H%M%S"Z)
EOF

$ dsidm -j EXAMPLECOM user get testovic | jq -r '.attrs.passwordexpirationtime'
[
  "20250428160817Z"
]

$ ldapsearch -xLLL -W -D "uid=testovic,ou=people,dc=example,dc=com" -H ldap://127.0.0.1:3899 -b dc=example,dc=com -e ppolicy
Enter LDAP Password: 
ldap_bind: Invalid credentials (49); Password expired
        additional info: password expired!
```

Do NOT expect to see _shadow_ aging data with `getent` when using
SSSD, it is not implemented by design!

``` shell
ag -i -C 5 getspnam sssd/src/
sssd/src/sss_client/sss_nss.exports
60-             _nss_sss_getservbyport_r;
61-             _nss_sss_setservent;
62-             _nss_sss_getservent_r;
63-             _nss_sss_endservent;
64-
65:             #_nss_sss_getspnam_r;
66-             #_nss_sss_setspent;
67-             #_nss_sss_getspent_r;
68-             #_nss_sss_endspent;
69-
70-     # everything else is local
 
sssd/src/sss_client/sss_cli.h
168-    SSS_NSS_ENDSERVENT     = 0x00A5,
169-
170-#if 0
171-/* shadow */
172-
173:    SSS_NSS_GETSPNAM       = 0x00B1,
174-    SSS_NSS_GETSPUID       = 0x00B2,
175-    SSS_NSS_SETSPENT       = 0x00B3,
176-    SSS_NSS_GETSPENT       = 0x00B4,
177-    SSS_NSS_ENDSPENT       = 0x00B5,
178-#endif
--
755-                                   uint8_t **repbuf, size_t *replen,
756-                                   int *errnop);
757-
758-#if 0
759-
760:/* GETSPNAM Request:
761- *
762- * 0-X: string with name
763- *
764- * Replies:
765- *
 
sssd/src/util/sss_cli_cmd.c
156-    case SSS_NSS_ENDSERVENT:
157-        return "SSS_NSS_ENDSERVENT";
158-
159-#if 0
160-    /* shadow */
161:    case SSS_NSS_GETSPNAM:
162:        return "SSS_NSS_GETSPNAM";
163-    case SSS_NSS_GETSPUID:
164-        return "SSS_NSS_GETSPUID";
165-    case SSS_NSS_SETSPENT:
166-        return "SSS_NSS_SETSPENT";
167-    case SSS_NSS_GETSPENT:
```

``` shell
# memberof plugin enabled!

$ dsidm EXAMPLECOM group add_member demo_group uid=testovic,ou=people,dc=example,dc=com
added member: uid=testovic,ou=people,dc=example,dc=com

$ dsidm EXAMPLECOM group members demo_group
dn: uid=testovic,ou=people,dc=example,dc=com

$ dsidm EXAMPLECOM user get testovic
dn: uid=testovic,ou=people,dc=example,dc=com
cn: testovic
displayName: Test Testovic
gidNumber: 10000
homeDirectory: /home/EXAMPLECOM/testovic
memberOf: cn=demo_group,ou=groups,dc=example,dc=com
objectClass: top
objectClass: nsPerson
objectClass: nsAccount
objectClass: nsOrgPerson
objectClass: posixAccount
objectClass: nsMemberOf
uid: testovic
uidNumber: 10000
userPassword: {PBKDF2-SHA512}10000$EQa9p3SvFDtNj4VoELi2NwGQHezdMxyE$JBM84cj1kBNGPjW01QzAuv1DOUpSlkClJD9UJqdcw19wiYZ+IOMStDtRHiOnbZoGmaBYaacsrYsYxG7SwTG9Eg==

$ ldapsearch -d 0 -LLL -x uid=testovic memberOf
dn: uid=testovic,ou=people,dc=example,dc=com
memberOf: cn=demo_group,ou=groups,dc=example,dc=com
```

Now we can test SSSD `ldap_access_filter`:

``` shell
$ grep -P '^ldap_access_filter' /etc/sssd/sssd.conf
ldap_access_filter = (memberOf=cn=demo_group,ou=groups,dc=example,dc=com)

$ ldapsearch -d 0 -LLL -x '(&(memberOf=cn=demo_group,ou=groups,dc=example,dc=com)(uid=testovic))' uid
dn: uid=testovic,ou=people,dc=example,dc=com
uid: testovic
```


## Kerberos

* `<host>$@<REALM>` - user principal name (UPN) of the computer object, eg. in AD
* `<host>/<FQDN>@<REALM>` - host-based keytab entry (used by `sshd` (hardcoded), it uses so-called generic "service class")
* `<service>/<FQDN>@<REALM>` - the application uses this specific "service class"

Both client and server side must "agree" on used "service class".


### MIT Kerberos client

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


### MIT Kerberos server/kdc

#### kdc with default DB backend

SLES 15 SP6 is missing LMDB suppport, thus using default DB backend.
`/etc/sysconfig/{krb5kdc,kadmind}` can `KRB5_KDC_PROFILE` (see
`krb5.conf(5)`) defined to` override `kdc.conf` if you need to have
multiple instances (however, untested).

``` shell
# might be helpful to set a realm explicitly
$ grep -Pv '^\s*(#|$)' /etc/sysconfig/krb5kdc 
KRB5KDC_ARGS="-r EXAMPLE.COM"

$ cat /var/lib/kerberos/krb5kdc/kdc.conf
[kdcdefaults]
        kdc_ports = 750,88
 
[realms]
        EXAMPLE.COM = {
                #database_module = lmdb
                admin_keytab = FILE:/var/lib/kerberos/krb5kdc/example.com.kadm5.keytab
                acl_file = /var/lib/kerberos/krb5kdc/example.com.kadm5.acl
                dict_file = /var/lib/kerberos/krb5kdc/example.com.kadm5.dict
                key_stash_file = /var/lib/kerberos/krb5kdc/.k5.EXAMPLE.COM
                kdc_ports = 750,88
                max_life = 10h 0m 0s
                max_renewable_life = 7d 0h 0m 0s
        }
 
[dbmodules]
        EXAMPLE.COM = {
                #db_library = klmdb
                database_name = /var/lib/kerberos/krb5kdc/example.com.principal
        }
 
[logging]
        kdc = FILE:/var/log/krb5/krb5kdc.log
        admin_server = FILE:/var/log/krb5/kadmind.log
        debug = true
		
$ /usr/lib/mit/sbin/kdb5_util \
    -r EXAMPLE.COM \
	-d /var/lib/kerberos/krb5kdc/example.com.principal \
	-sf /var/lib/kerberos/krb5kdc/.k5.EXAMPLE.COM \
	create -s

$ lsof -nPp $(systemctl show -P MainPID krb5kdc.service) | grep IP
krb5kdc 2844912 root   9u     IPv4 8339974      0t0      UDP *:750 
krb5kdc 2844912 root  10u     IPv6 8339975      0t0      UDP *:750 
krb5kdc 2844912 root  11u     IPv4 8339978      0t0      UDP *:88 
krb5kdc 2844912 root  12u     IPv6 8339979      0t0      UDP *:88 
krb5kdc 2844912 root  13u     IPv4 8339982      0t0      TCP *:88 (LISTEN)
krb5kdc 2844912 root  14u     IPv6 8339983      0t0      TCP *:88 (LISTEN)

$ lsof -nPp $(systemctl show -P MainPID krb5kdc.service) | grep /var
krb5kdc 2844912 root   3w      REG   254,3     2846  1777704 /var/log/krb5/krb5kdc.log
krb5kdc 2844912 root   4w      REG   254,3     2846  1777704 /var/log/krb5/krb5kdc.log
krb5kdc 2844912 root   5u      REG   254,3        0 17830758 /var/lib/kerberos/krb5kdc/example.com.principal.ok
krb5kdc 2844912 root   6u      REG   254,3        0 17831611 /var/lib/kerberos/krb5kdc/example.com.principal.kadm5.lock

$ /usr/lib/mit/sbin/kadmin.local listprincs
K/M@EXAMPLE.COM
kadmin/admin@EXAMPLE.COM
kadmin/changepw@EXAMPLE.COM
krbtgt/EXAMPLE.COM@EXAMPLE.COM

$ file /var/lib/kerberos/krb5kdc/example.com.principal
/var/lib/kerberos/krb5kdc/example.com.principal: Berkeley DB 1.85/1.86 (Btree, version 3, native byte-order)

$ /usr/lib/mit/sbin/kdb5_util \
 -d /var/lib/kerberos/krb5kdc/example.com.principal dump - demo_user@EXAMPLE.COM | \
 tail -n -1 | tr -s '[:space:]' '\n' | head
princ
38
21
4
2
0
demo_user@EXAMPLE.COM
0
36000
604800
```


#### kdc with LDAP backend

Now, LDAP backend:

``` shell
# on SLES, krb5-plugin-kdb-ldap package required

# importing into 389-ds
$ ldapadd -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-EXAMPLECOM.socket \
  -f /usr/share/kerberos/ldap/kerberos.ldif

$ cat /var/lib/kerberos/krb5kdc/kdc.conf
[kdcdefaults]
        kdc_ports = 750,88
 
[realms]
        EXAMPLE.COM = {
                database_module = ldapconf
                admin_keytab = FILE:/var/lib/kerberos/krb5kdc/example.com.kadm5.keytab
                acl_file = /var/lib/kerberos/krb5kdc/example.com.kadm5.acl
                dict_file = /var/lib/kerberos/krb5kdc/example.com.kadm5.dict
                key_stash_file = /var/lib/kerberos/krb5kdc/.k5.EXAMPLE.COM
                kdc_ports = 750,88
                max_life = 10h 0m 0s
                max_renewable_life = 7d 0h 0m 0s
        }
 
[dbmodules]
        ldapconf = {
                db_library = kldap
                ldap_servers = ldapi://%2Frun%2Fslapd-EXAMPLECOM.socket
                ldap_kerberos_container_dn = cn=kerberos,dc=example,dc=com
                ldap_kdc_sasl_mech = EXTERNAL
                ldap_kadmind_sasl_mech = EXTERNAL
        }
 
[logging]
        kdc = FILE:/var/log/krb5/krb5kdc.log
        admin_server = FILE:/var/log/krb5/kadmind.log
        debug = true

$ /usr/lib/mit/sbin/kdb5_ldap_util \
  -H ldapi://%2Frun%2Fslapd-EXAMPLECOM.socket \
  -r EXAMPLE.COM create \
  -subtrees dc=example,dc=com \
  -s \
  -sf /var/lib/kerberos/krb5kdc/.k5.EXAMPLE.COM
Initializing database for realm 'EXAMPLE.COM'
You will be prompted for the database Master Password.
It is important that you NOT FORGET this password.
Enter KDC database master key: 
Re-enter KDC database master key to verify:

$ ldapsearch -LLL -Y EXTERNAL \
  -H ldapi://%2Frun%2Fslapd-EXAMPLECOM.socket \
  -b cn=kerberos,dc=example,dc=com dn
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
dn: cn=kerberos,dc=example,dc=com
 
dn: cn=EXAMPLE.COM,cn=kerberos,dc=example,dc=com
 
dn: krbprincipalname=K/M@EXAMPLE.COM,cn=EXAMPLE.COM,cn=kerberos,dc=example,dc=
 com
 
dn: krbprincipalname=krbtgt/EXAMPLE.COM@EXAMPLE.COM,cn=EXAMPLE.COM,cn=kerberos
 ,dc=example,dc=com
 
dn: krbprincipalname=kadmin/admin@EXAMPLE.COM,cn=EXAMPLE.COM,cn=kerberos,dc=ex
 ample,dc=com
 
dn: krbprincipalname=kadmin/changepw@EXAMPLE.COM,cn=EXAMPLE.COM,cn=kerberos,dc
 =example,dc=com
 
dn: krbprincipalname=kadmin/history@EXAMPLE.COM,cn=EXAMPLE.COM,cn=kerberos,dc=
 example,dc=com
 
dn: krbprincipalname=demo_user@EXAMPLE.COM,cn=EXAMPLE.COM,cn=kerberos,dc=examp
 le,dc=com
```

Most likely one would like to have one "password", that is, not to
have one password for principal key and one as `userPassword`. See, in
389 DS part about *PAM Pass Through Authentication*'


#### kdc principals mgmt

``` shell
$ getent passwd demo_user@ldap
demo_user:*:99998:99998:Demo User:/var/empty:/bin/false

$ /usr/lib/mit/sbin/kadmin.local -q "addprinc demo_user"
Authenticating as principal Administrator/admin@EXAMPLE.NET with password.
No policy specified for demo_user@EXAMPLE.COM; defaulting to no policy
Enter password for principal "demo_user@EXAMPLE.COM": 
Re-enter password for principal "demo_user@EXAMPLE.COM": 
Principal "demo_user@EXAMPLE.COM" created.

$ su - demo_user@ldap

demo_user@jb155sapqe01:~> kinit -V
Using default cache: /tmp/krb5cc_99998
Using principal: demo_user@EXAMPLE.COM
Password for demo_user@EXAMPLE.COM: 
Authenticated to Kerberos v5

demo_user@jb155sapqe01:~> klist -efA
Ticket cache: FILE:/tmp/krb5cc_99998
Default principal: demo_user@EXAMPLE.COM
 
Valid starting       Expires              Service principal
04/30/2025 10:14:49  04/30/2025 20:14:49  krbtgt/EXAMPLE.COM@EXAMPLE.COM
        renew until 05/07/2025 10:14:49, Flags: FRI
        Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96 
```


### Kerberos-sshd intergration

When using kerberos with `sshd` on a machine conntected to AD/Samba/Winbind,
`yast samba-client` should take care of *ALMOST* all settings but there's a need
to *fix* `/etc/krb5.conf`; because a user uses *DOMAIN\username* when
authenticating to SSH daemon, but *kerberos* does not know anything about
*DOMAIN\\* part, thus there's need to strip it via `auth_to_local`.

``` shell
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
```

Modified krb5.conf, see comments inline

``` shell
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
```

What does the manpage says?

``` shell
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


### troubleshooting

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


### MIT Kerberos server passthrough authentication

MIT KRB5 supports "passthrough authentication", that is, KDC (Kerberos
Key Distribution Center) delegates password verification to an
external store.

MIT KRB5 supports PKINIT (Public Key Cryptography for Initial
Authentication), this enabled to authenticate users based on their
X.509 certificates instead of a traditional password.

*WARNING*: untested!!!

```
# PKINIT server example
[realms]
EXAMPLE.COM = {
    ...
    pkinit_anchors = FILE:/etc/krb5kdc/ca.crt
    pkinit_identity = FILE:/etc/krb5kdc/kdc.crt,/etc/krb5kdc/kdc.key
    pkinit_indicator = TLS-Client-Auth
}
```

```
# PKINIT client example
[libdefaults]
    default_realm = EXAMPLE.COM
    pkinit_identities = FILE:/etc/krb5/user.crt,/etc/krb5/user.key
```

``` shell
$ kinit -X X509_user_identity=FILE:/etc/krb5/user.crt,/etc/krb5/user.key user@EXAMPLE.COM
```

This way, the KDC validates the user's certificate and issues a TGT.


## OpenLDAP

Terminology:

- LDAP: lightweight directory access protocol
- directory information tree (DIT): hierarchical tree structure of LDAP
- root: top of the directory hierarchy
- distinguished name (DN): complete path to any node, unique identifier of an object
- entry or object: one unit in an LDAP directory, qualified by its
  distinguished name (DN)
- organizational unit (OU): an organizational boundarry, geographical
  or functional (eg. country, department,...)
- bind or binding: connection process to an LDAP server
- attributes: pieces of information associated with an entry
  (eg. employee's phone number)
- objectclass: special attribute type, like in OOP, a class defining
  which attributes are required for an object; each object _must_ have
  objectclass
- schema: schema determining the structure and contents of the
  directory; contains objectclass definitions, attribute types
  definitions etc.
- LDIF: LDAP Data Interchange Format, plain-text file for LDAP
  entries, used for importing and exporting data to and form an LDAP
  server

### OpenLDAP server

OSes or distroes vary how they handle OpenLDAP, here "mostly" SLES
related info.

Since OpenLDAP 2.3 there's a _Configuration Backend (cn=config)_, it's
also called _online configuration_ or _dynamic configuration_.

``` shell
$ grep -P '^[\w_]+="[^"]+"' /etc/sysconfig/openldap 
OPENLDAP_START_LDAP="yes"
OPENLDAP_START_LDAPS="no"
OPENLDAP_START_LDAPI="yes"
OPENLDAP_USER="ldap"
OPENLDAP_GROUP="ldap"
OPENLDAP_CHOWN_DIRS="yes"
OPENLDAP_REGISTER_SLP="no"
OPENLDAP_CONFIG_BACKEND="ldap"
OPENLDAP_MEMORY_LIMIT="yes"
```

OpenLDAP 2.5 [Quick-Start
Guide](https://www.openldap.org/doc/admin25/quickstart.html) says to
start with `slapd.ldif`; however, there are some things that need to
be modified:

``` shell
$ sed \
  -e 's|%LOCALSTATEDIR%|/tmp|;s|/run||;s|%MODULEDIR%|/usr/lib64/openldap|'\
  -e '/#dn: cn=module,cn=config/,+4 s/^#//' \
  -e '/^olcModuleload:/a\olcModuleload: pw-sha2.la' \
  -e 's|%SYSCONFDIR%|/etc/openldap|;s|openldap-data|slapd.d|' \
  -e '/olcDbMaxSize/d' \
  /usr/share/doc/packages/openldap2/slapd.ldif.default | \
  grep -Pv '^\s*#' | sed '/^$/N;/^\n$/D' | tee /tmp/input
dn: cn=config
objectClass: olcGlobal
cn: config
olcArgsFile: /tmp/slapd.args
olcPidFile: /tmp/slapd.pid

dn: cn=module,cn=config
objectClass: olcModuleList
cn: module
olcModulepath:  /usr/lib64/openldap
olcModuleload:  back_mdb.la
olcModuleload: pw-sha2.la

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

include: file:///etc/openldap/schema/core.ldif

dn: olcDatabase=frontend,cn=config
objectClass: olcDatabaseConfig
objectClass: olcFrontendConfig
olcDatabase: frontend

dn: olcDatabase=mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: mdb
olcSuffix: dc=my-domain,dc=com
olcRootDN: cn=Manager,dc=my-domain,dc=com
olcRootPW: secret
olcDbDirectory: /tmp/slapd.d
olcDbIndex: objectClass eq

dn: olcDatabase=monitor,cn=config
objectClass: olcDatabaseConfig
olcDatabase: monitor
olcRootDN: cn=config
olcMonitoring: FALSE
```

``` shell
$ slapadd -n 0 -F /tmp/slapd.d/ -l /tmp/input  -v
added: "cn=config" (00000001)
added: "cn=module{0},cn=config" (00000001)
added: "cn=schema,cn=config" (00000001)
added: "cn={0}core,cn=schema,cn=config" (00000001)
added: "olcDatabase={-1}frontend,cn=config" (00000001)
added: "olcDatabase={1}mdb,cn=config" (00000001)
added: "olcDatabase={2}monitor,cn=config" (00000001)
Closing DB...
```

If you want to add ACL for the local root user, then modify input LDIF:

```
dn: olcDatabase=config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: config
olcAccess: {0}to * by dn.exact=gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth manage by * break
```

Let's try `olcPasswordHash`, used in `pw-sha2` module:

``` shell
$ cat > /tmp/in <<EOF
dn: olcDatabase={-1}frontend,cn=config
changetype: modify
replace: olcPasswordHash
olcPasswordHash: {SSHA512}
olcPasswordHash: {SSHA}
EOF

$ slapmodify -F /tmp/slapd.d/ -l /tmp/in -b cn=config -v
modify: "olcDatabase={-1}frontend,cn=config" (00000001)
Closing DB...
```

Another way is to exploit `slapd.conf` (on SLES `slapd.conf.olctemplate`):

``` shell
$ sed \
  -e 's|%LOCALSTATEDIR%|/var|;s|%MODULEDIR%|/usr/lib64/openldap|' \
  -e 's|%SYSCONFDIR%|/etc/openldap|;s|/openldap-data|/lib/ldap|' \
  -e 's|^# module|module|;s|back_bdb|back_mdb|' \
  -e '/^moduleload.*back_mdb/a\moduleload pw-sha2.la' \
  -e '/back_ldap/d' ./servers/slapd/slapd.conf | \
  grep -Pv '^\s*#' | sed '/^$/N;/^\n$/D' | tee /tmp/input

include         /etc/openldap/schema/core.schema

pidfile         /var/run/slapd.pid
argsfile        /var/run/slapd.args

modulepath      /usr/lib64/openldap
moduleload      back_mdb.la
moduleload pw-sha2.la

database config

database        mdb
maxsize         1073741824
suffix          "dc=my-domain,dc=com"
rootdn          "cn=Manager,dc=my-domain,dc=com"
rootpw          secret
directory       /var/lib/ldap
index   objectClass     eq

database monitor
```

``` shell
$ slaptest -f /tmp/input -v -F /tmp/slapd.d/
config file testing succeeded

# same pw-sha2.so modification as above
$ slapmodify -F /tmp/slapd.d/ -l /tmp/in -b cn=config -v
modify: "olcDatabase={-1}frontend,cn=config" (00000001)
Closing DB...
```

NOTE: order is crucial - schemas, DBs, overlays!

A "schema" is built-in in
[`servers/slapd/bconfig.c`](https://github.com/openldap/openldap/blob/fc34ad5dc8402a4f0c76f5acff64d5e91b69602b/servers/slapd/bconfig.c#L1039);
when using `slaptest` to convert from `slapd.conf` to LDIF based
configuration, this schema is inserted into the final LDIF:

``` shell
$ slaptest -f /etc/openldap/slapd.conf.olctemplate -F /tmp/newtest
config file testing succeeded

$ slapcat -F /tmp/newtest -n0 | grep -A 5 'dn: cn=schema,cn=config'
dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema
olcObjectIdentifier: OLcfg 1.3.6.1.4.1.4203.1.12.2
olcObjectIdentifier: OLcfgAt OLcfg:3
olcObjectIdentifier: OLcfgGlAt OLcfgAt:0
```

This I haven't seen happen if one builds the configuration from a LDIF
file.

It is also possible to hash the password instead of using one in
plain-text:

``` shell
$ slappasswd -o module-path=/usr/lib64/openldap -o module-load=pw-sha2.so -h '{SSHA512}'
New password: 
Re-enter new password: 
{SSHA512}lJAE6VzkKWCaTV99hRuJQt9HyvoYJ8Gxrwhi/E9NSrhSxuS/KHpeS4HvrhcZfM6L0rCkblQPU4colX7yAKyC6yd
```

For log levels see https://www.openldap.org/doc/admin24/slapdconfig.html.

``` shell
$ ss -tnlp | grep slapd | col -b | sed -r 's/[[:blank:]]+/ /g'
LISTEN 0 128 0.0.0.0:636 0.0.0.0:* users:(("slapd",pid=4936,fd=7))
LISTEN 0 128 [::]:636 [::]:* users:(("slapd",pid=4936,fd=8))
```

`slapd` ACLs are first match win, so the most specific ACL must have
priority!  See
https://www.openldap.org/doc/admin24/access-control.html#Access%20Control%20Common%20Examples.

See [OpenLDAP Quick-Start
Guide](https://www.openldap.org/doc/admin25/quickstart.html) for
details.

An example of changing `slapd` configuration with _online_
(`OPENLDAP_CONFIG_BACKEND="ldap"`) configuration:

``` shell
$ cat tls.in
dn: cn=config
changetype: modify
replace: olcTLSDHParamFile
olcTLSDHParamFile: /etc/ssl/private/slapd.dh.params

dn: cn=config
changetype: modify
replace: olcTLSProtocolMin
olcTLSProtocolMin: 3.3
```

``` shell
$  ldapmodify -a -Q -Y EXTERNAL -H ldapi:/// -f tls.in

$  ldapsearch -LLL -Y EXTERNAL -H ldapi:/// -b cn=config | grep -P '^olcTLS(ProtocolMin|DHParamFile)'
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
olcTLSDHParamFile: /etc/ssl/private/slapd.dh.params
olcTLSProtocolMin: 3.3
```


### OpenLDAP tools

OpenLDAP utils use `/etc/openldap/ldap.conf` configuration, see `ldap.conf(5)`.

``` shell
$ ldapsearch -d 0 -v -x -y /root/.ldappw -D 'cn=Manager,dc=example,dc=com'
ldap_initialize( <DEFAULT> )
filter: (objectclass=*)
requesting: All userApplication attributes
# extended LDIF
#
# LDAPv3
# base <dc=example,dc=com> (default) with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 32 No such object

# numResponses: 1
```

bind failure would look like this:

``` shell
$ ldapsearch -d 0 -v -x -w badpass -D 'cn=Manager,dc=example,dc=com' -b 'dc=example,dc=com'
ldap_initialize( <DEFAULT> )
ldap_bind: Invalid credentials (49)
```

A TLS issue could look like this, here it is SAN problem:

``` shell
$ ldapsearch -d 1 -v -x -y /root/.ldappw -D 'cn=Manager,dc=example,dc=com' -b 'dc=example,dc=com'
ldap_initialize( <DEFAULT> )
ldap_create
ldap_sasl_bind
ldap_send_initial_request
ldap_new_connection 1 1 0
ldap_int_open_connection
ldap_connect_to_host: TCP t14s:636
ldap_new_socket: 3
ldap_prepare_socket: 3
ldap_connect_to_host: Trying 192.168.1.4:636
ldap_pvt_connect: fd: 3 tm: -1 async: 0
attempting to connect:
connect success
TLS trace: SSL_connect:before SSL initialization
TLS trace: SSL_connect:SSLv3/TLS write client hello
TLS trace: SSL_connect:SSLv3/TLS write client hello
TLS trace: SSL_connect:SSLv3/TLS read server hello
TLS trace: SSL_connect:TLSv1.3 read encrypted extensions
TLS certificate verification: depth: 0, err: 0, subject: /CN=t14s, issuer: /CN=t14s
TLS trace: SSL_connect:SSLv3/TLS read server certificate
TLS trace: SSL_connect:TLSv1.3 read server certificate verify
TLS trace: SSL_connect:SSLv3/TLS read finished
TLS trace: SSL_connect:SSLv3/TLS write change cipher spec
TLS trace: SSL_connect:SSLv3/TLS write finished
TLS: unable to get subjectAltName from peer certificate.
TLS: can't connect: TLS: unable to get subjectAltName from peer certificate.
ldap_err2string
ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)
```

Incorrectly created TLS key:

``` shell
$ openssl x509 -text -noout -in /etc/openldap/certs/server.pem \
    -certopt no_subject,no_header,no_version,no_serial,no_signame,no_validity,no_issuer,no_pubkey,no_sigdump,no_aux
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                D1:78:F4:21:D3:98:17:84:49:5D:D2:EF:2E:82:7E:DC:AD:98:C8:8C
            X509v3 Authority Key Identifier:
                keyid:D1:78:F4:21:D3:98:17:84:49:5D:D2:EF:2E:82:7E:DC:AD:98:C8:8C

            X509v3 Basic Constraints: critical
                CA:TRUE
```

Offtopic here but anyway, a comparison with defined SAN:

``` shell
$ : | openssl s_client -showcerts -connect www.openbsd.org:443 2>/dev/null | \
    openssl x509 -inform pem -noout -text | grep -B 1 DNS: | fmt -w80
            X509v3 Subject Alternative Name:
                DNS:ftplist1.openbsd.org, DNS:libressl.org, DNS:openbsd.org,
                DNS:openiked.org, DNS:openssh.com, DNS:rpki-client.org,
                DNS:www.libressl.org, DNS:www.openbsd.org,
                DNS:www.openiked.org, DNS:www.openrsync.org,
                DNS:www.openssh.com, DNS:www.rpki-client.org
```

Let's try to add first entry:

``` shell
$ grep -P '^objectclass.*(dcObject|organization(alRole)?)' /etc/openldap/schema/*.schema
/etc/openldap/schema/core.schema:objectclass ( 2.5.6.4 NAME 'organization'
/etc/openldap/schema/core.schema:objectclass ( 2.5.6.5 NAME 'organizationalUnit'
/etc/openldap/schema/core.schema:objectclass ( 2.5.6.7 NAME 'organizationalPerson'
/etc/openldap/schema/core.schema:objectclass ( 2.5.6.8 NAME 'organizationalRole'
/etc/openldap/schema/core.schema:objectclass ( 1.3.6.1.4.1.1466.344 NAME 'dcObject'
```

Huh? Let's try to see some more details:

``` shell
$ sed -rn '/objectclass.*(dcObject|organization(alRole)?)/,/^ *$/p' /etc/openldap/schema/*.schema
objectclass ( 2.5.6.4 NAME 'organization'
        DESC 'RFC2256: an organization'
        SUP top STRUCTURAL
        MUST o
        MAY ( userPassword $ searchGuide $ seeAlso $ businessCategory $
                x121Address $ registeredAddress $ destinationIndicator $
                preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $
                telephoneNumber $ internationalISDNNumber $
                facsimileTelephoneNumber $ street $ postOfficeBox $ postalCode $
                postalAddress $ physicalDeliveryOfficeName $ st $ l $ description ) )

objectclass ( 2.5.6.5 NAME 'organizationalUnit'
        DESC 'RFC2256: an organizational unit'
        SUP top STRUCTURAL
        MUST ou
        MAY ( userPassword $ searchGuide $ seeAlso $ businessCategory $
                x121Address $ registeredAddress $ destinationIndicator $
                preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $
                telephoneNumber $ internationalISDNNumber $
                facsimileTelephoneNumber $ street $ postOfficeBox $ postalCode $
                postalAddress $ physicalDeliveryOfficeName $ st $ l $ description ) )

objectclass ( 2.5.6.7 NAME 'organizationalPerson'
        DESC 'RFC2256: an organizational person'
        SUP person STRUCTURAL
        MAY ( title $ x121Address $ registeredAddress $ destinationIndicator $
                preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $
                telephoneNumber $ internationalISDNNumber $
                facsimileTelephoneNumber $ street $ postOfficeBox $ postalCode $
                postalAddress $ physicalDeliveryOfficeName $ ou $ st $ l ) )

objectclass ( 2.5.6.8 NAME 'organizationalRole'
        DESC 'RFC2256: an organizational role'
        SUP top STRUCTURAL
        MUST cn
        MAY ( x121Address $ registeredAddress $ destinationIndicator $
                preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $
                telephoneNumber $ internationalISDNNumber $ facsimileTelephoneNumber $
                seeAlso $ roleOccupant $ preferredDeliveryMethod $ street $
                postOfficeBox $ postalCode $ postalAddress $
                physicalDeliveryOfficeName $ ou $ st $ l $ description ) )

objectclass ( 1.3.6.1.4.1.1466.344 NAME 'dcObject'
        DESC 'RFC2247: domain component object'
        SUP top AUXILIARY MUST dc )
```

A LDIF example:

``` shell
$ cat > /tmp/input.ldif <<EOF
# organization object
dn: dc=example,dc=com
objectclass: dcObject
objectclass: organization
o: Example inc.
dc: example

# a user
dn: cn=testuser, dc=example, dc=com
objectclass: organizationalRole
cn: testuser
EOF
```

``` shell
$ ldapadd -d 0 -v -x -y /root/.ldappw -D 'cn=Manager,dc=example,dc=com' -f /tmp/input.ldif
ldap_initialize( <DEFAULT> )
add objectclass:
        dcObject
        organization
add o:
        Example inc.
add dc:
        example
adding new entry "dc=example,dc=com"
modify complete

add objectclass:
        organizationalRole
add cn:
        testuser
adding new entry "cn=testuser, dc=example, dc=com"
modify complete
```

``` shell
$ ldapsearch -LLL -x -y /root/.ldappw -D 'cn=Manager,dc=example,dc=com' -b 'dc=example,dc=com' '(cn=testuser)'
dn: cn=testuser,dc=example,dc=com
objectClass: organizationalRole
cn: testuser
```

Delete of an object:

``` shell
$ ldapdelete -v -x -y /root/.ldappw -D 'cn=Manager,dc=example,dc=com' 'cn=testuser, dc=example, dc=com'
ldap_initialize( <DEFAULT> )
deleting entry "cn=testuser, dc=example, dc=com"
```

The above user examle was not very usual, thus let's add new one:

``` shell
$ cat input.ldif
dn: ou=people, dc=example, dc=com
ou: people
objectClass: organizationalUnit

dn: uid=u123456, ou=people, dc=example, dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: u123456
cn: Joe Dirt
sn: Dirt
loginShell: /bin/bash
uidNumber: 10000
gidNumber: 10000
homeDirectory: /home/u123456
employeeNumber: 123456
employeeType: full-time
mobile: +420777111222

$ ldapadd -x -y /root/.ldappw -D 'cn=Manager,dc=example,dc=com' -f input.ldif
adding new entry "ou=people, dc=example, dc=com"

adding new entry "uid=u123456, ou=people, dc=example, dc=com"
```

Now, let's set users password:

``` shell
$ ldappasswd -x -y /root/.ldappw -D 'cn=Manager,dc=example,dc=com' -S 'uid=u123456, ou=people, dc=example, dc=com'                                                                                                           New
 password:
Re-enter new password:

$ ldapsearch -LLL -x -y /root/.ldappw -D 'cn=Manager,dc=example,dc=com' -b 'ou=people, dc=example,dc=com' '(uid=u123456)' userPassword
dn: uid=u123456,ou=people,dc=example,dc=com
userPassword:: e1NTSEF9WGlzS3E5OWtmaG9UdHM0V2hRUmR5VkxHTk1uQzlQdis=
```

Modifying password via `ldapmodify`:

``` shell
$ slappasswd -n | base64 -
New password:
Re-enter new password:
e1NTSEF9aFNyTy95bWpWZUhzUDRlUnplK1dmM3VjSlJmZ1d5OXQ=

$ cat input.ldif
dn: uid=u123456, ou=people, dc=example, dc=com
changetype: modify
replace: userPassword
userPassword:: e1NTSEF9aFNyTy95bWpWZUhzUDRlUnplK1dmM3VjSlJmZ1d5OXQ=

$ ldapmodify -v -x -y /root/.ldappw -D 'cn=Manager,dc=example,dc=com' -f input.ldif
ldap_initialize( <DEFAULT> )
replace userPassword:
        {SSHA}hSrO/ymjVeHsP4eRze+Wf3ucJRfgWy9t
modifying entry "uid=u123456, ou=people, dc=example, dc=com"
modify complete

$ ldapsearch -LLL -x -y /root/.ldappw -D 'cn=Manager,dc=example,dc=com' -b 'ou=people, dc=example,dc=com' '(uid=u123456)' userPassword
dn: uid=u123456,ou=people,dc=example,dc=com
userPassword:: e1NTSEF9aFNyTy95bWpWZUhzUDRlUnplK1dmM3VjSlJmZ1d5OXQ=

# and test
$ ldapsearch -LLL -x -W -D 'uid=u123456,ou=people,dc=example,dc=com' \
    -b 'ou=people,dc=example,dc=com' '(uid=u123456)' dn
Enter LDAP Password:
dn: uid=u123456,ou=people,dc=example,dc=com
```

We can use `slapcat` to convert current directory database to LDIF:

``` shell
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

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people
structuralObjectClass: organizationalUnit
entryUUID: 7e4e96d0-e33d-103c-8b12-df684872bf89
creatorsName: cn=Manager,dc=example,dc=com
createTimestamp: 20221018143252Z
entryCSN: 20221018143252.922917Z#000000#000#000000
modifiersName: cn=Manager,dc=example,dc=com
modifyTimestamp: 20221018143252Z

dn: cn=Gerald W. Carter,ou=people,dc=example,dc=com
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
entryCSN: 20221018151429.080994Z#000000#000#000000
modifiersName: cn=Manager,dc=example,dc=com
modifyTimestamp: 20221018151429Z
```

``` shell
# via sss NSS
getent passwd gwcarter
$ getent passwd gwcarter
gwcarter:*:1010:1010:Gerald W. Carter:/home/gwcarter:/bin/bash
```
