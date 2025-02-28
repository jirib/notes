# My cheatsheet

## acl

- *mask* is maximum permission for users (other than the owner) and groups!
- `chmod` incluences mask of ACL file/dir!
- default ACL of a directory for inheritance


## applications


### bugzilla

For bugzilla reports in CSV, just add `&ctype=csv` in the URL.


## authentication

### 389ds

One can create 389 DS instance via:

- a custom config file
- from a template

But basically `dscreate create-template` just generate a default
config file, so there's not really a difference which mode you would
use!

#### 389ds creation from a custome config file

``` shell
$ cat > ${XDG_RUNTIME_DIR}/389ds.inf <<-EOF
> [general]
> full_machine_name = jb154sapqe01.example.com
> start = False
> strict_host_checking = False
> [slapd]
> instance_name = EXAMPLECOM
> port = 389
> root_password = <password>
> self_sign_cert = False
> [backend-userroot]
> create_suffix_entry = True
> sample_entries = yes
> suffix = dc=example,dc=com
> EOF

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

$ ss -tnlp | grep $(systemctl show -p MainPID --value dirsrv@EXAMPLECOM.service)
LISTEN 0      128                *:389              *:*    users:(("ns-slapd",pid=17406,fd=7))
```


#### default .dsrc for sysadmins

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


#### 389ds management

- `dsconf`
- `dsctl`


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


#### external TLS in 389ds

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


#### plugins

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


#### user, group management

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


##### sshd

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


#### krb5 server

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


### openldap

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

#### server

OSes or distroes vary how they handle OpenLDAP, here SLES related info.

SLES makes it a little bit complicated:

``` shell
$ grep -Pv '^\s*($|#)' /etc/sysconfig/openldap
OPENLDAP_START_LDAP="no"
OPENLDAP_START_LDAPS="yes"
OPENLDAP_START_LDAPI="yes"
OPENLDAP_SLAPD_PARAMS=""
OPENLDAP_USER="ldap"
OPENLDAP_GROUP="ldap"
OPENLDAP_CHOWN_DIRS="yes"
OPENLDAP_LDAP_INTERFACES=""
OPENLDAP_LDAPS_INTERFACES=""
OPENLDAP_LDAPI_INTERFACES=""
OPENLDAP_REGISTER_SLP="no"
OPENLDAP_KRB5_KEYTAB=""
OPENLDAP_CONFIG_BACKEND="files"
OPENLDAP_MEMORY_LIMIT="yes"
```

Check what is default `slapd.conf`:

``` shell
$ grep -Pv '^\s*($|#)' /etc/openldap/slapd.conf
```

First we need a password, OpenLDAP rootpw:

``` shell
$ install -m 600 /dev/null /root/.ldappw
$ vi /root/.ldappw

$ slappasswd -T /root/.ldappw
{SSHA}iqKe4WidL7RnQsIKjRMsfOhaKcXv2wNs
```

Then, an example configuration to start with:

``` shell
$ cat /etc/openldap/slapd.conf
loglevel        492
pidfile         /run/slapd/slapd.pid
argsfile        /run/slapd/slapd.args
include /etc/openldap/schema/core.schema
include /etc/openldap/schema/cosine.schema
include /etc/openldap/schema/inetorgperson.schema
include /etc/openldap/schema/rfc2307bis.schema
include /etc/openldap/schema/yast.schema
include /usr/share/doc/packages/samba/examples/LDAP/samba.schema
modulepath /usr/lib64/openldap
moduleload back_mdb.la
access to dn.base=""
        by * read
access to dn.base="cn=Subschema"
        by * read
access to attrs=userPassword,userPKCS12
        by self write
        by * auth
access to attrs=shadowLastChange
        by self write
        by * read
access to *
        by * read
TLSProtocolMin 3.3
TLSCipherSuite HIGH+TLSv1.2+kECDHE+aECDSA!AES!SHA384!SHA256
TLSCACertificateFile /etc/openldap/example.com.crt
TLSCertificateFile /etc/openldap/example.com.crt
TLSCertificateKeyFile /etc/openldap/example.com.key
disallow bind_anon
require authc
database     mdb
suffix       "dc=example,dc=com"
rootdn       "cn=Manager,dc=example,dc=com"
rootpw       {SSHA}r+sjFrnEg2okiTc0WzWHsN1oUm6bZ9Ha
directory    /var/lib/ldap
index        objectClass eq
lastmod      on
```

NOTE: If `slapd` fails to start and it seems to be related to TLS,
check permissions!

For log levels see https://www.openldap.org/doc/admin24/slapdconfig.html.

``` shell
$ ss -tnlp | grep slapd | col -b | sed -r 's/[[:blank:]]+/ /g'
LISTEN 0 128 0.0.0.0:636 0.0.0.0:* users:(("slapd",pid=4936,fd=7))
LISTEN 0 128 [::]:636 [::]:* users:(("slapd",pid=4936,fd=8))
```

`slapd` ACLs are first match win, so the most specific ACL must have
priority!  See
https://www.openldap.org/doc/admin24/access-control.html#Access%20Control%20Common%20Examples.


#### online configuration

Since OpenLDAP 2.3 there's a _Configuration Backend (cn=config)_, it's
also called _online configuration_ or _dynamic configuration_.

On SLES, check `/etc/openldap/slapd.conf.olctemplate`, this is way to
migrate from `slapd.conf` to _olc_.

``` shell
$ grep -Pv '^\s*(#|$)' /etc/sysconfig/openldap
OPENLDAP_START_LDAP="yes"
OPENLDAP_START_LDAPS="yes"
OPENLDAP_START_LDAPI="yes"
OPENLDAP_SLAPD_PARAMS=""
OPENLDAP_USER="ldap"
OPENLDAP_GROUP="ldap"
OPENLDAP_CHOWN_DIRS="yes"
OPENLDAP_LDAP_INTERFACES=":2389"
OPENLDAP_LDAPS_INTERFACES=":2636"
OPENLDAP_LDAPI_INTERFACES=""
OPENLDAP_REGISTER_SLP="no"
OPENLDAP_KRB5_KEYTAB=""
OPENLDAP_CONFIG_BACKEND="ldap"
OPENLDAP_MEMORY_LIMIT="yes"
```

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


#### OpenLDAP tools

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


### sssd


#### LDAP

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

#### troubleshooting

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


### sudo

WARNING: Wildcares, take care, see [Dangerous Sudoers Entries – PART
4:
Wildcards](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-4-wildcards/).


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

Use `BORG_PASSCOMMAND` variable with literal command how to get the
password, instead of `BORG_PASSHRASE`, as the latter might leak in the
logs.


### rear

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

## boot loaders

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


## cloud


### azure

``` shell
$ az login
```

``` shell
$ cat ~/.azure/config
[cloud]
name = AzureCloud

[defaults]
group = <resource group>
location = germanywestcentral
vm = <vmprefix>

[storage]
account = <account name>
```

``` shell
$ az vm image list --offer sles-15-sp3-byos --all | jq '.[-1]'
{
  "offer": "sles-15-sp3-byos",
  "publisher": "SUSE",
  "sku": "gen2",
  "urn": "SUSE:sles-15-sp3-byos:gen2:2022.05.05",
  "version": "2022.05.05"
}
```

``` shell
$ az sshkey create --public-key "$(ssh-add -L | grep ssh-rsa)" --name <key name>
```

``` shell
$ az vm create --name <vm name> --image SUSE:sles-15-sp3-byos:gen2:2022.05.05 \
    --ssh-key-name <key name> --boot-diagnostics-storage csjbelka --eviction-policy Delete --nic-delete-option Delete --os-disk-delete-option Delete --admin-username sysadmin1

```

``` shell
$ az vm show --name <vm name>  | \
    jq -r '.osProfile | .linuxConfiguration.ssh.publicKeys[].path'
/home/jiri/.ssh/authorized_keys
```

``` shell
$ az vm list-ip-addresses -n csjbelka01 | grep ipAddress # for public IP
```

### tools

#### cloud-init

How to make "scripts" to run during every boot? See
https://stackoverflow.com/questions/6475374/how-do-i-make-cloud-init-startup-scripts-run-every-time-my-ec2-instance-boots.


`cloud-init devel net-convert` might be helpful to see what final
configuration would be from cloud-init instance data (well, there
'route' is missing for some unknown reason):

``` shell
$ cat ~/metadata.yaml
instance-id: cloud-vm
local-hostname: cloud-vm
network:
  version: 2
  ethernets:
    eth0:
      match:
        macaddress: '00:0c:29:21:f1:61'
      dhcp4: false
      addresses:
        - 172.16.171.139/24
      nameservers:
        addresses: [172.16.171.254]
      routes:
        - to: 0.0.0.0/0
          via: 172.16.171.254

$ cloud-init devel net-convert \
    -m eth0,00:0c:29:21:f1:61 \
    --network-data ~/metadata.yaml \
    --kind yaml \
    --output-kind sysconfig \
    -D sles -d ./
Read input format 'yaml' from '/root/metadata.yaml'.
Wrote output format 'sysconfig' to './'

$ find ./etc/
./etc/
./etc/resolv.conf
./etc/NetworkManager
./etc/NetworkManager/conf.d
./etc/NetworkManager/conf.d/99-cloud-init.conf
./etc/udev
./etc/udev/rules.d
./etc/udev/rules.d/85-persistent-net-cloud-init.rules
./etc/sysconfig
./etc/sysconfig/network
./etc/sysconfig/network/ifcfg-eth0

$ cat ./etc/sysconfig/network/ifcfg-eth0
# Created by cloud-init on instance boot automatically, do not edit.
#
BOOTPROTO=static
IPADDR=172.16.171.139
LLADDR=00:0c:29:21:f1:61
NETMASK=255.255.255.0
STARTMODE=auto
```

Pushing _cloud-init_ data to VMware:

``` shell
$ grep -H '' metadata.yaml userdata.yaml
metadata.yaml:instance-id: cloud-vm
metadata.yaml:local-hostname: cloud-vm
metadata.yaml:network:
metadata.yaml:  version: 2
metadata.yaml:  ethernets:
metadata.yaml:    eth0:
metadata.yaml:      match:
metadata.yaml:        macaddress: '00:0c:29:21:f1:61'
metadata.yaml:      dhcp4: false
metadata.yaml:      addresses:
metadata.yaml:        - 172.16.171.139/24
metadata.yaml:      nameservers:
metadata.yaml:        addresses: [172.16.171.254]
metadata.yaml:      routes:
metadata.yaml:        - to: 0.0.0.0/0
metadata.yaml:          via: 172.16.171.254
userdata.yaml:#cloud-config
userdata.yaml:
userdata.yaml:users:
userdata.yaml:  - default

$ export METADATA=$(gzip -c9 <metadata.yaml | { base64 -w0 2>/dev/null || base64; }) \
    USERDATA=$(gzip -c9 <userdata.yaml | { base64 -w0 2>/dev/null || base64; })

$ printenv | grep GOVC | sed 's/=.*/=******/'
GOVC_PASSWORD=******
GOVC_URL=******
GOVC_USERNAME=******
GOVC_INSECURE=******

$ export VM=/ha-datacenter/vm/test01
$ govc vm.change -vm "${VM}" -e guestinfo.metadata="${METADATA}" \
    -e guestinfo.metadata.encoding="gzip+base64" \
    -e guestinfo.userdata="${USERDATA}" \
    -e guestinfo.userdata.encoding="gzip+base64"

$ vmtoolsd --cmd "info-get guestinfo.metadata" | base64 -d | zcat -
instance-id: cloud-vm
local-hostname: cloud-vm
network:
  version: 2
  ethernets:
    eth0:
      match:
        macaddress: '00:0c:29:21:f1:61'
      dhcp4: false
      addresses:
        - 172.16.171.139/24
      nameservers:
        addresses: [172.16.171.254]
      routes:
        - to: 0.0.0.0/0
          via: 172.16.171.254

$ vmtoolsd --cmd "info-get guestinfo.userdata" | base64 -d | zcat -
#cloud-config

users:
  - default
```

Some _cloud-init_ commands:
- `cloud-init collect-logs -uv`
- `cloud-init clean -l --machine-id -s` # remove logs, zero machine-id and remove CI seed dir
- `DEBUG_LEVEL=2 DI_LOG=stderr /usr/lib/cloud-init/ds-identify --force` # detect datasources
- `cloud-id` # which datasource is being used by CI
  ``` shell
  # not yet run, or `cloud-init clean -s' was used
  $ cloud-id
  not run
  ```


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


#### corosync

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

##### corosync logs

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


### corosync-qdevice

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


#### DLM

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


#### pacemaker

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

##### pacemaker cli

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

##### pacemaker resources

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

#### crm (crmsh)

- by default *root* and *haclient* group members can manage cluster
- some `crm` actions require SSH working between nodes, either
  passwordless root or via a user configured with `crm options user
  <user>` (then it requires passwordless `sudoers` rule)

``` shell
crm
crm help <topic>    # generic syntax for help
crm status          # similar to *crm_mon*, part of crmsh
```

##### crm collocating resources

Reads from right to left, if last right resource runs somewhere, do action
defined with next-to-last and all previous resources.

```
colocation <id> <score>: <resource> <resource>

# an example
colocation c1 inf: p-goodservice p-badservice
```

The above reads: if `p-badservice` runs somehwere always run `p-goodservice`
together.

##### crm grouping resources

Reads from left to right, order is respected, this influence state of the
resources, that is states is respected in order, that is if a resource on the
left in the list is stopped, then resources on the right side are stopped too.

```
group <name> <res> <res>...

# an example
group g-grp1 p-goodservice p-badservice
```

The above reads: start `p-goodservice` and then `p-badservice`.

##### crm resource

``` shell
crm resource status # show status of resources

crm resource # interactive shell for resources
crm configure [edit] # configuration edit via editor
                     # do not forget commit changes!
crm move     # careful, creates constraints
crm resource constraints <resource> # show resource constraints
```

##### crmsh hacks

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


#### hawk web ui

[hawk](https://github.com/ClusterLabs/hawk) needs that a user is in
*haclient* group; it uses PAM
([*passwd*](https://github.com/ClusterLabs/hawk/blob/f9838ba95ed7a23ef4f8156b2b69031e8fadd19c/hawk/app/models/session.rb#L52)
service):

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


#### maintenances

WARNINGS:

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

``` shell
crm configure property maintenance-mode=<true|false> # global maintenance

crm node maintenance <node> # node maintenance start
crm node ready <node>       # node maintenance stop

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

##### tips & tricks

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

##### acls

- same users and userids on all nodes
- users must be in *haclient* user group
- users need to have rights to run `/usr/bin/crm`

##### troubleshooting

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


#### troubleshooting

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


## databases


### db2

DB2 requires `bin` user, see https://www.ibm.com/support/pages/db2-luw-product-installation-fails-unix-platform-without-bin-user.

*WIP* !!! https://www.tutorialspoint.com/db2/db2_instance.htm
          https://community.ibm.com/community/user/datamanagement/discussion/how-to-run-docker-ibmcomdb2-image-as-non-root


- ./db2setup to install db2

``` shell
$ cat > response_file <<EOF
LIC_AGREEMENT       = ACCEPT
PROD       = DB2_SERVER_EDITION
FILE       = /opt/ibm/db2/V11.5
INSTALL_TYPE       = CUSTOM
INTERACTIVE               = YES
COMP       = SQL_PROCEDURES
COMP       = CONNECT_SUPPORT
COMP       = BASE_DB2_ENGINE
COMP       = REPL_CLIENT
COMP       = JDK
COMP       = JAVA_SUPPORT
COMP       = BASE_CLIENT
COMP       = COMMUNICATION_SUPPORT_TCPIP
DAS_CONTACT_LIST       = LOCAL
LANG       = EN
EOF

$ db2/server_dec/db2setup -r response_file
```

- users/groups


- ./db2icrt ... to create instance



- disable db2fmd
- populate data into instance
- backup / restore
- hadr
- pacemaker


## dbus

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


## desktop


### ffmpeg

How to record a region of X11 screen?

``` shell
$ ffmpeg -f x11grab -y -framerate 20 \
    $(slop -f "-grab_x %x -grab_y %y -s %wx%h") \
    -i :0.0 -c:v libx264 -preset superfast -crf 21
    /tmp/"$(date +'%Y-%m-%d_%H-%M-%S').mp4"
```

And converting to GIF:

``` shell
$ ffmpeg -i <video> \
    -vf "fps=10,scale=640:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse" \
    -loop 0 <output>.gif
```

``` shell
$  mogrify -layers optimize -fuzz 10% <output>gif
```


### i3wm

To make tray on primary display, do:

``` shell
bar {
    status_command i3status
    tray_output primary
}
```


### brave-browser

For using multiple profiles I used these wrappers:

``` shell
$ grep -H '' ~/bin/{foobarbrave,brave-browser}
/home/jiri/bin/foobarbrave:#!/bin/bash
/home/jiri/bin/foobarbrave:exec /usr/bin/brave-browser --profile-directory="Profile 1" $@
/home/jiri/bin/brave-browser:#!/bin/bash
/home/jiri/bin/brave-browser:exec /usr/bin/brave-browser --profile-directory="Default" $@

# the name of the profile itself is defined in JSON file

$ jq -r '.profile.name' '/home/jiri/.config/BraveSoftware/Brave-Browser/Default/Preferences'
jiri
```

#### browserpass

If a distro does not have a system package, then:

``` shell
$ make BIN=browserpass-linux64 PREFIX=$HOME/.local DESTDIR= configure
$ make BIN=browserpass-linux64 PREFIX=$HOME/.local DESTDIR=~/.local/share/stow/browserpass-linux64-3.1.0 install
$ mv ~/.local/stow/browserpass-linux64-3.1.0/home/jiri/.local/* ~/.local/stow/browserpass-linux64-3.1.0/
$ rm -rf ~/.local/share/stow/browserpass-linux64-3.1.0/home
$ stow -d ~/.local/share/stow/ -t ~/.local -vvv browserpass-linux64-3.1.0
$ cd ~/.local/lib/browserpass/
$ make BIN=browserpass-linux64 PREFIX=.local DESTDIR=/home/jiri/ hosts-brave-user # creates symlink (replace with 'chromium' if needed)
$ make BIN=browserpass-linux64 PREFIX=.local DESTDIR=/home/jiri/ policies-brave-user # creates symlink (replace with 'chromium' if needed)

$ grep -H '' /home/jiri/.local/lib/browserpass/{hosts,policies}/chromium/com.github.browserpass.native.json
/home/jiri/.local/lib/browserpass/hosts/chromium/com.github.browserpass.native.json:{
/home/jiri/.local/lib/browserpass/hosts/chromium/com.github.browserpass.native.json:    "name": "com.github.browserpass.native",
/home/jiri/.local/lib/browserpass/hosts/chromium/com.github.browserpass.native.json:    "description": "Browserpass native component for the Chromium extension",
/home/jiri/.local/lib/browserpass/hosts/chromium/com.github.browserpass.native.json:    "path": "/home/jiri/.local/bin/browserpass-linux64",
/home/jiri/.local/lib/browserpass/hosts/chromium/com.github.browserpass.native.json:    "type": "stdio",
/home/jiri/.local/lib/browserpass/hosts/chromium/com.github.browserpass.native.json:    "allowed_origins": [
/home/jiri/.local/lib/browserpass/hosts/chromium/com.github.browserpass.native.json:        "chrome-extension://naepdomgkenhinolocfifgehidddafch/",
/home/jiri/.local/lib/browserpass/hosts/chromium/com.github.browserpass.native.json:        "chrome-extension://pjmbgaakjkbhpopmakjoedenlfdmcdgm/",
/home/jiri/.local/lib/browserpass/hosts/chromium/com.github.browserpass.native.json:        "chrome-extension://klfoddkbhleoaabpmiigbmpbjfljimgb/"
/home/jiri/.local/lib/browserpass/hosts/chromium/com.github.browserpass.native.json:    ]
/home/jiri/.local/lib/browserpass/hosts/chromium/com.github.browserpass.native.json:}
/home/jiri/.local/lib/browserpass/policies/chromium/com.github.browserpass.native.json:{
/home/jiri/.local/lib/browserpass/policies/chromium/com.github.browserpass.native.json:    "ExtensionInstallForcelist": [
/home/jiri/.local/lib/browserpass/policies/chromium/com.github.browserpass.native.json:        "naepdomgkenhinolocfifgehidddafch;https://clients2.google.com/service/update2/crx"
/home/jiri/.local/lib/browserpass/policies/chromium/com.github.browserpass.native.json:    ]
/home/jiri/.local/lib/browserpass/policies/chromium/com.github.browserpass.native.json:}
```

### desktop files

To override *exec* like for an `.desktop` file.

``` shell
$ desktop-file-install --dir ~/.local/share/applications/ /usr/share/applications/remote-viewer.desktop
$ desktop-file-edit --set-key=Exec --set-value='myremote-viewer %u' ~/.local/share/applications/remote-viewer.desktop
```

and write your `myremote-viewer` wrapper (eg. to force some options).


### dot-files management


#### yadm

[`yadm`](https://yadm.io/) is a wrapper around `git` which also can
encrypt some files.

As it is a wrapper, one can use `git` sub-commands, here listing
plain-text files managed by `yadm`:

``` shell
$ yadm ls-files
.Xresources
.ansible.cfg
.bash_profile
.bashrc
.config/gtk-3.0/bookmarks
.config/gtk-3.0/settings.ini
.config/i3/config
.config/mc/ini
.config/mc/mc.ext
.config/redshift/redshift.conf
.config/user-dirs.conf
.config/user-dirs.dirs
.config/yadm/bootstrap
.config/yadm/encrypt
.gitconfig
.gitmodules
.gnupg/gpg.conf
.gtkrc-2.0
.lftp/rc
.local/share/yadm/archive
.python3.lst
.ssh/config
.xinitrc
.xprofile
bin/booklet
bin/selscrot

# and with git directly

$ git --no-pager --git-dir .local/share/yadm/repo.git/ ls-files
.Xresources
.ansible.cfg
.bash_profile
.bashrc
.config/gtk-3.0/bookmarks
.config/gtk-3.0/settings.ini
.config/i3/config
.config/mc/ini
.config/mc/mc.ext
.config/redshift/redshift.conf
.config/user-dirs.conf
.config/user-dirs.dirs
.config/yadm/bootstrap
.config/yadm/encrypt
.gitconfig
.gitmodules
.gnupg/gpg.conf
.gtkrc-2.0
.lftp/rc
.local/share/yadm/archive
.python3.lst
.ssh/config
.xinitrc
.xprofile
bin/booklet
bin/selscrot
```

A definition for files to be encrypted can be something like this:

``` shell
$ cat .config/yadm/encrypt
.aws/config
.aws/credentials
.claws-mail/*rc
.claws-mail/addrbook
.claws-mail/certs
.claws-mail/templates
.config/keepassxc/keepassxc.ini
.config/rclone/rclone.conf
.config/syncthing/config.xml
.gnupg/*.gpg
.mbsyncrc
.msmtprc
.muttrc
.ssh/authorized_keys
.ssh/config-home
.ssh/config-local
.ssh/config-webhost
.ssh/config-work
.ssh/id_*
.ssh/known_hosts
.weechat/irc.conf
sync/**/*.kdbx
```

Encryption:

``` shell
# overriding default 'gpg' to use 'openssl'

$ cat .config/yadm/config
[yadm]
        cipher = openssl

$ yadm encrypt
Encrypting the following files:
...
enter AES-256-CBC encryption password:
Verifying - enter AES-256-CBC encryption password:
Wrote new file: /home/jiri/.local/share/yadm/archive

# no miracle format, one can validate with openssl command!

$ openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -md sha512 \
  -in /home/jiri/.local/share/yadm/archive -out /tmp/archive
enter AES-256-CBC decryption password:

$ file /tmp/archive
/tmp/archive: POSIX tar archive
```

`yadm` also support bootstrap script (`$HOME/.config/yadm/bootstrap`), an example:

``` shell
# not to mess with existing files and local repo changing 'yadm-repo'
# and 'work-dir' path

$ yadm --yadm-repo /tmp/yadm-repo clone git@gitlab.com:jirib79/dotfiles.git -w /tmp/jiri-home --bootstrap -f                                                                                                             [246/1915]
Cloning into 'repo.git'...
remote: Enumerating objects: 223, done.
remote: Counting objects: 100% (223/223), done.
remote: Compressing objects: 100% (132/132), done.
remote: Total 223 (delta 82), reused 140 (delta 47), pack-reused 0
Receiving objects: 100% (223/223), 2.06 MiB | 7.62 MiB/s, done.
Resolving deltas: 100% (82/82), done.
**NOTE**
  Local files with content that differs from the ones just
  cloned were found in /tmp/jiri-home. They have been left
  unmodified.

  Please review and resolve any differences appropriately.
  If you know what you're doing, and want to overwrite the
  tracked files, consider 'yadm checkout "/tmp/jiri-home"'.

Executing /home/jiri/.config/yadm/bootstrap
+ set -o pipefail
+ [[ -d /home/jiri/bin ]]
+ lsb_release -d
+ grep -q 'openSUSE Tumbleweed'
+ opensuse_setup
+ sudo zypper -n -q ar -f -p 90 https://ftp.gwdg.de/pub/linux/misc/packman/suse/openSUSE_Tumbleweed/ packman
Repository named 'packman' already exists. Please use another alias.
+ true
+ sudo zypper -n -q ar -f https://dl.google.com/linux/chrome/rpm/stable/x86_64 google-chrome
Repository named 'google-chrome' already exists. Please use another alias.
+ true
+ sudo zypper --gpg-auto-import-keys ref
Retrieving repository 'NEXT version of GNOME (unstable) (openSUSE_Factory)' metadata ...................................................................................................................................................[done]
Building repository 'NEXT version of GNOME (unstable) (openSUSE_Factory)' cache ........................................................................................................................................................[done]
Repository 'Kernel builds for branch stable (standard)' is up to date.
Repository 'SUSE_CA' is up to date.
Retrieving repository 'The Go Programming Language (openSUSE_Factory)' metadata ........................................................................................................................................................[done]
Building repository 'The Go Programming Language (openSUSE_Factory)' cache .............................................................................................................................................................[done]
Retrieving repository 'OCaml (openSUSE_Tumbleweed)' metadata ...........................................................................................................................................................................[done]
Building repository 'OCaml (openSUSE_Tumbleweed)' cache ................................................................................................................................................................................[done]
Retrieving repository 'Perl and perl modules (openSUSE_Tumbleweed)' metadata ...........................................................................................................................................................[done]
Building repository 'Perl and perl modules (openSUSE_Tumbleweed)' cache ................................................................................................................................................................[done]
Repository 'google-chrome' is up to date.
Repository 'home:tmuntan1 (openSUSE_Tumbleweed)' is up to date.
Repository 'packman' is up to date.
Repository 'repo-non-oss' is up to date.
Repository 'repo-oss' is up to date.
Repository 'repo-update' is up to date.
Repository 'Official repository for the snapd package (snap package manager) (openSUSE_Tumbleweed)' is up to date.
Retrieving repository 'vscode' metadata ................................................................................................................................................................................................[done]
Building repository 'vscode' cache .....................................................................................................................................................................................................[done]
All repositories have been refreshed.
++ opensuse_pkgs
++ local _pkgs
++ read -r -d '' _pkgs
++ :
+++ sed -r 's/#\S+//g'
++ _pkgs='7zip
         NetworkManager-applet
         NetworkManager-openconnect-gnome
         NetworkManager-openvpn-gnome
         bc
         blueman
         borgbackup
         bsdtar
...
```


### gtk

For version 3, 4... one can customize the themes this way:

``` shell
$ gsettings set org.gnome.desktop.interface font-name 'DejaVu Sans 9'
$ gsettings set org.gnome.desktop.interface icon-theme bloom-classic-dark
$ gsettings set org.gnome.desktop.interface gtk-theme Arc-Dark
```


#### file-chrooser

``` shell
dconf write /org/gtk/settings/file-chooser/sort-directories-first true # dirs first
cat  ~/.config/gtk-3.0/bookmarks # output: file://<absolute_path> <label>
```


### java iceadtea-web

An old Supermicro IPMI issue:

```
...
App already has trusted publisher: false
netx: Initialization Error: Could not initialize application. (Fatal: Application Error: Cannot grant permissions to unsigned jars. Application requested security permissions, but jars are not signed.)
net.sourceforge.jnlp.LaunchException: Fatal: Initialization Error: Could not initialize application. The application has not been initialized, for more information execute javaws from the command line.
        at java.desktop/net.sourceforge.jnlp.Launcher.createApplication(Launcher.java:823)
        at java.desktop/net.sourceforge.jnlp.Launcher.launchApplication(Launcher.java:531)
        at java.desktop/net.sourceforge.jnlp.Launcher$TgThread.run(Launcher.java:946)
Caused by: net.sourceforge.jnlp.LaunchException: Fatal: Application Error: Cannot grant permissions to unsigned jars. Application requested security permissions, but jars are not signed.
        at java.desktop/net.sourceforge.jnlp.runtime.JNLPClassLoader$SecurityDelegateImpl.getClassLoaderSecurity(JNLPClassLoader.java:2488)
        at java.desktop/net.sourceforge.jnlp.runtime.JNLPClassLoader.setSecurity(JNLPClassLoader.java:384)
        at java.desktop/net.sourceforge.jnlp.runtime.JNLPClassLoader.initializeResources(JNLPClassLoader.java:807)
        at java.desktop/net.sourceforge.jnlp.runtime.JNLPClassLoader.<init>(JNLPClassLoader.java:337)
        at java.desktop/net.sourceforge.jnlp.runtime.JNLPClassLoader.createInstance(JNLPClassLoader.java:420)
        at java.desktop/net.sourceforge.jnlp.runtime.JNLPClassLoader.getInstance(JNLPClassLoader.java:494)
        at java.desktop/net.sourceforge.jnlp.runtime.JNLPClassLoader.getInstance(JNLPClassLoader.java:467)
        at java.desktop/net.sourceforge.jnlp.Launcher.createApplication(Launcher.java:815)
        ... 2 more
```

``` shell
$ rpm -qf $(readlink -f `which jarsigner`)
java-11-openjdk-devel-11.0.17.0-2.1.x86_64

$ find /home/jiri/.cache/icedtea-web/ -type f -name '*.jar'
/home/jiri/.cache/icedtea-web/cache/2/http/192.168.200.100/80/iKVM__V1.69.21.0x0.jar
/home/jiri/.cache/icedtea-web/cache/3/http/192.168.200.100/80/liblinux_x86_64__V1.0.5.jar

$ jarsigner -verify -verbose /home/jiri/.cache/icedtea-web/cache/3/http/192.168.200.100/80/liblinux_x86_64__V1.0.5.jar

         309 Mon Jun 30 19:28:14 CEST 2014 META-INF/MANIFEST.MF
         331 Mon Jun 30 19:28:14 CEST 2014 META-INF/SMCCERT.SF
        5348 Mon Jun 30 19:28:14 CEST 2014 META-INF/SMCCERT.RSA
           0 Mon Jun 30 19:28:14 CEST 2014 META-INF/
 m  ? 261688 Wed Jun 25 11:53:44 CEST 2014 libSharedLibrary64.so
 m  ? 204592 Wed Jun 25 11:53:44 CEST 2014 libiKVM64.so

  s = signature was verified
  m = entry is listed in manifest
  k = at least one certificate was found in keystore
  ? = unsigned entry

- Signed by "CN="Super Micro Computer, Inc", OU="Super Micro Computer, Inc", OU=Digital ID Class 3 - Java Object Signing, O="Super Micro Computer, Inc", L=San Jose, ST=California, C=US"
    Digest algorithm: SHA1 (disabled)
    Signature algorithm: SHA1withRSA (disabled), 2048-bit key

WARNING: The jar will be treated as unsigned, because it is signed with a weak algorithm that is now disabled by the security property:

  jdk.jar.disabledAlgorithms=MD2, MD5, RSA keySize < 1024, DSA keySize < 1024, SHA1 denyAfter 2019-01-01, include jdk.disabled.namedCurves

$ grep -IRP -C 5 '^jdk.jar.disabledAlgorithms' $(dirname $(readlink -f $(which java)))/../
/usr/lib64/jvm/java-11-openjdk-11/bin/../conf/security/java.security-# implementation. It is not guaranteed to be examined and used by other
/usr/lib64/jvm/java-11-openjdk-11/bin/../conf/security/java.security-# implementations.
/usr/lib64/jvm/java-11-openjdk-11/bin/../conf/security/java.security-#
/usr/lib64/jvm/java-11-openjdk-11/bin/../conf/security/java.security-# See "jdk.certpath.disabledAlgorithms" for syntax descriptions.
/usr/lib64/jvm/java-11-openjdk-11/bin/../conf/security/java.security-#
/usr/lib64/jvm/java-11-openjdk-11/bin/../conf/security/java.security:jdk.jar.disabledAlgorithms=MD2, MD5, RSA keySize < 1024, \
/usr/lib64/jvm/java-11-openjdk-11/bin/../conf/security/java.security-      DSA keySize < 1024, SHA1 denyAfter 2019-01-01, \
/usr/lib64/jvm/java-11-openjdk-11/bin/../conf/security/java.security-      include jdk.disabled.namedCurves
/usr/lib64/jvm/java-11-openjdk-11/bin/../conf/security/java.security-
/usr/lib64/jvm/java-11-openjdk-11/bin/../conf/security/java.security-#
/usr/lib64/jvm/java-11-openjdk-11/bin/../conf/security/java.security-# Algorithm restrictions for Secure Socket Layer/Transport Layer Security
and commenting the line which causes "problems" made it working again (edited)
```

and overriding the option which causes "problems" made it working again.


### monitors

``` shell
ls /sys/class/drm/*/edid | \
  xargs -i {} sh -c "echo {}; parse-edid < {}" 2>/dev/null # get info about monitors
```


### pipewire

How to record a sound which is being played.

``` shell
$ pw-cli list-objects Node | grep -B 8 -iP 'node\.description = .*speaker'
        id 56, type PipeWire:Interface:Node/3
                object.serial = "56"
                object.path = "alsa:pcm:1:hw:Generic_1:playback"
                factory.id = "18"
                client.id = "35"
                device.id = "47"
                priority.session = "1000"
                priority.driver = "1000"
                node.description = "Family 17h/19h HD Audio Controller Speaker + Headphones"

$ pw-record --target 56 /tmp/sound.flac
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


### remote desktop

[freerdp](https://github.com/FreeRDP/FreeRDP) is newer alternative to
`rdesktop`; it has nice features:

``` shell
$ printf '/u:foo\n/d:.\\\n/v:192.168.100.176\n/cert:ignore\n/auth-pkg-list:ntlm,!kerberos\n/sec:nla' | \
    env FREERDP_ASKPASS='pass show hw/t14s/win11' /opt/freerdp-nightly/bin/xfreerdp3 /args-from:stdin
```


### xdg

``` shell
xdg-mime query filetype <file>     # returns mime type
xdg-mime query default <mime_type> # returns desktop file
```

### sway

Not fully completed yet.

``` shell
$ grep -RHPv '^\s*(#|$|//)' .config/{sway/config,waybar/*}
.config/sway/config:set $mod Mod4
.config/sway/config:set $left h
.config/sway/config:set $down j
.config/sway/config:set $up k
.config/sway/config:set $right l
.config/sway/config:set $term foot
.config/sway/config:set $menu dmenu_path | wmenu | xargs swaymsg exec --
.config/sway/config:include /etc/sway/config-vars.d/*
.config/sway/config:set $screenlock "swaylock -k -c 000000"
.config/sway/config:bindsym $mod+F2 exec $screenlock
.config/sway/config:    bindsym $mod+Return exec $term
.config/sway/config:    bindsym $mod+Shift+q kill
.config/sway/config:    bindsym $mod+d exec $menu
.config/sway/config:    floating_modifier $mod normal
.config/sway/config:    bindsym $mod+Shift+c reload
.config/sway/config:    bindsym $mod+Shift+e exec swaynag -t warning -m 'You pressed the exit shortcut. Do you really want to exit sway? This will end your Wayland session.' -B 'Yes, exit sway' 'swaymsg exit'
.config/sway/config:    bindsym $mod+$left focus left
.config/sway/config:    bindsym $mod+$down focus down
.config/sway/config:    bindsym $mod+$up focus up
.config/sway/config:    bindsym $mod+$right focus right
.config/sway/config:    bindsym $mod+Left focus left
.config/sway/config:    bindsym $mod+Down focus down
.config/sway/config:    bindsym $mod+Up focus up
.config/sway/config:    bindsym $mod+Right focus right
.config/sway/config:    bindsym $mod+Shift+$left move left
.config/sway/config:    bindsym $mod+Shift+$down move down
.config/sway/config:    bindsym $mod+Shift+$up move up
.config/sway/config:    bindsym $mod+Shift+$right move right
.config/sway/config:    bindsym $mod+Shift+Left move left
.config/sway/config:    bindsym $mod+Shift+Down move down
.config/sway/config:    bindsym $mod+Shift+Up move up
.config/sway/config:    bindsym $mod+Shift+Right move right
.config/sway/config:    bindsym $mod+1 workspace number 1
.config/sway/config:    bindsym $mod+2 workspace number 2
.config/sway/config:    bindsym $mod+3 workspace number 3
.config/sway/config:    bindsym $mod+4 workspace number 4
.config/sway/config:    bindsym $mod+5 workspace number 5
.config/sway/config:    bindsym $mod+6 workspace number 6
.config/sway/config:    bindsym $mod+7 workspace number 7
.config/sway/config:    bindsym $mod+8 workspace number 8
.config/sway/config:    bindsym $mod+9 workspace number 9
.config/sway/config:    bindsym $mod+0 workspace number 10
.config/sway/config:    bindsym $mod+Shift+1 move container to workspace number 1
.config/sway/config:    bindsym $mod+Shift+2 move container to workspace number 2
.config/sway/config:    bindsym $mod+Shift+3 move container to workspace number 3
.config/sway/config:    bindsym $mod+Shift+4 move container to workspace number 4
.config/sway/config:    bindsym $mod+Shift+5 move container to workspace number 5
.config/sway/config:    bindsym $mod+Shift+6 move container to workspace number 6
.config/sway/config:    bindsym $mod+Shift+7 move container to workspace number 7
.config/sway/config:    bindsym $mod+Shift+8 move container to workspace number 8
.config/sway/config:    bindsym $mod+Shift+9 move container to workspace number 9
.config/sway/config:    bindsym $mod+Shift+0 move container to workspace number 10
.config/sway/config:    bindsym $mod+b splith
.config/sway/config:    bindsym $mod+v splitv
.config/sway/config:    bindsym $mod+s layout stacking
.config/sway/config:    bindsym $mod+w layout tabbed
.config/sway/config:    bindsym $mod+e layout toggle split
.config/sway/config:    bindsym $mod+f fullscreen
.config/sway/config:    bindsym $mod+Shift+space floating toggle
.config/sway/config:    bindsym $mod+space focus mode_toggle
.config/sway/config:    bindsym $mod+a focus parent
.config/sway/config:    bindsym $mod+Shift+minus move scratchpad
.config/sway/config:    bindsym $mod+minus scratchpad show
.config/sway/config:mode "resize" {
.config/sway/config:    bindsym $left resize shrink width 10px
.config/sway/config:    bindsym $down resize grow height 10px
.config/sway/config:    bindsym $up resize shrink height 10px
.config/sway/config:    bindsym $right resize grow width 10px
.config/sway/config:    bindsym Left resize shrink width 10px
.config/sway/config:    bindsym Down resize grow height 10px
.config/sway/config:    bindsym Up resize shrink height 10px
.config/sway/config:    bindsym Right resize grow width 10px
.config/sway/config:    bindsym Return mode "default"
.config/sway/config:    bindsym Escape mode "default"
.config/sway/config:}
.config/sway/config:bindsym $mod+r mode "resize"
.config/sway/config:bar {
.config/sway/config:    swaybar_command waybar
.config/sway/config:    status_command i3status
.config/sway/config:    colors {
.config/sway/config:        statusline #ffffff
.config/sway/config:        background #000000
.config/sway/config:        inactive_workspace #32323200 #32323200 #5c5c5c
.config/sway/config:    }
.config/sway/config:}
.config/sway/config:include /etc/sway/config.d/*
.config/waybar/config.jsonc:{
.config/waybar/config.jsonc:    "position": "bottom", // Waybar position (top|bottom|left|right)
.config/waybar/config.jsonc:    "height": 30, // Waybar height (to be removed for auto height)
.config/waybar/config.jsonc:    "spacing": 4, // Gaps between modules (4px)
.config/waybar/config.jsonc:    "modules-left": [
.config/waybar/config.jsonc:        "sway/workspaces",
.config/waybar/config.jsonc:        "sway/mode",
.config/waybar/config.jsonc:        "sway/scratchpad",
.config/waybar/config.jsonc:        "custom/media"
.config/waybar/config.jsonc:    ],
.config/waybar/config.jsonc:    "modules-right": [
.config/waybar/config.jsonc:        "pulseaudio",
.config/waybar/config.jsonc:        "network",
.config/waybar/config.jsonc:        "cpu",
.config/waybar/config.jsonc:        "memory",
.config/waybar/config.jsonc:        "temperature",
.config/waybar/config.jsonc:        "backlight",
.config/waybar/config.jsonc:        "keyboard-state",
.config/waybar/config.jsonc:        "sway/language",
.config/waybar/config.jsonc:        "battery",
.config/waybar/config.jsonc:        "battery#bat2",
.config/waybar/config.jsonc:        "clock",
.config/waybar/config.jsonc:        "tray"
.config/waybar/config.jsonc:,
.config/waybar/config.jsonc:        "custom/power"
.config/waybar/config.jsonc:    ],
.config/waybar/config.jsonc:    "keyboard-state": {
.config/waybar/config.jsonc:        "numlock": true,
.config/waybar/config.jsonc:        "capslock": true,
.config/waybar/config.jsonc:        "format": "{name} {icon}",
.config/waybar/config.jsonc:        "format-icons": {
.config/waybar/config.jsonc:            "locked": "",
.config/waybar/config.jsonc:            "unlocked": ""
.config/waybar/config.jsonc:        }
.config/waybar/config.jsonc:    },
.config/waybar/config.jsonc:    "sway/mode": {
.config/waybar/config.jsonc:        "format": "<span style=\"italic\">{}</span>"
.config/waybar/config.jsonc:    },
.config/waybar/config.jsonc:    "sway/scratchpad": {
.config/waybar/config.jsonc:        "format": "{icon} {count}",
.config/waybar/config.jsonc:        "show-empty": false,
.config/waybar/config.jsonc:        "format-icons": ["", ""],
.config/waybar/config.jsonc:        "tooltip": true,
.config/waybar/config.jsonc:        "tooltip-format": "{app}: {title}"
.config/waybar/config.jsonc:    },
.config/waybar/config.jsonc:    "idle_inhibitor": {
.config/waybar/config.jsonc:        "format": "{icon}",
.config/waybar/config.jsonc:        "format-icons": {
.config/waybar/config.jsonc:            "activated": "",
.config/waybar/config.jsonc:            "deactivated": ""
.config/waybar/config.jsonc:        }
.config/waybar/config.jsonc:    },
.config/waybar/config.jsonc:    "tray": {
.config/waybar/config.jsonc:        "spacing": 10
.config/waybar/config.jsonc:    },
.config/waybar/config.jsonc:    "clock": {
.config/waybar/config.jsonc:        "tooltip-format": "<big>{:%Y %B}</big>\n<tt><small>{calendar}</small></tt>",
.config/waybar/config.jsonc:        "format-alt": "{:%Y-%m-%d}",
.config/waybar/config.jsonc:        "format": "{:%H:%M:%S}",
.config/waybar/config.jsonc:        "interval": 5
.config/waybar/config.jsonc:    },
.config/waybar/config.jsonc:    "cpu": {
.config/waybar/config.jsonc:        "format": "{usage}% ",
.config/waybar/config.jsonc:        "tooltip": false
.config/waybar/config.jsonc:    },
.config/waybar/config.jsonc:    "memory": {
.config/waybar/config.jsonc:        "format": "{}% "
.config/waybar/config.jsonc:    },
.config/waybar/config.jsonc:    "temperature": {
.config/waybar/config.jsonc:        "critical-threshold": 80,
.config/waybar/config.jsonc:        "format": "{temperatureC}°C {icon}",
.config/waybar/config.jsonc:        "format-icons": ["", "", ""]
.config/waybar/config.jsonc:    },
.config/waybar/config.jsonc:    "backlight": {
.config/waybar/config.jsonc:        "format": "{percent}% {icon}",
.config/waybar/config.jsonc:        "format-icons": ["", "", "", "", "", "", "", "", ""]
.config/waybar/config.jsonc:    },
.config/waybar/config.jsonc:    "battery": {
.config/waybar/config.jsonc:        "states": {
.config/waybar/config.jsonc:            "warning": 30,
.config/waybar/config.jsonc:            "critical": 15
.config/waybar/config.jsonc:        },
.config/waybar/config.jsonc:        "format": "{capacity}% {icon}",
.config/waybar/config.jsonc:        "format-full": "{capacity}% {icon}",
.config/waybar/config.jsonc:        "format-charging": "{capacity}% ",
.config/waybar/config.jsonc:        "format-plugged": "{capacity}% ",
.config/waybar/config.jsonc:        "format-alt": "{time} {icon}",
.config/waybar/config.jsonc:        "format-icons": ["", "", "", "", ""]
.config/waybar/config.jsonc:    },
.config/waybar/config.jsonc:    "battery#bat2": {
.config/waybar/config.jsonc:        "bat": "BAT2"
.config/waybar/config.jsonc:    },
.config/waybar/config.jsonc:    "power-profiles-daemon": {
.config/waybar/config.jsonc:      "format": "{icon}",
.config/waybar/config.jsonc:      "tooltip-format": "Power profile: {profile}\nDriver: {driver}",
.config/waybar/config.jsonc:      "tooltip": true,
.config/waybar/config.jsonc:      "format-icons": {
.config/waybar/config.jsonc:        "default": "",
.config/waybar/config.jsonc:        "performance": "",
.config/waybar/config.jsonc:        "balanced": "",
.config/waybar/config.jsonc:        "power-saver": ""
.config/waybar/config.jsonc:      }
.config/waybar/config.jsonc:    },
.config/waybar/config.jsonc:    "network": {
.config/waybar/config.jsonc:        "format-wifi": "{essid} ({signalStrength}%) ",
.config/waybar/config.jsonc:        "format-ethernet": "{ipaddr}/{cidr} ",
.config/waybar/config.jsonc:        "tooltip-format": "{ifname} via {gwaddr} ",
.config/waybar/config.jsonc:        "format-linked": "{ifname} (No IP) ",
.config/waybar/config.jsonc:        "format-disconnected": "Disconnected ⚠",
.config/waybar/config.jsonc:        "format-alt": "{ifname}: {ipaddr}/{cidr}"
.config/waybar/config.jsonc:    },
.config/waybar/config.jsonc:    "pulseaudio": {
.config/waybar/config.jsonc:        "format": "{volume}% {icon} {format_source}",
.config/waybar/config.jsonc:        "format-bluetooth": "{volume}% {icon} {format_source}",
.config/waybar/config.jsonc:        "format-bluetooth-muted": " {icon} {format_source}",
.config/waybar/config.jsonc:        "format-muted": " {format_source}",
.config/waybar/config.jsonc:        "format-source": "{volume}% ",
.config/waybar/config.jsonc:        "format-source-muted": "",
.config/waybar/config.jsonc:        "format-icons": {
.config/waybar/config.jsonc:            "headphone": "",
.config/waybar/config.jsonc:            "hands-free": "",
.config/waybar/config.jsonc:            "headset": "",
.config/waybar/config.jsonc:            "phone": "",
.config/waybar/config.jsonc:            "portable": "",
.config/waybar/config.jsonc:            "car": "",
.config/waybar/config.jsonc:            "default": ["", "", ""]
.config/waybar/config.jsonc:        },
.config/waybar/config.jsonc:        "on-click": "pavucontrol"
.config/waybar/config.jsonc:    },
.config/waybar/config.jsonc:    "custom/media": {
.config/waybar/config.jsonc:        "format": "{icon} {}",
.config/waybar/config.jsonc:        "return-type": "json",
.config/waybar/config.jsonc:        "max-length": 40,
.config/waybar/config.jsonc:        "format-icons": {
.config/waybar/config.jsonc:            "spotify": "",
.config/waybar/config.jsonc:            "default": "🎜"
.config/waybar/config.jsonc:        },
.config/waybar/config.jsonc:        "escape": true,
.config/waybar/config.jsonc:        "exec": "$HOME/.config/waybar/mediaplayer.py 2> /dev/null" // Script in resources folder
.config/waybar/config.jsonc:    },
.config/waybar/config.jsonc:    "custom/power": {
.config/waybar/config.jsonc:        "format" : "⏻ ",
.config/waybar/config.jsonc:		"tooltip": false,
.config/waybar/config.jsonc:		"menu": "on-click",
.config/waybar/config.jsonc:		"menu-file": "$HOME/.config/waybar/power_menu.xml", // Menu file in resources folder
.config/waybar/config.jsonc:		"menu-actions": {
.config/waybar/config.jsonc:			"shutdown": "shutdown",
.config/waybar/config.jsonc:			"reboot": "reboot",
.config/waybar/config.jsonc:			"suspend": "systemctl suspend",
.config/waybar/config.jsonc:			"hibernate": "systemctl hibernate"
.config/waybar/config.jsonc:		}
.config/waybar/config.jsonc:    }
.config/waybar/config.jsonc:}
.config/waybar/style.css:* {
.config/waybar/style.css:    /* `otf-font-awesome` is required to be installed for icons */
.config/waybar/style.css:    font-family: FontAwesome, Roboto, Helvetica, Arial, sans-serif;
.config/waybar/style.css:    font-size: 13px;
.config/waybar/style.css:}
.config/waybar/style.css:window#waybar {
.config/waybar/style.css:  /* background-color: rgba(43, 48, 59, 0.5); */
.config/waybar/style.css:  background-color: black;
.config/waybar/style.css:    border-bottom: 3px solid rgba(100, 114, 125, 0.5);
.config/waybar/style.css:    color: #ffffff;
.config/waybar/style.css:    transition-property: background-color;
.config/waybar/style.css:    transition-duration: .5s;
.config/waybar/style.css:}
.config/waybar/style.css:window#waybar.hidden {
.config/waybar/style.css:    opacity: 0.2;
.config/waybar/style.css:}
.config/waybar/style.css:/*
.config/waybar/style.css:window#waybar.empty {
.config/waybar/style.css:    background-color: transparent;
.config/waybar/style.css:}
.config/waybar/style.css:window#waybar.solo {
.config/waybar/style.css:    background-color: #FFFFFF;
.config/waybar/style.css:}
.config/waybar/style.css:*/
.config/waybar/style.css:window#waybar.termite {
.config/waybar/style.css:    background-color: #3F3F3F;
.config/waybar/style.css:}
.config/waybar/style.css:window#waybar.chromium {
.config/waybar/style.css:    background-color: #000000;
.config/waybar/style.css:    border: none;
.config/waybar/style.css:}
.config/waybar/style.css:button {
.config/waybar/style.css:    /* Use box-shadow instead of border so the text isn't offset */
.config/waybar/style.css:    box-shadow: inset 0 -3px transparent;
.config/waybar/style.css:    /* Avoid rounded borders under each button name */
.config/waybar/style.css:    border: none;
.config/waybar/style.css:    border-radius: 0;
.config/waybar/style.css:}
.config/waybar/style.css:/* https://github.com/Alexays/Waybar/wiki/FAQ#the-workspace-buttons-have-a-strange-hover-effect */
.config/waybar/style.css:button:hover {
.config/waybar/style.css:    background: inherit;
.config/waybar/style.css:    box-shadow: inset 0 -3px #ffffff;
.config/waybar/style.css:}
.config/waybar/style.css:/* you can set a style on hover for any module like this */
.config/waybar/style.css:    background-color: #a37800;
.config/waybar/style.css:}
.config/waybar/style.css:    padding: 0 5px;
.config/waybar/style.css:    background-color: transparent;
.config/waybar/style.css:    color: #ffffff;
.config/waybar/style.css:}
.config/waybar/style.css:    background: rgba(0, 0, 0, 0.2);
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #64727D;
.config/waybar/style.css:    box-shadow: inset 0 -3px #ffffff;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #eb4d4b;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #64727D;
.config/waybar/style.css:    box-shadow: inset 0 -3px #ffffff;
.config/waybar/style.css:}
.config/waybar/style.css:    padding: 0 10px;
.config/waybar/style.css:    color: #ffffff;
.config/waybar/style.css:}
.config/waybar/style.css:    margin: 0 4px;
.config/waybar/style.css:}
.config/waybar/style.css:/* If workspaces is the leftmost module, omit left margin */
.config/waybar/style.css:.modules-left > widget:first-child > #workspaces {
.config/waybar/style.css:    margin-left: 0;
.config/waybar/style.css:}
.config/waybar/style.css:/* If workspaces is the rightmost module, omit right margin */
.config/waybar/style.css:.modules-right > widget:last-child > #workspaces {
.config/waybar/style.css:    margin-right: 0;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #000000;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #ffffff;
.config/waybar/style.css:    color: #000000;
.config/waybar/style.css:}
.config/waybar/style.css:    color: #ffffff;
.config/waybar/style.css:    background-color: #000000;
.config/waybar/style.css:}
.config/waybar/style.css:@keyframes blink {
.config/waybar/style.css:    to {
.config/waybar/style.css:        background-color: #ffffff;
.config/waybar/style.css:        color: #000000;
.config/waybar/style.css:    }
.config/waybar/style.css:}
.config/waybar/style.css:/* Using steps() instead of linear as a timing function to limit cpu usage */
.config/waybar/style.css:    background-color: #f53c3c;
.config/waybar/style.css:    color: #ffffff;
.config/waybar/style.css:    animation-name: blink;
.config/waybar/style.css:    animation-duration: 0.5s;
.config/waybar/style.css:    animation-timing-function: steps(12);
.config/waybar/style.css:    animation-iteration-count: infinite;
.config/waybar/style.css:    animation-direction: alternate;
.config/waybar/style.css:}
.config/waybar/style.css:    padding-right: 15px;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #f53c3c;
.config/waybar/style.css:    color: #ffffff;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #2980b9;
.config/waybar/style.css:    color: #ffffff;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #2ecc71;
.config/waybar/style.css:    color: #000000;
.config/waybar/style.css:}
.config/waybar/style.css:label:focus {
.config/waybar/style.css:    background-color: #000000;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #000000;
.config/waybar/style.css:    color: #ffffff;
.config/waybar/style.css:}
.config/waybar/style.css:  background-color: #000000;
.config/waybar/style.css:  color: #ffffff;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #964B00;
.config/waybar/style.css:}
.config/waybar/style.css:  background-color: #000000;
.config/waybar/style.css:  color: #ffffff;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #000000;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #f53c3c;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #000000;
.config/waybar/style.css:    color: #ffffff;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #90b1b1;
.config/waybar/style.css:    color: #2a5c45;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #fff0f5;
.config/waybar/style.css:    color: #000000;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #f53c3c;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #66cc99;
.config/waybar/style.css:    color: #2a5c45;
.config/waybar/style.css:    min-width: 100px;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #66cc99;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #ffa000;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #000000;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #eb4d4b;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #000000;
.config/waybar/style.css:}
.config/waybar/style.css:    -gtk-icon-effect: dim;
.config/waybar/style.css:}
.config/waybar/style.css:    -gtk-icon-effect: highlight;
.config/waybar/style.css:    background-color: #eb4d4b;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #2d3436;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #ecf0f1;
.config/waybar/style.css:    color: #2d3436;
.config/waybar/style.css:}
.config/waybar/style.css:    background: #000000;
.config/waybar/style.css:    color: #ffffff;
.config/waybar/style.css:    padding: 0 5px;
.config/waybar/style.css:    margin: 0 5px;
.config/waybar/style.css:    min-width: 16px;
.config/waybar/style.css:}
.config/waybar/style.css:    background: #000000;
.config/waybar/style.css:    color: #ffffff;
.config/waybar/style.css:    padding: 0 0px;
.config/waybar/style.css:    margin: 0 5px;
.config/waybar/style.css:    min-width: 16px;
.config/waybar/style.css:}
.config/waybar/style.css:    padding: 0 5px;
.config/waybar/style.css:}
.config/waybar/style.css:    background: rgba(0, 0, 0, 0.2);
.config/waybar/style.css:}
.config/waybar/style.css:    background: rgba(0, 0, 0, 0.2);
.config/waybar/style.css:}
.config/waybar/style.css:	background-color: transparent;
.config/waybar/style.css:}
.config/waybar/style.css:    padding: 0;
.config/waybar/style.css:}
.config/waybar/style.css:    padding: 0 5px;
.config/waybar/style.css:    color: white;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #cf5700;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #1ca000;
.config/waybar/style.css:}
.config/waybar/style.css:    background-color: #0069d4;
.config/waybar/style.css:}
```

TODO: env variables, monitors, keyboard layout switching...


### syncthing

Excluding all but a directory (see
https://docs.syncthing.net/users/ignoring.html for details):

```
!/directory-to-include
// Ignore everything else:
*
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

A C code with seccomp filter, an example: https://gist.github.com/fntlnz/08ae20befb91befd9a53cd91cdc6d507.

``` c
#include <errno.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>

static int install_filter(int nr, int arch, int error) {
  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, arch))),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, arch, 0, 3),
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, nr, 0, 1),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (error & SECCOMP_RET_DATA)),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("prctl(NO_NEW_PRIVS)");
    return 1;
  }
  if (prctl(PR_SET_SECCOMP, 2, &prog)) {
    perror("prctl(PR_SET_SECCOMP)");
    return 1;
  }
  return 0;
}

int main() {
  printf("hey there!\n");

  install_filter(__NR_write, AUDIT_ARCH_X86_64, EPERM);

  printf("something's gonna happen!!\n");
  printf("it will not definitely print this here\n");
  return 0;
}
```


### diff / patch

To extract hunks from a diff, see https://stackoverflow.com/questions/1990498/how-to-patch-only-a-particular-hunk-from-a-diff.


### git


#### attributes

How to make a custom `diff` for a binary file?

``` shell
$ tail -n3 .git/config
[diff "docx"]
    binary = true
    textconv = /home/jiri/bin/docx-3rd-column.py

$ tail -n1 .gitattributes
*.docx diff=docx
```

So, now `git diff` will use above _textconv_ script... Voila!


#### cloning

cloning a huge repo could take ages because of its history, adding `--depth 1`
will copy only the latest revision of everything in the repository.

``` shell
$ git clone --depth 1 git@github.com:torvalds/linux.git
```


#### git-lfs

`git-lfs` is used to efficiently manage big binary files in a git repo.

``` shell
$ echo $GIT_DIR
$ /home/jiri/www/.git

$ git lfs env
git-lfs/3.4.1 (GitHub; linux amd64; go 1.21.5)
git version 2.43.0

LocalWorkingDir=/home/jiri/www/data-202312290103
LocalGitDir=/home/jiri/www/.git
LocalGitStorageDir=/home/jiri/www/.git
LocalMediaDir=/home/jiri/www/.git/lfs/objects
LocalReferenceDirs=
TempDir=/home/jiri/www/.git/lfs/tmp
ConcurrentTransfers=8
TusTransfers=false
BasicTransfersOnly=false
SkipDownloadErrors=false
FetchRecentAlways=false
FetchRecentRefsDays=7
FetchRecentCommitsDays=0
FetchRecentRefsIncludeRemotes=true
PruneOffsetDays=3
PruneVerifyRemoteAlways=false
PruneRemoteName=origin
LfsStorageDir=/home/jiri/www/.git/lfs
AccessDownload=none
AccessUpload=none
DownloadTransfers=basic,lfs-standalone-file,ssh
UploadTransfers=basic,lfs-standalone-file,ssh
GIT_DIR=/home/jiri/www/.git
GIT_EXEC_PATH=/usr/lib/git-core
git config filter.lfs.process = "git-lfs filter-process"
git config filter.lfs.smudge = "git-lfs smudge -- %f"
git config filter.lfs.clean = "git-lfs clean -- %f"
```

See above `LfsStorageDir`.

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


#### tricks & tips

- Get GH PR as raw diff/patch, an example:
  https://github.com/weppos/whois/pull/90.diff
  https://github.com/weppos/whois/pull/90.patch
- Search commit diffs which introduce or remove a pattern:
  ``` shell
  $ git log -S <pattern>
  ```
- Working with bare repository:
  ``` shell
  $ git --no-pager --git-dir /path/to/bar/repo.git show branch:path/to/file.txt
  ```


#### github-cli

``` shell
$ asdf plugin add github-cli
$ asdf install github-cli latest
$ asdf global github-cli 2.67.0

$ gh auth login -p ssh
? Where do you use GitHub? GitHub.com
? Upload your SSH public key to your GitHub account? /home/jiri/.ssh/id_ed25519.pub
? Title for your SSH key: GitHub CLI
? How would you like to authenticate GitHub CLI? Login with a web browser

! First copy your one-time code: XXXX-YYYY
Press Enter to open https://github.com/login/device in your browser... 
Opening in existing browser session.
✓ Authentication complete.
- gh config set -h github.com git_protocol ssh
✓ Configured git protocol
✓ SSH key already existed on your GitHub account: /home/jiri/.ssh/id_ed25519.pub
✓ Logged in as jirib
! You were already logged in to this account
```

``` shell
$ gh repo list # to list repos
$ gh repo create
```

An example:

``` shell
$ gh repo create \
    scribus-scripts \
    -r origin -s . \
    --push --public --disable-wiki -d 'my scribus python scripts'
✓ Created repository jirib/scribus-scripts on GitHub
  https://github.com/jirib/scribus-scripts
✓ Added remote git@github.com:jirib/scribus-scripts.git
Enumerating objects: 3, done.
Counting objects: 100% (3/3), done.
Delta compression using up to 16 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 1.10 KiB | 1.10 MiB/s, done.
Total 3 (delta 0), reused 0 (delta 0), pack-reused 0
To github.com:jirib/scribus-scripts.git
 * [new branch]      HEAD -> main
branch 'main' set up to track 'origin/main'.
✓ Pushed commits to git@github.com:jirib/scribus-scripts.git
```


### json

A [playgroun](https://jqplay.org/) for `jq`.


### (GNU) make

An example how to automate creating of vCenter in KVM:

``` makefile
ISO=/tmp/data/iso/VMware-VCSA-all-8.0.3-24022515.iso
OVA='vcsa/VMware-vCenter-Server-Appliance-8.*.ova'
SHELL=/bin/bash
VM=vcenter

DISK_NUM := 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17
# from ./usr/lib/vmware/cis_upgrade_runner/config/deployment-size-layout.json, converted to bytes
# the 2nd disk is not in the json file, it is in fact an iso

DISK_SIZES := 52143587328 7840620544 26843545600 26843545600 10737418240 \
        10737418240 16106127360 10737418240 1073741824 10737418240 10737418240 \
        107374182400 53687091200 10737418240 5368709120 107374182400 161061273600

DISK_OPTS := $(foreach num,$(DISK_NUM),--disk /var/lib/libvirt/images/vsphere/vcenter-disk$(num).qcow2,bus=sata)

all: vmdk qcow2 snapshot install

vmdk: vcenter-disk1.vmdk vcenter-disk2.vmdk vcenter-disk3.vmdk

%.vmdk:
        @echo -n "Extracting vmdk files... "
        @bsdtar xOf ${ISO} ${OVA} | bsdtar -xf - -s '/.*disk/vcenter-disk/' '*.vmdk'
        @echo Done

qcow2: vmdk $(patsubst %,vcenter-disk%.qcow2,$(DISK_NUM))

%.qcow2:
        @if [[ "$@" =~ vcenter-disk[1-3].qcow2 ]]; then \
            vmdk_file=$(@:.qcow2=.vmdk); \
            echo -n "Converting $$vmdk_file to qcow2... "; \
            qemu-img convert -O qcow2 $$vmdk_file $@ >/dev/null; \
            echo Done; \
            DISK_NUM=$$(echo $@ | grep -Po 'vcenter-disk\K([0-9]+)(?=.qcow2)'); \
            SIZE=$$(echo $(DISK_SIZES) | cut -d' ' -f$$DISK_NUM); \
            echo -n "Resizing $@ to required size... "; \
            qemu-img resize --shrink $@ $${SIZE}; \
            echo Done; \
        elif [[ "$@" =~ vcenter-disk[4-9]|1[0-7].qcow2 ]]; then \
            DISK_NUM=$$(echo $@ | grep -Po 'vcenter-disk\K([0-9]+)(?=.qcow2)'); \
            SIZE=$$(echo $(DISK_SIZES) | cut -d' ' -f$$DISK_NUM); \
            echo -n "Creating additional $@ file... "; \
            qemu-img create -f qcow2 $@ $${SIZE} >/dev/null >/dev/null; \
            echo Done; \
        else \
            echo "Unknown disk name: $<"; \
        fi

snapshot: $(patsubst %,vcenter-disk%.qcow2,$(DISK_NUM))
        @for disk in $(patsubst %,vcenter-disk%.qcow2,$(DISK_NUM)); do \
                echo "Creating snapshot for $$disk"; \
                qemu-img snapshot -c default $$disk; \
        done

install:
        @echo -n "Importing vcenter VM... "
        @virt-install \
        --name vcenter \
        --memory 14336 \
        --vcpus 2 \
        --cpu host-passthrough,check=none,migratable=on \
        $(DISK_OPTS) \
        --os-variant linux2022 \
        --network model=e1000e,network=vsphere,mac=52:54:00:fa:fc:35 \
        --wait 0 \
        --import
        @echo Done
        @echo ""
        @echo "Open vcenter console and change root user password!"
        @echo ""
        @echo "In case of an issue, revert to 'default' snapshot"

clean:
        -virsh destroy $(VM)
        -virsh undefine --nvram --tpm $(VM)
        rm -f vcenter-disk*.vmdk vcenter-disk*.qcow2
```


### patches / diffs

Patching files from different paths from one diff, that is extracting
a portion of the diff and applying separately:

``` shell
s153cl1:/usr/lib/python3.6/site-packages/crmsh # filterdiff -p2 \
    -i 'hb_report.in' -i 'utillib.py' /tmp/974.diff | \
    sed 's/hb_report\.in/hb_report/g' | patch -b -p1
patching file hb_report/hb_report
patching file hb_report/utillib.py

s153cl1:/usr/lib/python3.6/site-packages/crmsh # filterdiff -p2 \
    -i 'msg.py' -i 'utils.py' /tmp/974.diff | patch -p2 -b
patching file msg.py
patching file utils.py
```

Or more funny example...

``` shell
$ diff -uNp <(pandoc -f odt -t plain /tmp/orig.odt) \
    <(pandoc -f odt -t plain /tmp/new.odt) \
    | filterdiff --lines=171,180
```


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
- `(.*?)` - non-greedy pattern, see an example:
  ``` shell
  $ tr '\n' '\0' < src/http.c | grep -aPo '\s+proxyauth = NULL;\0\s+\}\0(.*?\0){4}' | tr '\0' '\n'
              proxyauth = NULL;
            }
          /* Examples in rfc2817 use the Host header in CONNECT
             requests.  I don't see how that gains anything, given
             that the contents of Host would be exactly the same as
             the contents of CONNECT.  */
  ```


### php

`phpinfo()` shows some basic info about PHP on the system:

``` shell
$ php8 -r 'phpinfo();' | less

# or via browser
$ echo '<?php phpinfo(); ?>' >88 /tmp/index.php
$ php8 -t / -S 127.0.0.1:8888 /tmp/index.php
[Thu Feb 23 11:32:19 2023] PHP 8.1.16 Development Server (http://127.0.0.1:8888) started
```

...and open in a web browser.

Testing `php-fpm` without whole web stack,
cf. https://maxchadwick.xyz/blog/getting-the-php-fpm-status-from-the-command-line.
An example (apparmor not taken into account here!):

``` shell
$ cat > /tmp/phptest.php <<EOF
<?php echo("Hello World!\n"); ?>
EOF

$ /usr/sbin/php-fpm --nodaemonize --fpm-config /etc/php8/fpm/php-fpm.conf -R

# other terminal

$ SCRIPT_NAME=/tmp/phptest.php SCRIPT_FILENAME=/tmp/phptest.php REQUEST_METHOD=GET QUERY_STRING=full cgi-fcgi -bind -connect 127.0.0.1:9000
X-Powered-By: PHP/8.1.7
Content-type: text/html; charset=UTF-8

Hello World!
```


#### pecl

PECL is a packaging tool for PHP allowing to install other
extensions. `mcrypt` is **deprecated** but this is just for testing:

``` shell
$ pecl download mcrypt
$ pecl install mcrypt
$ cnf phpize
$ zypper install php8-devel
$ pecl install mcrypt

$ php8 -r 'phpinfo();' | grep mcrypt
Registered Stream Filters => string.rot13, string.toupper, string.tolower, convert.*, consumed, dechunk, mcrypt.*, mdecrypt.*, convert.iconv.*, zlib.*
mcrypt
mcrypt support => enabled
mcrypt_filter support => enabled
mcrypt.algorithms_dir => no value => no value
mcrypt.modes_dir => no value => no value
PWD => /tmp/libmcrypt-2.5.8
$_SERVER['PWD'] => /tmp/libmcrypt-2.5.8
```

``` shell
$ pecl uninstall mcrypt
```


### python


#### jinja

`jinja-cli` is nice tools to validate Jinja templates/syntax:

``` shell
# here testing overload of apache_httpd_package variable

$ printf '%s\n%s\n' '{% set _pkg = apache_httpd_package | default("apache2", true) %}' '{{- _pkg }}' | \
    jinja
apache2

# ...simulating the overload, eg. for a distro which has different package name

$ printf '%s\n%s\n' '{% set _pkg = apache_httpd_package | default("apache2", true) %}' '{{- _pkg }}' | \
    jinja -D apache_httpd_package httpd
httpd
```


#### pdb

``` python
(Pdb) l 110,113
110  ->         if IMPORT_PAGE_EXTRACTOR: # in self.site.config:
111                 content = IMPORT_PAGE_EXTRACTOR(node)
112             else:
113                 content = node.prettify()

(Pdb) p bool(IMPORT_PAGE_EXTRACTOR)
True

(Pdb) p IMPORT_PAGE_EXTRACTOR
<function CommandImportPage._import_page.<locals>.<lambda> at 0x7f093b64ab60>

(Pdb) import inspect
(Pdb) p inspect.getsource(IMPORT_PAGE_EXTRACTOR)
'        IMPORT_PAGE_EXTRACTOR = lambda node: BeautifulSoup(node.decode_contents(), "html.parser").prettify()\n'

(Pdb) !IMPORT_PAGE_EXTRACTOR = None
(Pdb) p bool(IMPORT_PAGE_EXTRACTOR)
False

(pdb) n
(Pdb) l 110,113
110             if IMPORT_PAGE_EXTRACTOR: # in self.site.config:
111                 content = IMPORT_PAGE_EXTRACTOR(node)
112             else:
113  ->             content = node.prettify()
```

So, here, an example how to make a lamba-based variable `None`; that
is, change the code flow in the condition.

Now, breakpoints:

``` python
(Pdb) l 69
 64         doc_usage = "[options] page_url [page_url,...]"
 65         doc_purpose = "import arbitrary web pages"
 66  
 67         def _execute(self, options, args):
 68             import pdb;pdb.set_trace()
 69  ->         """Import a Page."""
 70             if BeautifulSoup is None:
 71                 utils.req_missing(['bs4'], 'use the import_page plugin')
 72  
 73             urls = []
 74             selector = None

(Pdb) l 86,90
 86             if not urls:
 87                 LOGGER.error(f'No page URL or file path provided.')
 88  
 89             for url in args:
 90                 self._import_page(url, selector, extractor)

(Pdb) b 86
Breakpoint 1 at /home/jiri/.nikola/plugins/import_page/import_page.py:86

(Pdb) b
Num Type         Disp Enb   Where
1   breakpoint   keep yes   at /home/jiri/.nikola/plugins/import_page/import_page.py:86

(Pdb) c
> /home/jiri/.nikola/plugins/import_page/import_page.py(86)_execute()
-> if not urls:

(Pdb) l 86
 81                 elif arg == "-e" and args:
 82                     extractor = args.pop(0)
 83                 else:
 84                     urls.append(arg)  # Assume it's a page URL
 85  
 86 B->         if not urls:
 87                 LOGGER.error(f'No page URL or file path provided.')
 88  
 89             for url in args:
 90                 self._import_page(url, selector, extractor)
 91  
```


#### python project management tools

##### python requirements.txt

This is the simplest approach:

``` shell
$ python -m venv .venv
$ pip install pyyaml remote_pdb
$ pip freeze > requirements.txt
cat requirements.txt 
PyYAML==6.0.2
remote-pdb==2.1.0
```


### svn

SVN metadata are located in `.svn` directory inside a checkout repo.

``` shell
$ svn list svn://scribus.net
branches/
tags/
tools/
trunk/
```

``` shell
# to get "upstream"

$ sqlite3 .svn/wc.db << EOF
SELECT (repository.root || '/' || nodes.local_relpath) AS full_url
FROM repository, nodes
WHERE nodes.parent_relpath IS NULL;
EOF
svn://scribus.net/


## devops


### hashicorp packer

``` shell
$ git clone https://github.com/asdf-vm/asdf.git ~/.asdf --branch v0.14.0
$ . "$HOME/.asdf/asdf.sh"
$ . "$HOME/.asdf/completions/asdf.bash"
$ asdf plugin add packer
$ asdf install packer latest
$ asdf global packer latest
```

Usually, Packer plugins are installed via `packer init`; they might be defined in a file ending with `pkr.hcl`:

``` shell
# plugins

$ find .config/packer/plugins -type f -name 'packer-plugin*amd64'
.config/packer/plugins/github.com/hashicorp/vsphere/packer-plugin-vsphere_v1.4.0_x5.0_linux_amd64
.config/packer/plugins/github.com/hashicorp/ansible/packer-plugin-ansible_v1.1.1_x5.0_linux_amd64
.config/packer/plugins/github.com/hashicorp/qemu/packer-plugin-qemu_v1.1.0_x5.0_linux_amd64

$ grep -H '' !(*var*|*templ*).pkr.hcl
provider.pkr.hcl:packer {
provider.pkr.hcl:  required_version = ">= 1.10.0"
provider.pkr.hcl:  required_plugins {
provider.pkr.hcl:    vsphere = {
provider.pkr.hcl:      version = ">= 1.3.0"
provider.pkr.hcl:      source  = "github.com/hashicorp/vsphere"
provider.pkr.hcl:    }
provider.pkr.hcl:    ansible = {
provider.pkr.hcl:      version = ">= 1.1.0"
provider.pkr.hcl:      source  = "github.com/hashicorp/ansible"
provider.pkr.hcl:    }
provider.pkr.hcl:    qemu = {
provider.pkr.hcl:      version = ">= 1.1.0"
provider.pkr.hcl:      source = "github.com/hashicorp/qemu"
provider.pkr.hcl:    }
provider.pkr.hcl:  }
provider.pkr.hcl:}
```

If you define a variable which is _sensitive_, then do NOT define it
inside Packer templates; or it might end in the artifact and,
oops... It's better to fail if such a variable is not defined properly
_outside_ of the _fixed_ template files. See [Assigning Values to
input
Variables](https://developer.hashicorp.com/packer/docs/templates/hcl_templates/variables#assigning-values-to-input-variables):

``` shell
$ packer validate -var-file=$(echo *.pkrvars.hcl) .
Error: Unset variable "ssh_private_key_file"

A used variable must be set or have a default value; see
https://packer.io/docs/templates/hcl_templates/syntax for details.

Error: Unset variable "root_password"

A used variable must be set or have a default value; see
https://packer.io/docs/templates/hcl_templates/syntax for details.

Error: Unset variable "encrypted_bootloader_password"

A used variable must be set or have a default value; see
https://packer.io/docs/templates/hcl_templates/syntax for details.
```

And, a real example:

``` shell
$ ls -l template.pkr.hcl
-rw-r--r--. 1 root root 8735 Aug 21 08:38 template.pkr.hcl

$ PACKER_LOG=1 packer build \
  -var=root_password=foobar \
  -var=encrypted_bootloader_password=foobar \
  -var=build_username=packer \
  -var=ssh_private_key_file=.ssh/id_rsa \
  -var-file=variables.pkrvars.hcl .
```

Packer can server "dynamic" files via HTTP:

``` hcl
locals {
  data_source_content = {
    autoinstxml = templatefile("${abspath(path.root)}/data/autoinst.pkrtpl.hcl", {
      build_username                   = var.build_username
      build_user_id                    = var.build_user_id
      encrypted_bootloader_password    = var.encrypted_bootloader_password
      vm_guest_os_language             = var.vm_guest_os_language
      vm_guest_os_keyboard             = var.vm_guest_os_keyboard
      vm_guest_os_timezone             = var.vm_guest_os_timezone
      vm_guest_os_cloudinit            = var.vm_guest_os_cloudinit
      additional_packages              = var.additional_packages
      reg_server                       = regex_replace(var.reg_server, "https?://", "")
      reg_server_cert_fingerprint_type = var.reg_server_cert_fingerprint_type
      reg_server_cert_fingerprint      = var.reg_server_cert_fingerprint
      reg_server_install_updates       = var.reg_server_install_updates
      reg_server_addons                = var.reg_server_addons
      reg_server_os_level              = var.reg_server_os_level
      reg_server_os_arch               = var.reg_server_os_arch
      proxy_enabled                    = var.proxy_enabled
      proxy_host                       = var.proxy_host
      no_proxy                         = var.no_proxy
    })
  }
  # for 'boot_cmd'
  data_source_command = " netsetup=dhcp autoyast=http://{{ .HTTPIP }}:{{ .HTTPPort }}/autoinst.xml rootpassword=${var.root_password}"
}

source "qemu" "root_iso" {
  ...
  http_content = {
    "/autoinst.xml" = "${local.data_source_content.autoinstxml}"
  }
  ...
```

Packer QEMU builder notes:

``` hcl
source "qemu" "root_iso" {
  ...
  qemu_binary = "/usr/libexec/qemu-kvm"
  display = "none"
  use_default_display = true

  vm_name              = "SLES15SP6-template"
  memory               = var.vm_mem_size
  disk_size            = var.vm_disk_size
  cpus                 = var.vm_cpu_count
  format               = "qcow2"
  disk_interface       = element(var.vm_disk_controller_type, 0)
  disk_compression     = true
  accelerator          = "kvm"
  headless             = "false"
  machine_type         = "q35"
  cpu_model            = "host"
  net_device           = var.vm_network_card
  vtpm                 = true
  efi_firmware_code    = "ovmf-x86_64-smm-suse-code.bin"
  efi_firmware_vars    = "ovmf-x86_64-smm-suse-vars.bin"
  ...

  # log to serial console file-backend, not everything seems to work correctly !!!
  qemuargs             = [
          ["-vga", "virtio"],
          ["-serial", "file:/tmp/ttyS0.log"]
  ]

  ...
  # SLES/OpenSUSE specific
  boot_command = [
    "<esc>",
    "e",
    "<down><down><down><down><end>",
    "${local.data_source_command}",
    "<f10>"
  ]

  ...
```

Packer cache is located at `./packer_cache` by default, or
`PACKER_CACHE_DIR` environment variable, see:
https://developer.hashicorp.com/packer/docs/configure#configure-the-cache-directory.

To debug Packer/boot of a VM, one might do:

- add `-monitor telnet:127.0.0.1:5555,server,nowait` to `qemuargs`
- add `-S` to `qemuargs` (starts QEMU in stopped mode)

```
$ PACKER_lOG=1 packer build -debug...
...
==> qemu.root_iso: Overriding default Qemu arguments with qemuargs template option...
2025/02/21 09:09:14 packer-plugin-qemu_v1.1.0_x5.0_linux_amd64 plugin: 2025/02/21 09:09:14 Executing /usr/libexec/qemu-kvm: []string{"-name", "Linux-SLES15SP6-Minimal", "-chardev", "socket,id=vtpm,path=/tmp/2901371886/vtpm.sock", "-machine", "type=q35,accel=kvm", "-vga", "virtio", "-serial", "file:/tmp/ttyS0.log", "-vnc", "127.0.0.1:52", "-m", "2048M", "-cpu", "host", "-device", "virtio-scsi-pci,id=scsi0", "-device", "scsi-hd,bus=scsi0.0,drive=drive0", "-device", "virtio-net,netdev=user.0", "-device", "tpm-tis,tpmdev=tpm0", "-smp", "2", "-tpmdev", "emulator,id=tpm0,chardev=vtpm", "-drive", "if=none,file=/data/install/__temp__/out/Linux-SLES15SP6-Minimal,id=drive0,cache=writeback,discard=ignore,format=qcow2", "-drive", "file=/data/install/__temp__/usb.img,media=cdrom", "-drive", "file=ovmf-x86_64-smm-suse-code.bin,if=pflash,unit=0,format=raw,readonly=on", "-drive", "file=/data/install/__temp__/out/efivars.fd,if=pflash,unit=1,format=raw", "-netdev", "user,id=user.0,hostfwd=tcp::2313-:22"}
...
```

An ungly hack to allow an installation from a disk image, that is, a
copy of an usb bootable media; note, it's not an installation with a
backing image!

``` hcl
source "qemu" "root_iso" {
  iso_url = "/data/install/__temp__/usb.img"
...
  qemuargs             = [
  ...
          ["-device", "ahci,id=ahci0"],
          ["-device", "ide-hd,drive=sata0,bus=ahci0.1"],
          ["-device", "ide-hd,drive=sata1,bus=ahci0.2"],
          ["-drive", "if=none,file=/data/install/__temp__/usb.img,id=sata0,cache=writeback,discard=ignore,format=raw,file.locking=off"], <---+--- same as iso_url
          ["-drive", "if=none,file=/data/install/__temp__/out/Linux-SLES15SP6-Minimal,id=sata1,cache=writeback,discard=ignore,format=qcow2,file.locking=off"] <---+--- as vm_name
  ]
```


### salt

Terminology cheat sheet:

- *salt master*: management server
- *salt minion*: managed client
- *salt SSH*: to manage clients over SSH withour minion
- *`salt-call`: runs Salt commands locally on a minion, without
   requiring a master
- *grains*: static system information
- *pillar*: secure, structured data for minions
- *reactor*: watches for events and triggers automated responses
- *beacons*: monitors minion activity (CPU load, file changes, etc...)
   and sends events to the master


#### salt on Debian

The official docs is [Install Salt
DEBs](https://docs.saltproject.io/salt/install-guide/en/latest/topics/install-by-operating-system/linux-deb.html#install-salt-debs),
but I prefer other format of sources list.

``` shell
$ curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public | \
    gpg --dearmor > /etc/apt/keyrings/saltproject-public.gpg
$ curl -fsSL https://github.com/saltstack/salt-install-guide/releases/latest/download/salt.sources | \
    awk -f <(cat <<'EOF'
BEGIN
{
    format="deb [signed-by=/etc/apt/keyrings/saltproject-public.gpg] %s %s %s\n"
}
/^(URIs|Suites|Components):/
{
    if (/^S/)
        s=$NF
    else if (/^C/)
        c=$NF
    else
        u=$NF
}
END
{
    printf(format, u, s, c)
}
EOF
) | tee /etc/apt/sources.list.d/saltproject.list
```

Version 3006 is the LTS for now, so let's pin it:

``` shell
$ cat > /etc/apt/preferences.d/salt-pin-3006 <<EOF
Package: salt-*
Pin: version 3006.*
Pin-Priority: 900
EOF
```


#### salt on SLES

Default `/etc/salt/master` on SLES:

``` shell
$ grep -Pv '^\s*(#|$)' /etc/salt/master
user: salt
syndic_user: salt

```

#### salt-master

Starting `salt-master` for the first time generates PKI certificates:

``` shell
$ salt-master -l debug
...
$ [INFO    ] Generating master keys: /etc/salt/pki/master
[DEBUG   ] salt.crypt.get_rsa_key: Loading private key
[DEBUG   ] salt.crypt._get_key_with_evict: Loading private key
[DEBUG   ] Loaded master key: /etc/salt/pki/master/master.pem
...
[INFO    ] Starting the Salt Publisher on tcp://0.0.0.0:4505
...
[DEBUG   ] Guessing ID. The id can be explicitly set in /etc/salt/minion
[DEBUG   ] Reading configuration from /etc/salt/master
[DEBUG   ] Found minion id from generate_minion_id(): avocado.example.com
[DEBUG   ] Grains refresh requested. Refreshing grains.
[DEBUG   ] Reading configuration from /etc/salt/master
...
```

After usual `salt-master` start as *systemd* unit, its processed are:

``` shell
$ systemd-cgls -u salt-master.service
Unit salt-master.service (/system.slice/salt-master.service):
├─ 1030 /usr/bin/python3 /usr/bin/salt-master
├─ 1038 /usr/bin/python3 /usr/bin/salt-master
├─ 1043 /usr/bin/python3 /usr/bin/salt-master
├─ 1047 /usr/bin/python3 /usr/bin/salt-master
├─ 1048 /usr/bin/python3 /usr/bin/salt-master
├─ 1049 /usr/bin/python3 /usr/bin/salt-master
├─ 1059 /usr/bin/python3 /usr/bin/salt-master
├─ 1074 /usr/bin/python3 /usr/bin/salt-master
├─ 1075 /usr/bin/python3 /usr/bin/salt-master
├─ 1076 /usr/bin/python3 /usr/bin/salt-master
├─ 1078 /usr/bin/python3 /usr/bin/salt-master
├─ 1079 /usr/bin/python3 /usr/bin/salt-master
└─ 1080 /usr/bin/python3 /usr/bin/salt-master

$ ss -utpl | grep salt-master
tcp   LISTEN 0      1000          0.0.0.0:4506                0.0.0.0:*    users:(("salt-master",pid=1059,fd=31))
tcp   LISTEN 0      1000          0.0.0.0:4505                0.0.0.0:*    users:(("salt-master",pid=1043,fd=18))
```

Salt PKI is RSA private PEM key and its public key.

``` shell
$ openssl rsa -in /etc/salt/pki/minion/minion.pem -pubout
writing RSA key
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxTK4hk0QXfbE0yuLrLVl
Dq8lH4you5fvO6H20PLkig3/+YWgUyxVt7MaxW/45PvV3sEAPFDWWWYRCgkUzzdI
NaKv8unUj3wDt7lduWr8zmOLwnznzjziakoDti2vwnx2P1zlFphCA4mxAc3F3+0x
0d6Y4JgrSm1Y6BGPrgC21VaArk4S6BjxPnd9xeS+DP2Q2r3g072WKn4oheuDWmqL
bYnQAdMcBeX7dx2jIUT0PZItKqiE+MMW/+m5h0i2PPRcvZzQdAZYOW+7xqdZ9n0m
yE3dlntn6NYtMxu6Zk9mnQ2ZR2t2C0/KJ/UruBNKfmCCG0NQvtGTbxYUFmx6D8uC
EwIDAQAB
-----END PUBLIC KEY-----

$ cat /etc/salt/pki/minion/minion.pub
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxTK4hk0QXfbE0yuLrLVl
Dq8lH4you5fvO6H20PLkig3/+YWgUyxVt7MaxW/45PvV3sEAPFDWWWYRCgkUzzdI
NaKv8unUj3wDt7lduWr8zmOLwnznzjziakoDti2vwnx2P1zlFphCA4mxAc3F3+0x
0d6Y4JgrSm1Y6BGPrgC21VaArk4S6BjxPnd9xeS+DP2Q2r3g072WKn4oheuDWmqL
bYnQAdMcBeX7dx2jIUT0PZItKqiE+MMW/+m5h0i2PPRcvZzQdAZYOW+7xqdZ9n0m
yE3dlntn6NYtMxu6Zk9mnQ2ZR2t2C0/KJ/UruBNKfmCCG0NQvtGTbxYUFmx6D8uC
EwIDAQAB
-----END PUBLIC KEY-----
```


#### salt-minion

`salt-minion` needs first to establish a connection to a master to
generate its key, it's *ID* is generated based on:

- FQDN
  ``` shell
  $ python3 -c 'import socket; print(socket.getfqdn());'
  avocado.example.com
  ```
- first public routable IP
- first private routable IP
- *localhost*

``` shell
...
[DEBUG   ] Connecting to master. Attempt 1 of 1
[DEBUG   ] "localhost" Not an IP address? Assuming it is a hostname.
[DEBUG   ] Master URI: tcp://127.0.0.1:4506
[DEBUG   ] Initializing new AsyncAuth for ('/etc/salt/pki/minion', 'avocado.example.com', 'tcp://127.0.0.1:4506')
[INFO    ] Generating keys: /etc/salt/pki/minion
[DEBUG   ] salt.crypt.get_rsa_key: Loading private key
[DEBUG   ] salt.crypt._get_key_with_evict: Loading private key
[DEBUG   ] Loaded minion key: /etc/salt/pki/minion/minion.pem
```

Every *minion* needs to be approved on the master:

``` shell
$ salt-key
Accepted Keys:
Denied Keys:
Unaccepted Keys:
avocado.example.com <---+--- our new minion !
Rejected Keys:

$ salt-key -a avocado.example.com
The following keys are going to be accepted:
Unaccepted Keys:
avocado.example.com
Proceed? [n/Y] y
Key for minion avocado.example.com accepted.

$ salt-key
Accepted Keys:
avocado.example.com
Denied Keys:
Unaccepted Keys:
Rejected Keys:
...
```

Basics:

``` shell
# NOTE: the minion is running!

$ salt avocado.example.com test.ping
avocado.example.com:
    True

$ salt avocado.example.com test.version
avocado.example.com:
    3004

$ salt '*' pkg.install tdfiglet
avocado.example.com:
    ----------
    tdfiglet:
        ----------
        new:
            0.5+3-bp154.1.18
        old:

$ salt '*' pkg.remove tdfiglet -v
Executing job with jid 20230223151656438667
-------------------------------------------

avocado.example.com:
    ----------
    tdfiglet:
        ----------
        new:
        old:
            0.5+3-bp154.1.18
```

Documentation for ...:

``` shell
$ salt-call sys.doc pkg | head
local:
    ----------
    pkg.add_lock:

            .. deprecated:: 3003
                This function is deprecated. Please use ``hold()`` instead.

            Add a package lock. Specify packages to lock by exact name.

            root
```


##### masterless salt-minion

To use Salt without a server is to use Salt Standalone Mode via
`salt-call'.

###### under root

``` shell
$ sed -i 's/^#* *file_client:.*/file_client: local/' /etc/salt/minion

$ systemctl  restart salt-minion.service

$ salt-call --local test.ping
local:
    True

$ salt-call --local cmd.run 'uptime'
local:
     16:17:01 up 1 day,  4:11, 15 users,  load average: 0.36, 0.63, 0.45
```

Just an example...

``` shell
$ salt-call --local pkg.install salt-master
local:
    ----------
    salt-master:
        ----------
        new:
            3006.9
        old:
```


###### under normal user

``` shell
$ cat ~/.config/user-tmpfiles.d/salt.conf
v %C/salt 0755 - -
D %C/salt/log 0755 - -
v %h/.config/salt/pki 0755 - -
D /run/user/%U/salt
v %h/.local/share/salt/files 0755 - -
v %h/.local/share/salt/pillar 0755 - -

$ systemd-tmpfiles --user --create

$ grep -Pv '^\s*(#|$)' .config/salt/minion
user: jiri
pidfile: /run/user/1000/salt/salt-minion.pid
conf_file: /home/jiri/.config/salt/minion
pki_dir: /home/jiri/.config/salt/pki/minion
cachedir: /home/jiri/.cache/salt
extension_modules: /home/jiri/.cache/salt/extmods
sock_dir: /run/user/1000/salt/minion
file_client: local
file_roots:
   base:
     - /home/jiri/.local/share/salt/files
pillar_roots:
  base:
    - /home/jiri/.local/share/salt/pillar
log_file: /run/user/1000/salt/log/minion

$ salt-call -c .config/salt/ sys.doc pkg | head
local:
    ----------
    pkg.add_repo_key:

            New in version 2017.7.0

            Add a repo key using ``apt-key add``.

            :param str path: The path of the key file to import.
            :param str text: The key data to import, in string form.
```

An example:

``` shell
$ grep -H '' {top,t14s}.sls
top.sls:base:
top.sls:  '*':
top.sls:    - t14s
t14s.sls:/home/jiri/.configured:
t14s.sls:  file.managed:
t14s.sls:    - contents: |
t14s.sls:        This system is configured by masterless Salt!
t14s.sls:    - mode: 0600

$ salt-call -c ~/.config/salt/ state.apply
local:
----------
          ID: /home/jiri/.configured
    Function: file.managed
      Result: True
     Comment: File /home/jiri/.configured updated
     Started: 14:17:26.880663
    Duration: 5.142 ms
     Changes:
              ----------
              diff:
                  New file

Summary for local
------------
Succeeded: 1 (changed=1)
Failed:    0
------------
Total states run:     1
Total run time:   5.142 ms
```


### modules

``` shell
# listing all modules

$ salt-call -c ~/.config/salt/ sys.list_modules | head
local:
    - acl
    - aliases
    - alternatives
    - ansible
    - apache
    - archive
    - artifactory
    - aws_sqs
    - baredoc

$ salt-call -c ~/.config/salt/ sys.doc file | head
local:
    ----------
    file.access:

            New in version 2014.1.0

            Test whether the Salt process has the specified access to the file. One of
            the following modes must be specified:

                f: Test the existence of the path
```

### pillars

Pillar is a feature of Salt to provide a minion some data, for example
various variables used in Salt States (SLS) files.

For example in Ansible's [Alternative directory
layout](https://docs.ansible.com/ansible/latest/tips_tricks/sample_setup.html#alternative-directory-layout),
one would in inventories define data/variables for hosts, groups... Similar could be done with *pillar*.


``` shell
$ grep -Pv '^\s*(#|$)' /etc/salt/master | sed -n '/^pillar/,/^[a-z]/p'
pillar_roots:
  base:
    - /srv/pillar

```


### XML

XML Entity Includes allow including an external XML file:

``` shell
$ jiri@t14s:/tmp$ nl server.xml | sed -n -e '1,4p' -e '/\&connector1-config/p'
     1  <?xml version="1.0" encoding="UTF-8"?>
     2  <!DOCTYPE server-xml [
     3        <!ENTITY connector1-config SYSTEM "include.xml">
     4      ]>
    67      &connector1-config;
$ cat include.xml 
    <Connector port="9999" protocol="HTTP/1.1"
               connectionTimeout="20000"
               redirectPort="9998" />
	       
$ xsltproc --output - valve.xslt server.xml | sed -n -e '1,4p' -e '/port="999[89]"/p'
<?xml version="1.0" encoding="UTF-8"?>
<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
    <Connector port="9999" protocol="HTTP/1.1" connectionTimeout="20000" redirectPort="9998"/>
```


## dns


### bind / named

``` shell
# IPv4 only
$ grep -Pv '^ *($|#)' /etc/sysconfig/named
NAMED_INITIALIZE_SCRIPTS=""
NAMED_ARGS="-4"
RNDC_KEYSIZE=512
```

``` shell
# for libvirt network only
grep -Pv '^\s*($|#)' /etc/named.conf
options {
        stale-answer-enable no;
        directory "/var/lib/named";
        managed-keys-directory "/var/lib/named/dyn/";
        dump-file "/var/log/named_dump.db";
        statistics-file "/var/log/named.stats";
        listen-on port 53 { 192.168.122.1; };
        notify no;
    disable-empty-zone "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.IP6.ARPA";
    geoip-directory none;
};
zone "." in {
        type hint;
        file "root.hint";
};
zone "localhost" in {
        type master;
        file "localhost.zone";
};
zone "0.0.127.in-addr.arpa" in {
        type master;
        file "127.0.0.zone";
};
zone "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa" IN {
    type master;
    file "127.0.0.zone";
};
zone "example.com" IN {
     type master;
     file "example.com.zone";
};
```

``` shell
$ grep -Pv '^\s*(#|$)' /var/lib/named/example.com.zone
$TTL 1h
@               IN SOA          localhost.   root.localhost. (
                                2               ; serial (d. adams)
                                2D              ; refresh
                                4H              ; retry
                                6W              ; expiry
                                1W )            ; minimum
                IN NS           ns.example.com.
ns              IN A            192.168.122.1

$ named-checkzone example.com /var/lib/named/example.com.zone
zone example.com/IN: loaded serial 2
OK
```

A stub zone forwarding, note `dns-enable` was deprected and removed
recently, thus [bind to consul
forwarding](https://developer.hashicorp.com/consul/tutorials/networking/dns-forwarding#bind-setup)
may not work in some bind versions:

```
options {
    ...
    # depends on your environment
    # dnssec-validation no;
    ...
};

zone "example.net" IN {
     type forward;
     forward only;
     forwarders {
          127.0.0.1 port 53533;
     };
};
```


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

### autofs

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


#### troubleshooting

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


### drbd

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

configs `/etc/drbd.{conf,d/*.res}`

``` shell
drbdadm [create | up | status] <resource>
drbdadm new-current-uuid --clear-bitmap <resource>/0
```


#### clustered drbd

RA is in *drbd-utils* package on SUSE.

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

#### troubleshooting

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


### OCFS2

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

For BTRFS, see its own section.


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
- *PDC* aka *NT4 domain*, `security = User` and `domain logons = Yes`,
  `domain master = Yes`, `encrypt password = Yes`; plus `[netlogon]`
  shared must be available to all users

For logging, see [Configuring Logging on a Samba
Server](https://wiki.samba.org/index.php/Configuring_Logging_on_a_Samba_Server).

Note difference in domain and realm concepts. The correct user name formats are
`DOMAIN\user` or `user@REALM`.


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

Leaving an AD domain:

``` shell
$ net ads leave -U <user>%<password>
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
    or see [Samba issues after CVE-2020-25717
    fixes](https://www.suse.com/support/kb/doc/?id=000020533)

Note that `*` in `idmap config *` does not mean a general wildcard which could
be used with whatever idmap backend; this is a *default domain* which can be
used *only* with `tdb` or `autorid` backends, see [3.4.2. THE * DEFAULT
DOMAIN](https://access.redhat.com/documentation/zh-cn/red_hat_enterprise_linux/8/html/deploying_different_types_of_servers/con_the-asterisk-default-domain_assembly_understanding-and-configuring-samba-id-mapping).

##### PDC aka NT4 domain

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

#### TDB files

Samba project maintains [TDB
Locations](https://wiki.samba.org/index.php/TDB_Locations) page which tries to
explain meaning of `tdb` files. There's also another
[page](https://web.archive.org/web/20200220135846/http://pig.made-it.com/samba-tdb.html)
which describes if such files are temporary or permanent.

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


#### usershares

It was via writing a "description" file to `/var/lib/samba/usershares':

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


### nfs

What NFS protocol version are support?

``` shell
# cat /proc/fs/nfsd/versions
-2 +3 +4 +4.1 +4.2
```

#### /etc/exports

- long lines can be wrapped with a backslash `\`
- an exported filesystem should be separated from hosts and hosts
  declaration from one another with *a space* character
- *NO space* between the host identifier and first parenthesis of
  options!

Options:

- `anonuid/anonguid`, maps "nobody" to a special UID/GID

#### nfsv4

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


#### nfsv3

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

### troubleshooting

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


### libreoffice

Running Python from LibreOffice? In headless mode? No problem!

``` shell
$ cat ~/.config/libreoffice/4/user/Scripts/python/foo.py <<EOF
import sys

def print_python_interpreter_path():
    # Print the path of the Python interpreter
    print("Python Interpreter Path:", sys.executable)
EOF

$ libreoffice --headless 'vnd.sun.star.script:foo.py$print_python_interpreter_path?language=Python&location=user'
Python Interpreter Path: /usr/bin/python3
```

It seems this is what is supported in the URI:

* `<script_file>`: Name of the script file (e.g., `foo.py`).
* `<function_name>`: Name of the function to execute (e.g., `print_python_interpreter_path`).
* `language=Python`: Specifies the script language (*Python* in this case).
* `location=<location>`: Specifies where the script is located:
  - `user`: User's script directory (`~/.config/libreoffice/4/user/Scripts/python/`).
  - `share`: Shared script directory (eg. `/usr/lib/libreoffice/share/Scripts/python/`).
  - `application`: Application-specific location (rarely used).

*NOTE*: `application` doesn't mean you can specify a full path to your
 script; it is some LO internal stuff; thus, either user or shared
 location.

And to use LibreOffice _completely_ from outside; an example:

``` shell
$ libreoffice --headless --accept="socket,host=localhost,port=2002;urp;" &
$ cat > /tmp/in.py <<EOF
import uno
import unohelper

def connect_to_libreoffice():
    # Create a local context
    local_context = uno.getComponentContext()

    # Get the UnoUrlResolver
    resolver = local_context.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local_context
    )

    # Connect to the running LibreOffice instance
    context = resolver.resolve("uno:socket,host=localhost,port=2002;urp;StarOffice.ComponentContext")
    return context

if __name__ == "__main__":
    try:
        # Connect to LibreOffice
        context = connect_to_libreoffice()
        smgr = context.ServiceManager
        desktop = smgr.createInstanceWithContext("com.sun.star.frame.Desktop", context)

        print("Successfully connected to LibreOffice!")
    except Exception as e:
        print("Error connecting to LibreOffice:", e)
EOF

$ env PYTHONPATH=/usr/lib/libreoffice/program python3 /tmp/in.py
Successfully connected to LibreOffice!
```


### scribus

Fonts, dictionaries and hyphenations can be "imported" into Scribus via: Windows - Resource Manager. See:

``` shell
$ ls -1 .local/share/scribus/{dicts/{hyph,spell}/,downloads,fonts}
.local/share/scribus/dicts/hyph/:
hyph_cs_CZ.dic
README_cs.txt

.local/share/scribus/dicts/spell/:
cs_CZ.aff
cs_CZ.dic

.local/share/scribus/downloads:
cs_CZ.aff
cs_CZ.dic
hyph_cs_CZ.dic
hyph_pl_PL.dic
pl_PL.aff
pl_PL.dic
README_cs.txt
README_pl.txt
scribus_fonts.xml
scribus_fonts.xml.sha256
scribus_help.xml
scribus_help.xml.sha256
scribus_hyph_dicts.xml
scribus_hyph_dicts.xml.sha256
scribus_palettes.xml
scribus_palettes.xml.sha256
scribus_spell_dicts.xml
scribus_spell_dicts.xml.sha256

.local/share/scribus/fonts:
```

Hm, Resource Manager could not download spellcheck dicts and hyphenation data, so I did:

``` shell
$ curl -Ls 'https://download.documentfoundation.org/libreoffice/src/24.8.1/libreoffice-dictionaries-24.8.1.2.tar.xz?idx=2' | \
    bsdtar --strip-components 3 -xf - -C ~/.local/share/scribus/dicts/spell 'libreoffice*/cs_CZ/cs_CZ*'
$ curl -Ls 'https://download.documentfoundation.org/libreoffice/src/24.8.1/libreoffice-dictionaries-24.8.1.2.tar.xz?idx=2' | \
    bsdtar --strip-components 3 -xf - -C ~/.local/share/scribus/dicts/hyph 'libreoffice*/cs_CZ/hyph_cs_CZ*'
```

Scribus uses unicode character U+00AD (soft hyphen) as a hyphenation
character in its _sla_ format.

``` shell
$ tac /tmp/out.sla | grep -m1 -Po 'ITEXT.*CH="\K[^"]+' | xxd -a
00000000: 5465 c2ad 7a65 0a                        Te..ze.
```

However, if you explictly insert a soft hyphen (Insert - Character -
Soft Hyphen), it doubles that unicode character.

``` shell
$ tac /tmp/out.sla | grep -m1 -Po 'ITEXT.*CH="\K[^"]+'
Te­­ze

s tac /tmp/out.sla | grep -m1 -Po 'ITEXT.*CH="\K[^"]+' | xxd -a
00000000: 5465 c2ad c2ad 7a65 0a                   Te....ze.
```

So, this might help if one prefers to hyphenate the text herself via
Scribus python API, for example.

To view a PDF inside Scribus, ie. a PDF image, one needs 'PostScript
Interpreter'; that is, _ghostscript_: see, File -> Preferences ->
External Tools.

Similarly, to view printed PDF, one needs 'PDF Viewer',
eg. `SumatraPDF.exe` on Windows: again, see External Tools in
Preferences.


#### styles

Language of a style in Scribus seem to work this way:

- in the general Preferences, there's 'Document Setup - Language':
  this influences document language of the future documents, that is,
  of documents to be created. That is: if 'French' is in 'Preferences -
  Document Setup - Language', then after new document creation, the
  'Default Paragraph Style' would use 'Default Character Style'
  'French' language.
  
- once a document is opened, its text language by default is
  determined by the setting of the document creation; that is, even if
  you update 'Document Setup' language, the styles would still have
  the original language value; the only way to influence default
  language of a newly created text frame, is to update existing
  'Default Character Style' language


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

### linux CPU flags

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


### supermicro

OMG, supermicro! Anyway, how to generate a license for IPMI to be able to update
their crappy BIOS? See https://techblog.jeppson.org/2018/12/generate-supermicro-ipmi-license/ .

``` shell
$ echo -n 'XX:XX:XX:XX:XX:XX | \
    xxd -r -p | \
    openssl dgst -sha1 -mac HMAC -macopt hexkey:8544E3B47ECA58F9583043F8 | \
    awk '{ printf $2 }' | \
    cut -c 1-24 | \
    sed -r 's/(....)/\1-/g;s/-$//'
yyyy-yyyy-yyyy-yyyy-yyyy-yyyy
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


### analysis

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


## mail

### mailx

Sending mail with authentication via a relay.

``` shell
$ man mailx | sed -rn '/smtp[[:blank:]]+Normally,/,/^ *$/p' | fmt -w72
       smtp   Normally, mailx invokes sendmail(8) directly to transfer
       messages.  If the smtp variable is set, a SMTP connection to the
       server specified by the value of this variable is used instead.
       If the SMTP server  does
              not use the standard port, a value of server:port can
              be given, with port as a name or as a number.
```
That is, define something like the following...

``` shell
$ cat $HOME/.mailrc
set name="Server1234"
set from="username@example.com.com"
set smtp=smtps://smtp.example.com.com
set smtp-auth=login
set smtp-auth-user=username@example.com
set smtp-auth-password=mysecretpassword
set ssl-verify=ignore
```


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

`mbsync` does not have native proxy support but it does have `Tunnel`
option, which can be used as a way to proxy IMAP connection - that is,
`Tunnel` expects stdin/stdout communication:

```shell
Tunnel "socat -d0 STDIN\!\!STDOUT SOCKS4A:127.0.0.1:imap.gmail.com:993,socksport=9050"
```

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

### postfix

- null client, submission and forwards somewhere else, NO local delivery


### troubleshooting

Comparing two Postfix configurations

``` shell
$ sdiff -s <(postconf -n -c /tmp/postfix-data | sort) <(postconf -n -c /etc/postfix | sort) | sed -e '/config_directory/d'
mydestination = $myhostname, localhost.$mydomain              | mydestination = $myhostname, localhost.$mydomain, localhost
myhostname = myrelay.example.com                              | myhostname = 192
relay_domains = $mydestination, lmdb:/etc/postfix/relay       | relay_domains = $mydestination lmdb:/etc/postfix/relay
relayhost = mysmtp.example.com:25                             | relayhost =
                                                              > smtpd_sasl_auth_enable = no
                                                              > smtpd_sasl_path = smtpd
                                                              > smtpd_sasl_type = cyrus
                                                              > smtpd_tls_exclude_ciphers = RC4
smtp_sasl_auth_enable = yes                                   | smtp_sasl_auth_enable = no
smtp_sasl_password_maps = lmdb:/etc/postfix/sasl_passwd       | smtp_sasl_password_maps =
smtp_sasl_security_options = noanonymous                      | smtp_sasl_security_options =
virtual_alias_domains = lmdb:/etc/postfix/virtual

# or an alternative

$ bash -c "comm -23 <(postconf -n -c /tmp/postfix-data | sort) <(postconf -n -c /etc/postfix | sort)" | sed -e '/config_directory/d'
mydestination = $myhostname, localhost.$mydomain
myhostname = mysmtp.example.com
relay_domains = $mydestination, lmdb:/etc/postfix/relay
relayhost = myrelay.example.com:25
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = lmdb:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
virtual_alias_domains = lmdb:/etc/postfix/virtual
```

Comparing actual Postfix configuration with built-in defaults

``` shell
$ bash -c "comm -23 <(postconf -n | sort) <(postconf -d | sort)"
alias_maps = lmdb:/etc/aliases
biff = no
canonical_maps = lmdb:/etc/postfix/canonical
compatibility_level = 2
daemon_directory = /usr/lib/postfix/bin/
debugger_command = PATH=/bin:/usr/bin:/usr/local/bin:/usr/X11R6/bin ddd $daemon_directory/$process_name $process_id & sleep 5
delay_warning_time = 1h
disable_vrfy_command = yes
html_directory = /usr/share/doc/packages/postfix-doc/html
inet_interfaces = localhost
mailbox_size_limit = 0
manpage_directory = /usr/share/man
masquerade_exceptions = root
message_size_limit = 0
message_strip_characters = \0
myhostname = 192
mynetworks_style = subnet
readme_directory = /usr/share/doc/packages/postfix-doc/README_FILES
relay_domains = $mydestination lmdb:/etc/postfix/relay
relocated_maps = lmdb:/etc/postfix/relocated
sample_directory = /usr/share/doc/packages/postfix-doc/samples
sender_canonical_maps = lmdb:/etc/postfix/sender_canonical
setgid_group = maildrop
smtpd_banner = $myhostname ESMTP
smtpd_recipient_restrictions = permit_mynetworks,reject_unauth_destination
smtpd_sender_restrictions = lmdb:/etc/postfix/access
smtpd_tls_exclude_ciphers = RC4
smtpd_tls_key_file =
smtp_sasl_security_options =
smtp_tls_key_file =
transport_maps = lmdb:/etc/postfix/transport
virtual_alias_maps = lmdb:/etc/postfix/virtual
```


## monitoring and logging

### rsyslog

`rsyslog` is ..., but anyway, TLS client fowarding:

``` shell
global(
  DefaultNetstreamDriverCAFile="<path>"
  DefaultNetstreamDriverCertFile="<path>"
  DefaultNetstreamDriverKeyFile="<path>"
)

# Set up the action for all messages
*.* action(
  type="omfwd"
  StreamDriver="gtls"
  StreamDriverMode="1"
  StreamDriverAuthMode="anon"
  target="127.0.0.1" port="12345" protocol="tcp"
))
```

Since 8.2108.0, one should be able to define TLS settings in _omfwd_ module directly:

``` shell
  StreamDriver.CAFile="<path>"
  StreamDriver.KeyFile="<path>"
  StreamDriver.CertFile="<path>"
```

#### rsyslog & SLES

``` shell
$ systemctl stop rsyslog.service syslog.socket
$ ls -l /dev/log
lrwxrwxrwx 1 root root 28 Nov 30 15:47 /dev/log -> /run/systemd/journal/dev-log

$ pgrep -c rsyslogd
0

$ rsyslogd -iNONE -d -n 2>&1 | tee /tmp/rsyslogd.out.txt
...

$ lsof -np $(pgrep rsyslogd) | grep -P 'unix\b.*DGRAM'
rsyslogd 27268 root    4u  unix 0xffff997cf9256a80      0t0      63700 /run/systemd/journal/syslog type=DGRAM
rsyslogd 27268 root    6u  unix 0xffff997cf9257740      0t0      63702 type=DGRAM
```


### vector

**NOTE**: as of Dec 21 2022, _vector_ can't write to datagram-oriented
unix sockets (SOCK_DGRAM), so eg. using a sink for a rsyslog unix
socket won't work!

> Vector is a high-performance observability data pipeline that puts
> organizations in control of their observability data. Collect,
> transform, and route all your logs, metrics, and traces to any
> vendors...

Vector is written in Rust...

A primitive configuration could be something like this:

``` shell
$ cat vector.toml
[sources.my_source_id]
type = "syslog"
address = "127.0.0.1:12345"
mode = "tcp"
tls.key_file = "<path>"
tls.crt_file = "<path>"
tls.ca_file = "<path>"
tls.enabled = true

[sinks.my_sink_id]
type = "console"
inputs = [ "my_source_id" ]
target = "stdout"
encoding.codec = "text"

$ vector -c vector.toml
2022-10-04T14:00:18.142247Z  INFO vector::app: Log level is enabled. level="vector=info,codec=info,vrl=info,file_source=info,tower_limit=trace,rdkafka=info,buffers=info,kube=info"
2022-10-04T14:00:18.142319Z  INFO vector::app: Loading configs. paths=["vector.toml"]
2022-10-04T14:00:18.146363Z  INFO vector::topology::running: Running healthchecks.
2022-10-04T14:00:18.146482Z  INFO vector::topology::builder: Healthcheck: Passed.
2022-10-04T14:00:18.146493Z  INFO vector: Vector has started. debug="false" version="0.24.1" arch="x86_64" build_id="8935681 2022-09-12"
2022-10-04T14:00:18.146516Z  INFO vector::app: API is disabled, enable by setting `api.enabled` to `true` and use commands like `vector top`.
2022-10-04T14:00:18.149903Z  INFO source{component_kind="source" component_id=my_source_id component_type=syslog component_name=my_source_id}: vector::sources::util::tcp: Listening. addr=127.0.0.1:12345
```


### sar

To get a graphical output from `sar` files, one can:

``` shell
$ sadf -O showtoc,showinfo -g -- -A <sa file> > /tmp/out.svg
```

Reading `sar` files is `TZ` dependent:

``` shell
$ ag --nofilename --nocolor --nogroup '^2024-06-30T.*Linux version' | grep -Pv '^\s*(#|$)' | sort -u | cut -c1-80
2024-06-30T14:36:48.584469+08:00 example01 kernel: [    0.000000][    T0] Linux ve
2024-06-30T16:09:14.103268+08:00 example01 kernel: [    0.000000][    T0] Linux ve
2024-06-30T16:25:42.728050+08:00 example01 kernel: [    0.000000][    T0] Linux ve
2024-06-30T16:59:41.364945+08:00 example01 kernel: [    0.000000][    T0] Linux ve
2024-06-30T17:16:39.920318+08:00 example01 kernel: [    0.000000][    T0] Linux ve
2024-06-30T17:26:30.210241+08:00 example02 kernel: [    0.000000][    T0] Linux ve

$ TZ=Asia/Taipei LC_TIME=POSIX sar -n UDP -f scc_example01_240701_1645/sar/sa20240630 | grep RESTART
14:36:48     LINUX RESTART      (8 CPU)
16:09:14     LINUX RESTART      (8 CPU)
16:25:42     LINUX RESTART      (8 CPU)
16:59:41     LINUX RESTART      (8 CPU)
17:16:39     LINUX RESTART      (8 CPU)

## versus ##

$ LC_TIME=POSIX sar -n UDP -f scc_example01_240701_1645/sar/sa20240630 | grep RESTART
08:36:48     LINUX RESTART      (8 CPU)
10:09:14     LINUX RESTART      (8 CPU)
10:25:42     LINUX RESTART      (8 CPU)
10:59:41     LINUX RESTART      (8 CPU)
11:16:39     LINUX RESTART      (8 CPU)
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

PCAP file stats:

``` shell
$ rpm -qf $(which capinfos)
wireshark-3.6.7-1.1.x86_64

$ capinfos dump_POP_2022.08.09-10.55.52.pcap.1.gz
capinfos: An error occurred after reading 3281218 packets from "dump_POP_2022.08.09-10.55.52.pcap.1.gz".
capinfos: The file "dump_POP_2022.08.09-10.55.52.pcap.1.gz" appears to have been cut short in the middle of a packet.
  (will continue anyway, checksums might be incorrect)
File name:           dump_POP_2022.08.09-10.55.52.pcap.1.gz
File type:           Wireshark/tcpdump/... - pcap (gzip compressed)
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: 262144 bytes
Number of packets:   3,281 k
File size:           90 MB
Data size:           4,447 MB
Capture duration:    3565.325831 seconds
First packet time:   2022-08-09 10:56:01.894982
Last packet time:    2022-08-09 11:55:27.220813
Data byte rate:      1,247 kBps
Data bit rate:       9,979 kbps
Average packet size: 1355.49 bytes
Average packet rate: 920 packets/s
SHA256:              e927a3d417d0befaa77bce2d543af824226dfb3ac63dad725152d2fa5388ce1d
RIPEMD160:           cd25d25a49582a54ecaad577a94fcc5b4a5e7590
SHA1:                42ad5963c9074adb147f8ea2523dd08bba562131
Strict time order:   False
Number of interfaces in file: 1
Interface #0 info:
                     Encapsulation = Ethernet (1 - ether)
                     Capture length = 262144
                     Time precision = microseconds (6)
                     Time ticks per second = 1000000
                     Number of stat entries = 0
                     Number of packets = 3281218
```

An example for fields and display filter:

``` shell
$ tshark -r /tmp/latest-dump.pcap -Y nbns -T fields -e frame.time -e ip.src -e ip.dst -e ip.proto -e _ws.col.Info -e nbns.netbios_name
Oct 26, 2022 11:53:07.995874000 CEST    193.197.33.232  193.197.33.36   17      Name query NB DLAN<1c>
Oct 26, 2022 11:53:07.996368000 CEST    193.197.33.36   193.197.33.232  17      Name query response NB 193.197.33.248
Oct 26, 2022 11:53:09.196091000 CEST    193.197.33.232  193.197.33.36   17      Name query NB UNIVERS<20>
Oct 26, 2022 11:53:09.196555000 CEST    193.197.33.36   193.197.33.232  17      Name query response NB 193.197.33.248
```

Protocols...

``` shell
$ tshark -G protocols | grep -P '\bnbns\b'
NetBIOS Name Service    NBNS    nbns
```

``` shell
$ tshark -r /tmp/w10qe01.pcap -Y 'nbns and frame.number==174' -O nbns
Frame 174: 104 bytes on wire (832 bits), 104 bytes captured (832 bits)
Ethernet II, Src: RealtekU_67:87:7d (52:54:00:67:87:7d), Dst: RealtekU_1a:54:5d (52:54:00:1a:54:5d)
Internet Protocol Version 4, Src: 192.168.122.11, Dst: 192.168.122.248
User Datagram Protocol, Src Port: 137, Dst Port: 137
NetBIOS Name Service
    Transaction ID: 0xb5a4
    Flags: 0x8580, Response, Opcode: Name query, Authoritative, Recursion desired, Recursion available, Reply code: No error
        1... .... .... .... = Response: Message is a response
        .000 0... .... .... = Opcode: Name query (0)
        .... .1.. .... .... = Authoritative: Server is an authority for domain
        .... ..0. .... .... = Truncated: Message is not truncated
        .... ...1 .... .... = Recursion desired: Do query recursively
        .... .... 1... .... = Recursion available: Server can do recursive queries
        .... .... ...0 .... = Broadcast: Not a broadcast packet
        .... .... .... 0000 = Reply code: No error (0)
    Questions: 0
    Answer RRs: 1
    Authority RRs: 0
    Additional RRs: 0
    Answers
        EXAMPLE<1b>: type NB, class IN
            Name: EXAMPLE<1b> (Domain Master Browser)
            Type: NB (32)
            Class: IN (1)
            Time to live: 3 days
            Data length: 6
            Name flags: 0x6000, ONT: Unknown (H-node, unique)
                0... .... .... .... = Name type: Unique name
                .11. .... .... .... = ONT: Unknown (3)
            Addr: 192.168.122.11
```

Raw data from GELF:

``` shell
$ tshark -c1 -i eth0 -f 'udp and host 1.2.3.4 and port 12201' -T fields -e data.data 2>/dev/null | tr -d '\n',':' | xxd -r -ps | zcat | jq '.'
{
  "version": "1.1",
  "host": "jb155sapqe02",
  "short_message": "Hello from Docker!",
  "timestamp": 1695712531.719,
  "level": 6,
  "_command": "/hello",
  "_container_id": "6b8c8c3beb8b3eb0ad50cd5b303f4295b808257e182f7622f12deb228f56f1f7",
  "_container_name": "naughty_khorana",
  "_created": "2023-09-26T07:15:31.306166382Z",
  "_image_id": "sha256:9c7a54a9a43cca047013b82af109fe963fde787f63f9e016fdc3384500c2823d",
  "_image_name": "hello-world",
  "_tag": "6b8c8c3beb8b"
}
```


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

##### tips and tricks

To recreate a packet from a captured PCAP file for issue reproduction in Wireshark, do:

- select packet to recreate
- right-click, select "Copy" > "Bytes" > "Hex Stream"; and save into a file

Or, it seems one can use `tshark -x -r <pcap> frame.number == 2593 > <out file>`.

TODO: The following is very generic, the MAC addresses etc. should be changed.

``` shell
#!/usr/bin/env python3

from scapy.all import *

# Load the hex stream file into a string
with open("/tmp/input-packet.txt", "r") as f:
    hex_stream = f.read().strip()

# Convert the hex stream string into a Scapy packet
packet = Raw(hex_stream))

# Send the packet
send(packet)
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


### SSH

Capturing SSH handshake.


``` shell
$ tshark -i eth0 -f 'port 22 and not host 192.168.0.1' -Y 'ssh.message_code == 20' -O ssh
Capturing on 'eth0'
 ** (tshark:13759) 17:29:25.282458 [Main MESSAGE] -- Capture started.
 ** (tshark:13759) 17:29:25.282559 [Main MESSAGE] -- File: "/tmp/wireshark_eth0N896Z1.pcapng"
Frame 8: 1602 bytes on wire (12816 bits), 1602 bytes captured (12816 bits) on interface eth0, id 0
Ethernet II, Src: RealtekU_3b:d8:6d (52:54:00:3b:d8:6d), Dst: RealtekU_d2:63:30 (52:54:00:d2:63:30)
Internet Protocol Version 4, Src: 192.168.0.187, Dst: 192.168.0.57
Transmission Control Protocol, Src Port: 65218, Dst Port: 22, Seq: 22, Ack: 22, Len: 1536
SSH Protocol
    SSH Version 2
        Packet Length: 1532
        Padding Length: 6
        Key Exchange
            Message Code: Key Exchange Init (20)
            Algorithms
                Cookie: 2c8b82f936d02ceea31d34643295efe9
                kex_algorithms length: 269
                kex_algorithms string [truncated]: curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,di
                server_host_key_algorithms length: 500
                server_host_key_algorithms string [truncated]: ssh-ed25519-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-
                encryption_algorithms_client_to_server length: 108
                encryption_algorithms_client_to_server string: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
                encryption_algorithms_server_to_client length: 108
                encryption_algorithms_server_to_client string: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
                mac_algorithms_client_to_server length: 213
                mac_algorithms_client_to_server string [truncated]: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-
                mac_algorithms_server_to_client length: 213
                mac_algorithms_server_to_client string [truncated]: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-
                compression_algorithms_client_to_server length: 26
                compression_algorithms_client_to_server string: none,zlib@openssh.com,zlib
                compression_algorithms_server_to_client length: 26
                compression_algorithms_server_to_client string: none,zlib@openssh.com,zlib
                languages_client_to_server length: 0
                languages_client_to_server string:
                languages_server_to_client length: 0
                languages_server_to_client string:
                First KEX Packet Follows: 0
                Reserved: 00000000
                [hasshAlgorithms [truncated]: curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-h]
                [hassh: ec7378c1a92f5a8dde7e8b7a1ddf33d1]
        Padding String: 000000000000
    [Direction: client-to-server]

Frame 10: 1146 bytes on wire (9168 bits), 1146 bytes captured (9168 bits) on interface eth0, id 0
Ethernet II, Src: RealtekU_d2:63:30 (52:54:00:d2:63:30), Dst: RealtekU_3b:d8:6d (52:54:00:3b:d8:6d)
Internet Protocol Version 4, Src: 192.168.0.57, Dst: 192.168.0.187
Transmission Control Protocol, Src Port: 22, Dst Port: 65218, Seq: 22, Ack: 1558, Len: 1080
SSH Protocol
    SSH Version 2
        Packet Length: 1076
        Padding Length: 6
        Key Exchange
            Message Code: Key Exchange Init (20)
            Algorithms
                Cookie: 701e5cdd774938f24c7d07186ceae1a6
                kex_algorithms length: 258
                kex_algorithms string [truncated]: curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,di
                server_host_key_algorithms length: 65
                server_host_key_algorithms string: rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519
                encryption_algorithms_client_to_server length: 108
                encryption_algorithms_client_to_server string: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
                encryption_algorithms_server_to_client length: 108
                encryption_algorithms_server_to_client string: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
                mac_algorithms_client_to_server length: 213
                mac_algorithms_client_to_server string [truncated]: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-
                mac_algorithms_server_to_client length: 213
                mac_algorithms_server_to_client string [truncated]: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-
                compression_algorithms_client_to_server length: 21
                compression_algorithms_client_to_server string: none,zlib@openssh.com
                compression_algorithms_server_to_client length: 21
                compression_algorithms_server_to_client string: none,zlib@openssh.com
                languages_client_to_server length: 0
                languages_client_to_server string:
                languages_server_to_client length: 0
                languages_server_to_client string:
                First KEX Packet Follows: 0
                Reserved: 00000000
                [hasshServerAlgorithms [truncated]: curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,di]
                [hasshServer: b12d2871a1189eff20364cf5333619ee]
        Padding String: 000000000000
    [Direction: server-to-client]
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

### fc / fcoe / fibre channel

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

### lvm

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

#### SLES

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


### SLE Micro

SLE Micro as libvirt domain/VM:


#### ignition

Note, that *ignition* needs to match `ignition.platform.id` and
provided that, that is, if you would have `ignition.platform.id=metal`
and would in fact use QEMU sysinfo, it won't work!

``` shell
$ for i in /var/lib/libvirt/images/iso/SUSE-Manager-Server.x86_64-5.0.0*; do \
    echo '#' image: $i ; virt-cat -a $i /boot/grub2/grub.cfg | grep -Po -m1 'ignition.platform.id=\S+'; \
  done
# image: /var/lib/libvirt/images/iso/SUSE-Manager-Server.x86_64-5.0.0-Qcow-GM.qcow2
ignition.platform.id=qemu
# image: /var/lib/libvirt/images/iso/SUSE-Manager-Server.x86_64-5.0.0-Raw-GM.raw
ignition.platform.id=metal

$ virsh dumpxml jbelka-jbmrt55qe01 | xmllint --xpath '//sysinfo' -
<sysinfo type="fwcfg">
    <entry name="opt/com.coreos/config" file="/var/lib/libvirt/images/jbelka/jbmrt55qe01.config.ign"/>
    <entry name="opt/org.opensuse.combustion/script" file="/var/lib/libvirt/images/jbelka/jbmrt55qe01.combustion.sh"/>
  </sysinfo>
```

[*Ignition*](https://coreos.github.io/butane/config-fcos-v1_5/) config
can be generated, eg. https://opensuse.github.io/fuel-ignition.

``` shell
$ cat jbm155qe01.config.ign
{
  "ignition": {
    "version": "3.2.0"
  },
  "passwd": {
    "users": [
      {
        "name": "root",
        "passwordHash": "$2a$10$UQcdA3i2uB5p/XNeDzYfCemxBW1hdDfj6yCgRqDENHxxhbsB7DqRW",
        "sshAuthorizedKeys": [
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE1x+93H1K9QT62tvFbO3M8Ze5JvjtDB4QeslJJx60xi"
        ]
      }
    ]
  },
  "storage": {
    "Files": [
      {
        "path": "/etc/hostname",
        "mode": 420,
        "overwrite": true,
        "contents": {
          "source": "data:,jbm55qe01"
        }
      },
      {
        "path": "/etc/NetworkManager/system-connections/eth0.nmconnection",
        "mode": 384,
        "overwrite": true,
        "contents": {
          "source": "data:text/plain;charset=utf-8;base64,Cltjb25uZWN0aW9uXQppZD1ldGgwCnR5cGU9ZXRoZXJuZXQKaW50ZXJmYWNlLW5hbWU9ZXRoMAoKW2lwdjRdCmRucy1zZWFyY2g9Cm1ldGhvZD1hdXRvCgpbaXB2Nl0KZG5zLXNlYXJjaD0KYWRkci1nZW4tbW9kZT1ldWk2NAptZXRob2Q9aWdub3JlCg==",
          "human_read": "\n[connection]\nid=eth0\ntype=ethernet\ninterface-name=eth0\n\n[ipv4]\ndns-search=\nmethod=auto\n\n[ipv6]\ndns-search=\naddr-gen-mode=eui64\nmethod=ignore\n"
        }
      },
      {
        "path": "/etc/NetworkManager/conf.d/noauto.conf",
        "mode": 420,
        "overwrite": true,
        "contents": {
          "source": "data:text/plain;charset=utf-8;base64,W21haW5dCiMgRG8gbm90IGRvIGF1dG9tYXRpYyAoREhDUC9TTEFBQykgY29uZmlndXJhdGlvbiBvbiBldGhlcm5ldCBkZXZpY2VzCiMgd2l0aCBubyBvdGhlciBtYXRjaGluZyBjb25uZWN0aW9ucy4Kbm8tYXV0by1kZWZhdWx0PSoK",
          "human_read": "[main]\n# Do not do automatic (DHCP/SLAAC) configuration on ethernet devices\n# with no other matching connections.\nno-auto-default=*\n"
        }
      }
    ]
  }
}

```

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


#### YaST

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


#### zypper


##### installing

To run `zypper` non-interactively do:

``` shell
$ zypper --non-interactive install --auto-agree-with-licenses -y <package>
```

##### repos

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

##### zypper/rpm signing keys

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


## printing


### cups

SUSE has an awesome reading about
[CUPS](https://en.opensuse.org/SDB:CUPS_in_a_Nutshell#The_Filter_.28includes_the_Driver.29).

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

CUPS does convertion via filters; an example:

``` shell
$ grep -m1 -P '^<.*Printer \w+>$' /etc/cups/printers.conf
<DefaultPrinter hp>

$ grep -P '(cupsFilter|PCFileName)' /etc/cups/ppd/hp.ppd
*cupsFilter: "application/vnd.cups-postscript 0 hpps"
*PCFileName: "HPCM3530.PPD"
```

A different PPD:

``` shell
$ grep -iP '(DeviceID|JCLTo|NickName|PCFileName|filter)' CM353PDF.PPD
*% PDF mode, using CUPS with the OpenPrinting CUPS Filters package
*PCFileName:    "CM353PDF.PPD"
*ShortNickName: "HP Color LaserJet CM3530 MFP"
*NickName:      "HP Color LaserJet CM3530 MFP PDF"
*1284DeviceID: "MFG:Hewlett-Packard;CMD:PJL,BIDI-ECP,PCLXL,PCL,PDF,PJL,POSTSCRIPT;MDL:HP Color LaserJet CM3530 MFP;CLS:PRINTER;DES:Hewlett-Packard Color LaserJet CM3530 MFP;DRV:DPDF,R0,M0;"
*JCLToPDFInterpreter: "@PJL ENTER LANGUAGE = PDF <0A>"
*cupsFilter: "application/vnd.cups-pdf 0 -"
*cupsFilter2: "application/pdf application/vnd.cups-pdf 0 pdftopdf"
```


#### tips

- https://access.redhat.com/solutions/305283

#### troubleshooting

When a printer in unreachable, one can see the following

```
E [05/Jun/2024:13:50:46 -0400] [Job 1026332] The printer is not responding.
E [05/Jun/2024:13:53:26 -0400] [Job 1026332] The printer is not responding.
```

However, to correlate the printer which "is not responding" in
historical data, that is, how to find out which printer was not
reachable while it is reachable now and the jobs are already all
printed, the historical logs are needed because the printer name for
the job is *only* logged when such a job is created:

``` shell
I [26/Jun/2024:18:08:04 +0200] [Job 36] Queued on "testovic" by "root".
...
D [26/Jun/2024:18:08:04 +0200] [Job 36] Sending job to queue tagged as raw...
D [26/Jun/2024:18:08:04 +0200] [Job 36] job-sheets=none,none
D [26/Jun/2024:18:08:04 +0200] [Job 36] argv[0]="testovic"
D [26/Jun/2024:18:08:04 +0200] [Job 36] argv[1]="36"
D [26/Jun/2024:18:08:04 +0200] [Job 36] argv[2]="root"
D [26/Jun/2024:18:08:04 +0200] [Job 36] argv[3]="fstab"
D [26/Jun/2024:18:08:04 +0200] [Job 36] argv[4]="1"
D [26/Jun/2024:18:08:04 +0200] [Job 36] argv[5]="finishings=3 number-up=1 print-color-mode=monochrome job-uuid=urn:uuid:5d24d8bc-ea58-3dd1-423e-537915e2c4e6 job-originating-host-name=localhost date-time-at-creation= date-time-at-processing
= time-at-creation=1719418084 time-at-processing=1719418084 document-name-supplied=fstab"
D [26/Jun/2024:18:08:04 +0200] [Job 36] argv[6]="/var/spool/cups/d00036-001"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[0]="CUPS_CACHEDIR=/var/cache/cups"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[1]="CUPS_DATADIR=/usr/share/cups"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[2]="CUPS_DOCROOT=/usr/share/cups/doc-root"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[3]="CUPS_REQUESTROOT=/var/spool/cups"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[4]="CUPS_SERVERBIN=/usr/lib/cups"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[5]="CUPS_SERVERROOT=/etc/cups"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[6]="CUPS_STATEDIR=/run/cups"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[7]="HOME=/var/spool/cups/tmp"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[8]="PATH=/usr/lib/cups/filter:/usr/bin:/usr/sbin:/bin:/usr/bin"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[9]="SERVER_ADMIN=root@t14s"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[10]="SOFTWARE=CUPS/2.4.10"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[11]="TMPDIR=/var/spool/cups/tmp"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[12]="USER=root"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[13]="CUPS_MAX_MESSAGE=2047"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[14]="CUPS_SERVER=/run/cups/cups.sock"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[15]="CUPS_ENCRYPTION=IfRequested"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[16]="IPP_PORT=631"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[17]="CHARSET=utf-8"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[18]="LANG=en_US.UTF-8"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[19]="PPD=/etc/cups/ppd/testovic.ppd"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[20]="CONTENT_TYPE=text/plain"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[21]="DEVICE_URI=socket://127.0.0.1:5170"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[22]="PRINTER_INFO=testovic"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[23]="PRINTER_LOCATION=test room"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[24]="PRINTER=testovic"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[25]="PRINTER_STATE_REASONS=none"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[26]="CUPS_FILETYPE=document"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[27]="AUTH_I****"
```

That is, without old job data or old logs where one can see creation
of a job, it is impossible to know what printer was not reachable.

If the old data exist, one might get it from *control file*:

``` shell
$ strings /var/spool/cups/*36 | grep '^ipp'
ipp://t14s/printers/testovic!
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

CUPS can cancel "stuck" jobs, ie. those expiring *MaxJobTime*

``` shell
$ lpstat -o testovic
$ grep -P 'Job 39.*Canceling stuck' /var/log/cups/error_log
I [27/Jun/2024:16:04:02 +0200] [Job 39] Canceling stuck job after 120 seconds.

$ ./cups-2.4.7/cups/testipp /var/spool/cups/c00039 | grep 'job-state '
    job-state (enum): canceled

# compare succesful jobs with all jobs but not-completed

$ grep -F -x -v -f <(lpstat -W successful -o testovic) \
    <<< "$(grep -F -x -v -f <(lpstat -W not-completed -o testovic) <(lpstat -W all -o testovic))"
testovic-38             root              2048   Thu 27 Jun 2024 03:47:37 PM CEST
testovic-39             root              2048   Thu 27 Jun 2024 04:02:01 PM CEST

$ lp -i 39 -H restart

$ ps auxww | grep -P '[s]ocket.*\b39\b'
lp         33000  0.0  0.0  14896  6908 ?        S    16:06   0:00 socket://127.0.0.1:5170 39 root fstab 1 finishings=3 number-up=1 print-color-mode=monochrome job-uuid=urn:uuid:23f8c77f-76f3-3a77-5e2c-2e447740790f job-originating-host-name=localhost date-time-at-completed= date-time-at-creation= date-time-at-processing= time-at-completed=1719497042 time-at-creation=1719496921 time-at-processing=1719497167 document-name-supplied=fstab /var/spool/cups/d00039-001

$ lpstat -o testovic
testovic-39             root              2048   Thu 27 Jun 2024 04:02:01 PM CEST
```


### TeX

Terminology as I understand it sofar (that is, it might be inappropriate):

- TeX: typesetting (low-level - instructions - or primitives ??? -
  working with "boxes", internally, everything is a box: a letter,
  word, line, paragraph...)  system, or programming language, by
  Donald Knuth
  
- TeX engines: adaptations/modifications of TeX (pdfTeX, XeTeX,
  LuaTeX...); apart from LuaTex, they do not affect the language
  itself, mostly handling input/output files, etc...

- TeX formats: collection of TeX commands, macros (eg. Plain TeX -
  from Knuth himself, LaTeX, ConTeXt - but not only that) and programs
  that load large macros collections into format files (predumped
  memory images of TeX) before calling the actual "`tex`" engine

- ConTeXt: macros, a format, a collection of tools/scripts, an
  interface; that is, it is more an eco-system; it differs from LaTeX
  in philosofy: unlike LaTeX, it does not limit flexibility due to
  simplifying the use of TeX or isolating the user from typesetting
  details, that is, it gives the user absolute and complete control
  over typesetting.


#### ConTeXt

``` shell
$ mkdir -p ~/.local/stow/context2025
$ ln -s context2025 ~/.local/stow/context
$ cd $_
$ curl -Ls https://lmtx.pragma-ade.com/install-lmtx/context-linux-64.zip | bsdtar -xvf -
x bin/
x bin/mtxrun
x bin/mtx-install.lua
x bin/mtxrun.lua
x install.sh
x installation.pdf

$ bash ./install.sh
```


#### texlive

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



### hashicorp vault

**NOTE:** Sharing publicly Vault token, keys is stupid but this is a test instance!!!

By default `init` would create 5 keys with 3 keys required to unseal.

``` shell
$ vault operator init
Unseal Key 1: <key1>
Unseal Key 2: <key2>
Unseal Key 3: <key3>
Unseal Key 4: <key4>
Unseal Key 5: <key5>

Initial Root Token: <token>

Vault initialized with 5 key shares and a key threshold of 3. Please securely
distribute the key shares printed above. When the Vault is re-sealed,
restarted, or stopped, you must supply at least 3 of these keys to unseal it
before it can start servicing requests.

Vault does not store the generated root key. Without at least 3 keys to
reconstruct the root key, Vault will remain permanently sealed!

It is possible to generate new unseal keys, provided you have a quorum of
existing unseal keys shares. See "vault operator rekey" for more information.
```

1. use 'key' to unseal (here one key is enough to unseal!!!)

``` shell
$ export VAULT_ADDR=https://avocado.example.com:8200
$ export VAULT_TOKEN=<token>

$ vault status
Key                Value
---                -----
Seal Type          shamir
Initialized        true
Sealed             true <---+--- !!!
Total Shares       1
Threshold          1
Unseal Progress    0/1
Unseal Nonce       n/a
Version            1.12.3
Build Date         2023-02-02T09:07:27Z
Storage Type       file
HA Enabled         false

$ vault operator unseal
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false
Total Shares    1
Threshold       1
Version         1.12.3
Build Date      2023-02-02T09:07:27Z
Storage Type    file
Cluster Name    vault-cluster-3904eff6
Cluster ID      45238404-cc0a-f9d1-a65e-07b57d32034f
HA Enabled      false

$ vault status
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false <---+--- !!!
Total Shares    1
Threshold       1
Version         1.12.3
Build Date      2023-02-02T09:07:27Z
Storage Type    file
Cluster Name    vault-cluster-3904eff6
Cluster ID      45238404-cc0a-f9d1-a65e-07b57d32034f
HA Enabled      false
```

2. you can login via browser with 'root.token'

``` shell
$ export VAULT_ADDR=https://avocado.example.com:8200
$ export VAULT_TOKEN=<token>
```

#### pki secrets engine

``` shell
$ vault secrets list
Path          Type         Accessor              Description
----          ----         --------              -----------
cubbyhole/    cubbyhole    cubbyhole_ea287431    per-token private secret storage
identity/     identity     identity_0dc45c85     identity store
sys/          system       system_0378cabc       system endpoints used for control, policy and debugging

$ vault secrets enable -description=hashiCorpVaultCA pki
Success! Enabled the pki secrets engine at: pki/

$ vault secrets list
Path          Type         Accessor              Description
----          ----         --------              -----------
cubbyhole/    cubbyhole    cubbyhole_ea287431    per-token private secret storage
identity/     identity     identity_0dc45c85     identity store
pki/          pki          pki_65e37d8e          hashiCorpVaultCA <---+--- !!!
sys/          system       system_0378cabc       system endpoints used for control, policy and debugging
```

Importing existing CA cert and key into Vault:

``` shell
$ jq -n --arg v "$(cat ca.crt ca.key)" '{"pem_bundle": $v }' > payload.json

$ curl -s -H "X-Vault-Token: <token>" -X POST --data "@payload.json" https://avocado.example.com:8200/v1/pki/config/ca
```

Creating a role which allows issuing of certs:

``` shell
$ vault write pki/roles/example-dot-com allowed_domains="*example.com" allow_glob_domains=true allow_subdomains=true     max_ttl=72h
Success! Data written to: pki/roles/example-dot-com
```

Issue/request a cert (note that role should be linked to a user/group
in production).

``` shell
$ vault write pki/issue/example-dot-com \
  common_name=jb154sapqe01.example.com \
  alt_names="jb154sapqe01.example.com,example.com,*.example.com"
WARNING! The following warnings were returned from Vault:

  * TTL "768h0m0s" is longer than permitted maxTTL "72h0m0s", so maxTTL is
  being used

Key                 Value
---                 -----
ca_chain            [-----BEGIN CERTIFICATE-----
MIIFxjCCA66gAwIBAgIUCWy6A27QQO8sdQcFz+S4Or2iD9YwDQYJKoZIhvcNAQEL
BQAwezELMAkGA1UEBhMCQ1oxDzANBgNVBAgMBlByYWd1ZTEPMA0GA1UEBwwGUHJh
Z3VlMSMwIQYDVQQKDBphdm9jYWRvIEhhc2hpQ29ycCBWYXVsdCBDQTElMCMGA1UE
AwwcYXZvY2Fkb0hhc2hpQ29ycFZhdWx0Q0EgMjAyMzAeFw0yMzAyMjExMTA4MzNa
Fw0yMzAzMjMxMTA4MzNaMHsxCzAJBgNVBAYTAkNaMQ8wDQYDVQQIDAZQcmFndWUx
DzANBgNVBAcMBlByYWd1ZTEjMCEGA1UECgwaYXZvY2FkbyBIYXNoaUNvcnAgVmF1
bHQgQ0ExJTAjBgNVBAMMHGF2b2NhZG9IYXNoaUNvcnBWYXVsdENBIDIwMjMwggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQClI0POCUzvpkGWo/RbNJEkYi/0
WifzjQI5bpfa9TyjyVuQHkCKRMv2iyNSxxGCeNCuMoSVitxC/rpEvQf9SvhVcAfT
vu8MPg2ptWn4ACjsmxYBe5N3RGSEPXmMwc8XTY+ZIdgcF9PuvIcqz8A1uN+C1Qpc
pxm8HsuAOp/HFJMZ8uFRO6/akAmBbZwQi/8X6aXY8hMMtF638RdxJDQS6I30cEvX
q57gsNCX68fQOiNmZw1K2Ra8soEldfG7BXJruKkCaUbfGeqsEmShld+FMYGiDJuJ
ti1FdGdyCshxHEFlK90WCUYKKrjxn0zBcQmkfD5qhyOSDu9GJ07kHhmI9zme4NTC
SOMmK6HEhBCATsGo3ckxcg7BefcwhFjXIlWhsXXIAW1LakTT62M/K3SrrD/3u+Ad
egIceirlbx5i+7aBdg+obnp3R8ZSCNwB5t3nIbj4wPivsBQKmf60O+kXvk9psXK0
w6xjPLH4HuWHO4IE6lNeGfvuIlBMuIupoVyqH+G0LRvTOaSQ1aY3dZwmzh2luopE
E1NWWWtluEYmC8uF9cpUm4z9n0D45ULSZ+BXwHFEAvC09xdKSOrdghicOvhOfIGA
4V0eOGhXeqGlG1PsoPDpGrV7tIAJxRHYz4F6kcKU7Tnv6yX95bNCN6sEO7K1ZDza
gBDvkYIieTSzSSFZDwIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/
BAUwAwEB/zAdBgNVHQ4EFgQU7zH1WVWqWYutUhYK0zxMAPCNBvEwDQYJKoZIhvcN
AQELBQADggIBABgxIgH/biVsxN+7fBl+5ar/uW5yeLAomaVz7/762MX8yifY9qP5
IhAQRF8HPv6YkPoBOJROtmE4oZmbmGth1cDqIZEIaKzTu7Pum/CR48lYkheOD4Jx
R4U4fhJv7Un1/gkpuNEJ7LmBaIdXwg2LLLD1yUa7v19lZIcMZ/nA+fTA4L0SXHo+
tUxP9Yzyk+j2X+DHvdSctdUYlXNNz8leY+g8Zw/Q4BDfm2e6cohjnQ0h/zOA1Drl
ZHs4oLjkngu55/kwuq55kv5A7+lKf4Vq00jEzgueD8Gr5XQ8MnWgn9GvohqQxn+t
WNcn/gZLIHgyfyMwXOBKYULg32HQjzaeRgjm5Le9znI5TK6jTTUz0fGbkQWkGgYF
l9Qm9q0wwUmnDHL2PA/Rlm/upS2Fb9/U/oY7tD6CUIvfeGwBMssgLFyp3ap6Uj8D
ObgOw5wUvS0A9XauZmY2DEwdqYdHGentx0Fl3s+bazApKCdkmwYl6j6EiHYlqKPw
GGiEfAVoXhbRkt/m2oiNReTGYDaHoqI8PfyhVV5pQctEXt3GWNPzXG/02XUcpL3H
NeGsb39wF0PfwSuy/37ZgvTWNR74FTLm4ZJ4LVMVJ52O9GhKt8SGpfFzJJGge0ZX
GVmyR4YFKBSOJ4If53xIFBUCfa4uiyrqw4VbvgEd2l9uZYQgmz0Re1yI
-----END CERTIFICATE-----]
certificate         -----BEGIN CERTIFICATE-----
MIIFaDCCA1CgAwIBAgIUaeDqKZV2JPw9OBLqwdgD8PamcDUwDQYJKoZIhvcNAQEL
BQAwezELMAkGA1UEBhMCQ1oxDzANBgNVBAgMBlByYWd1ZTEPMA0GA1UEBwwGUHJh
Z3VlMSMwIQYDVQQKDBphdm9jYWRvIEhhc2hpQ29ycCBWYXVsdCBDQTElMCMGA1UE
AwwcYXZvY2Fkb0hhc2hpQ29ycFZhdWx0Q0EgMjAyMzAeFw0yMzAyMjExMjA5MTda
Fw0yMzAyMjQxMjA5NDdaMCMxITAfBgNVBAMTGGpiMTU0c2FwcWUwMS5leGFtcGxl
LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANxqYVrxnoz1G/fP
Nm6tw+Aql8nh0MkUe8ZOAlXqze69bGZr4iJnsNnhVtFBXQEhqQxUVv8uYMgvtFyJ
/UXcg+yWp6DgPnwpkSAxe51mKaoVMogHO8dPxJIApWqGqttKBhmlOmdvzbnQynqF
6d6X0Rdy91edFrnxwuG9o1vu0E4Oo/nMCGg40xqQkOPi2DFhX/6EzFrTEyNqTo20
mObKu9id/2M7+his2zDvpCtBW1BaKS5x58A+9QkVY4B+4U8/DqkJUNiEc2VqrSnD
Gd3pwAJYvakw+oDZAbmSMosejPzwDXkP89+9dBK0yhLelo2tF+Lk+VXnKTsu5xUh
IJxEkUMCAwEAAaOCATowggE2MA4GA1UdDwEB/wQEAwIDqDAdBgNVHSUEFjAUBggr
BgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFE01xwNbCr6lKv5OyeDjDaTy2WLo
MB8GA1UdIwQYMBaAFO8x9VlVqlmLrVIWCtM8TADwjQbxMEYGCCsGAQUFBwEBBDow
ODA2BggrBgEFBQcwAoYqaHR0cHM6Ly9hdm9jYWRvLmV4YW1wbGUuY29tOjgyMDAv
djEvcGtpL2NhMD8GA1UdEQQ4MDaCDSouZXhhbXBsZS5jb22CC2V4YW1wbGUuY29t
ghhqYjE1NHNhcHFlMDEuZXhhbXBsZS5jb20wPAYDVR0fBDUwMzAxoC+gLYYraHR0
cHM6Ly9hdm9jYWRvLmV4YW1wbGUuY29tOjgyMDAvdjEvcGtpL2NybDANBgkqhkiG
9w0BAQsFAAOCAgEAlbzAd4fI1XT2hfjobf4dbjvfLaKNfh9/WQ3dGJ9W3QHQfw89
GELAu7Uw+VFqME6HVEKue3fKf8TwL4+GuwTX24WvOS57y4+u3xFm3rAmDs9ar5tM
xerwuq9YxqUabpNktXXaZYBNiusiAuZUh/U40UzGa5vHRZa7kpOLumFFQMqKBMRI
rekqFETjJTScSDXOCS2NMZZp+2pt8G5bC+rFtKGbdc/c/BXtBZYrWVFEK4Fm9Jq9
yIL2LmGuJbcHNZN/Dpo8rcFr5uYFubLwilKRj3ecWBB1T6JtefSy9MXAeqaTeMyz
b9uRzlM2NLbwXM6y8yDvVq6tQulw/6oEaElpc9byYf10mV/FIJH/sZzTrBM9L2cC
GJIGVbIqGlFenA6nFehOfocgCNJrwlSe/cq/akd/ZzPwBKE12JtufcXs5jYs2Wlx
QdstthGk4hp90ugGwEHYoIGaZqDlOhyniK1RCsFEXA9gY37saEPdBltcltMqw7qd
1i8ngqQEadSzEyDEGGvlUbR2F9YZZaJyPk+42qlx5rtox3igwilILV/qf8s2Wibv
QvTsxYUgKA1A+w0pFcdNQmZD9tb+cvlC+QEijrXp799R/mXO6VpYuqcOj/jXx1na
ZzAjS0/g+XheiOki72DUlxPN6YlRKDxxthTFViohKAEYsf+KHcgBotfHLoI=
-----END CERTIFICATE-----
expiration          1677240587
issuing_ca          -----BEGIN CERTIFICATE-----
MIIFxjCCA66gAwIBAgIUCWy6A27QQO8sdQcFz+S4Or2iD9YwDQYJKoZIhvcNAQEL
BQAwezELMAkGA1UEBhMCQ1oxDzANBgNVBAgMBlByYWd1ZTEPMA0GA1UEBwwGUHJh
Z3VlMSMwIQYDVQQKDBphdm9jYWRvIEhhc2hpQ29ycCBWYXVsdCBDQTElMCMGA1UE
AwwcYXZvY2Fkb0hhc2hpQ29ycFZhdWx0Q0EgMjAyMzAeFw0yMzAyMjExMTA4MzNa
Fw0yMzAzMjMxMTA4MzNaMHsxCzAJBgNVBAYTAkNaMQ8wDQYDVQQIDAZQcmFndWUx
DzANBgNVBAcMBlByYWd1ZTEjMCEGA1UECgwaYXZvY2FkbyBIYXNoaUNvcnAgVmF1
bHQgQ0ExJTAjBgNVBAMMHGF2b2NhZG9IYXNoaUNvcnBWYXVsdENBIDIwMjMwggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQClI0POCUzvpkGWo/RbNJEkYi/0
WifzjQI5bpfa9TyjyVuQHkCKRMv2iyNSxxGCeNCuMoSVitxC/rpEvQf9SvhVcAfT
vu8MPg2ptWn4ACjsmxYBe5N3RGSEPXmMwc8XTY+ZIdgcF9PuvIcqz8A1uN+C1Qpc
pxm8HsuAOp/HFJMZ8uFRO6/akAmBbZwQi/8X6aXY8hMMtF638RdxJDQS6I30cEvX
q57gsNCX68fQOiNmZw1K2Ra8soEldfG7BXJruKkCaUbfGeqsEmShld+FMYGiDJuJ
ti1FdGdyCshxHEFlK90WCUYKKrjxn0zBcQmkfD5qhyOSDu9GJ07kHhmI9zme4NTC
SOMmK6HEhBCATsGo3ckxcg7BefcwhFjXIlWhsXXIAW1LakTT62M/K3SrrD/3u+Ad
egIceirlbx5i+7aBdg+obnp3R8ZSCNwB5t3nIbj4wPivsBQKmf60O+kXvk9psXK0
w6xjPLH4HuWHO4IE6lNeGfvuIlBMuIupoVyqH+G0LRvTOaSQ1aY3dZwmzh2luopE
E1NWWWtluEYmC8uF9cpUm4z9n0D45ULSZ+BXwHFEAvC09xdKSOrdghicOvhOfIGA
4V0eOGhXeqGlG1PsoPDpGrV7tIAJxRHYz4F6kcKU7Tnv6yX95bNCN6sEO7K1ZDza
gBDvkYIieTSzSSFZDwIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/
BAUwAwEB/zAdBgNVHQ4EFgQU7zH1WVWqWYutUhYK0zxMAPCNBvEwDQYJKoZIhvcN
BAUwAwEB/zAdBgNVHQ4EFgQU7zH1WVWqWYutUhYK0zxMAPCNBvEwDQYJKoZIhvcN
AQELBQADggIBABgxIgH/biVsxN+7fBl+5ar/uW5yeLAomaVz7/762MX8yifY9qP5
IhAQRF8HPv6YkPoBOJROtmE4oZmbmGth1cDqIZEIaKzTu7Pum/CR48lYkheOD4Jx
R4U4fhJv7Un1/gkpuNEJ7LmBaIdXwg2LLLD1yUa7v19lZIcMZ/nA+fTA4L0SXHo+
tUxP9Yzyk+j2X+DHvdSctdUYlXNNz8leY+g8Zw/Q4BDfm2e6cohjnQ0h/zOA1Drl
ZHs4oLjkngu55/kwuq55kv5A7+lKf4Vq00jEzgueD8Gr5XQ8MnWgn9GvohqQxn+t
l9Qm9q0wwUmnDHL2PA/Rlm/upS2Fb9/U/oY7tD6CUIvfeGwBMssgLFyp3ap6Uj8D
ObgOw5wUvS0A9XauZmY2DEwdqYdHGentx0Fl3s+bazApKCdkmwYl6j6EiHYlqKPw
GGiEfAVoXhbRkt/m2oiNReTGYDaHoqI8PfyhVV5pQctEXt3GWNPzXG/02XUcpL3H
NeGsb39wF0PfwSuy/37ZgvTWNR74FTLm4ZJ4LVMVJ52O9GhKt8SGpfFzJJGge0ZX
GVmyR4YFKBSOJ4If53xIFBUCfa4uiyrqw4VbvgEd2l9uZYQgmz0Re1yI
-----END CERTIFICATE-----
private_key         -----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3GphWvGejPUb9882bq3D4CqXyeHQyRR7xk4CVerN7r1sZmvi
Imew2eFW0UFdASGpDFRW/y5gyC+0XIn9RdyD7JanoOA+fCmRIDF7nWYpqhUyiAc7
x0/EkgClaoaq20oGGaU6Z2/NudDKeoXp3pfRF3L3V50WufHC4b2jW+7QTg6j+cwI
aDjTGpCQ4+LYMWFf/oTMWtMTI2pOjbSY5sq72J3/Yzv6GKzbMO+kK0FbUFopLnHn
wD71CRVjgH7hTz8OqQlQ2IRzZWqtKcMZ3enAAli9qTD6gNkBuZIyix6M/PANeQ/z
3710ErTKEt6Wja0X4uT5VecpOy7nFSEgnESRQwIDAQABAoIBAQCLTEfeu9ih6L4W
LMSPyg2CfCiVk7rpeaKHvwFG3y/qc5gwWnn9mF5yNDEz6gUnE+jMO/kHKH5NxahM
24BPSH+vY77osw+KVJK9L8iZvtkR/neC9F9ZJRZr1zCzVAxirjOQvZVdjZEMn+F2
8W7OGFAya5vZqROVzC6Hj9vP2+uViArbOE0Uq9rqQXhSWGPEJgKcZ5d5t9+9eiHB
auZ6K/YtF3laBGDSQScYSrhsU/OrTun/J81iKykKZvxhnUXwBVAYKFJt4s1pT2F+
AwZLEFbtVG/ITp4zj0WUjRZPVyyOykQWscH9r7HKhz7gzlosgZIFicQjH74y6QEG
O7nTuythAoGBAPGKXpePJo+eTa3xwXIge37OtySIRdUCMSsn1N2s3hbXFVJphTze
VFm4U1Prl7iioVVkMrvpcuJJJrH/gjBTcOBy+yyRZYZWeEU7dNtAmGU59TEvMaYb
yNuStWUc8uydVQ1NNp96LicM03XCNd8uIWsDA3gAWU8EfpLpgsbMC737AoGBAOmc
RNSdIrtoAqOH82Zb/0QaZDkECjk9EA1vESqvjmvDs9PxYjduuQSlNojYxfTQl0gg
UrMTuZjnBSmIcYAiXcyE8g1YbpocNMikC5aH6mfjZzzvsP1tuDZyGsEdianBmsKn
NUKMvHYvsZRZR6uZeXaP+cX8agHnO3LYO9bn0H9ZAoGAZqlIISTP3/UJ0SfS774M
n04fG2DsRWfkHBKW8A08a/rI7jk5TzC0K1oj2KRm3SwKZG/s/F9x2+n5j2gpHn8o
l81nIn895oY0IkDuHw5qd4PVyizj7lUa3vCRNsPCIH2Sm8+4qrnUifZynjeIjC5g
N8qVG9kSHHqtjaXAVtx9FScCgYAmkKCgRMyOCY6d9nyNAlTypjSzYOJbLqRuw04f
MNofGjCepXOkWQf8J1YIY1jSoHjI9GUSoQf7oO+uOpMaJxI7CBt5bobbtBpWoRY0
pH1i5xyM57jdLXbCrjWSedDXEFn/FmFpehhGnnr/VXnKb0yo8P233IKXi9e5js7a
HGzECQKBgCUi3Gf60N6Ryi0AnroTU8AdKOnajMcMqoYxxLFcRiO7K8RnUDVifszy
fNfyjluHMo3Rj5iErDbORW4WKkjjdRaHq4HjZmU/wq0rjM1ABFgCENi9aZoHezU+
gVTmNlEl3qjYpCc96OvuMo83aI7laGg+mSa5EASBqhray00jfq7x
-----END RSA PRIVATE KEY-----
private_key_type    rsa
serial_number       69:e0:ea:29:95:76:24:fc:3d:38:12:ea:c1:d8:03:f0:f6:a6:70:35
```

**NEVER** leak private key, the above is just a test!!!

Same can be done via `curl`:

``` shell
$ curl -s -H "X-Vault-Token: <token>" -X POST \
  -d '{"common_name": "jb154sapqe01.example.com", "alt_names": "jb154sapqe01.example.com,example.com,*.example.com"}' \
  https://avocado.example.com:8200/v1/pki/issue/example-dot-com | \
  jq '.'
```

And parsing output from `curl` to make things easier:

``` shell
$ curl -s -H "X-Vault-Token: <token>"  -X POST \
  -d '{ "common_name": "jb154sapqe01.example.com", "alt_names": "jb154sapqe01.example.com,example.com,*.example.com"}' \
  https://avocado.example.com:8200/v1/pki/issue/example-dot-com | \
  tee >(jq -r .data.certificate > cert.pem) >(jq -r .data.private_key > key.pem) >(jq -r .data.ca_chain[] > chained.pem)

$ file *.pem
cert.pem:    PEM certificate
chained.pem: PEM certificate
key.pem:     PEM RSA private key

$ openssl x509 -in cert.pem -subject -ext subjectAltName -noout
subject=CN = jb154sapqe01.example.com
X509v3 Subject Alternative Name:
    DNS:*.example.com, DNS:example.com, DNS:jb154sapqe01.example.com
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


### pgp / gnupg


### generating a new key

``` shell
$ gpg --full-gen-key
```


#### revoketing a key

``` shell
$ gpg --list-secret-keys | grep -B 1 '<email>'
      40F509939F782D3AE9BCA37DB970A976D18403BF
uid           [ultimate] XXXX XXXX <email>

$ gpg --output ~/tmp/revoke-<email> --gen-revoke 40F509939F782D3AE9BCA37DB970A976D18403BF

sec  ed25519/B970A976D18403BF 2021-12-28 XXXX XXXX <email>

Create a revocation certificate for this key? (y/N) y
Please select the reason for the revocation:
  0 = No reason specified
  1 = Key has been compromised
  2 = Key is superseded
  3 = Key is no longer used
  Q = Cancel
(Probably you want to select 1 here)
Your decision? 3
Enter an optional description; end it with an empty line:
>
Reason for revocation: Key is no longer used
(No description given)
Is this okay? (y/N) y
ASCII armored output forced.
Revocation certificate created.

Please move it to a medium which you can hide away; if Mallory gets
access to this certificate he can use it to make your key unusable.
It is smart to print this certificate and store it away, just in case
your media become unreadable.  But have some caution:  The print system of
your machine might store the data and make it available to others!

$ file revoke-<email>
revoke-<email>: PGP public key block Signature (old)

$ gpg --import revoke-<email>
gpg: key B970A976D18403BF: "XXXX XXXX <email>" revocation certificate imported
gpg: Total number processed: 1
gpg:    new key revocations: 1
gpg: public key of ultimately trusted key D4FB86F50CE03FD3 not found
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   4  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 4u
gpg: next trustdb check due at 2023-09-17

$ gpg --list-key <email>
pub   ed25519 2021-12-28 [SC] [revoked: 2023-02-15]
      40F509939F782D3AE9BCA37DB970A976D18403BF
uid           [ revoked] XXXX XXXX <email>
```

But that does not automatically changes the key on a keyserver!!!

You can use below to download a key without importing into default key DB:

``` shell
$ export GNUPGHOME=$(mktemp -d)

$ gpg --recv-keys 40F509939F782D3AE9BCA37DB970A976D18403BF
gpg: keybox '/tmp/tmp.Nx99oojTkK/pubring.kbx' created
gpg: /tmp/tmp.Nx99oojTkK/trustdb.gpg: trustdb created
gpg: key B970A976D18403BF: public key "XXXX XXXX <email>" imported
gpg: Total number processed: 1
gpg:               imported: 1

$ gpg --list-keys
/tmp/tmp.Nx99oojTkK/pubring.kbx
-------------------------------
pub   ed25519 2021-12-28 [SC] [expires: 2023-12-28]
      40F509939F782D3AE9BCA37DB970A976D18403BF
uid           [ unknown] XXXX XXXX <email>
sub   cv25519 2021-12-28 [E] [expires: 2023-12-28]
```

Thus, sending the key again.

``` shell
$ gpg --send-keys 40F509939F782D3AE9BCA37DB970A976D18403BF
gpg: sending key 40F509939F782D3AE9BCA37DB970A976D18403BF to hkp://keyserver.ubuntu.com
```

Validation that the keyserver has the revoked key:

``` shell
$ export GNUPGHOME=$(mktemp -d)

$ gpg --verbose --search-keys 40F509939F782D3AE9BCA37DB970A976D18403BF
gpg: keybox '/tmp/tmp.e5QpFUYpgq/pubring.kbx' created
gpg: no running dirmngr - starting '/usr/bin/dirmngr'
gpg: waiting for the dirmngr to come up ... (5s)
gpg: connection to the dirmngr established
gpg: data source: https://162.213.33.8:443
(1)     XXXX XXXX <email>
          263 bit EDDSA key B970A976D18403BF, created: 2021-12-28
Keys 1-1 of 1 for "40F509939F782D3AE9BCA37DB970A976D18403BF".  Enter number(s), N)ext, or Q)uit > 1
gpg: data source: https://162.213.33.8:443
gpg: armor header: Comment: Hostname:
gpg: armor header: Version: Hockeypuck 2.1.0-189-g15ebf24
gpg: pub  ed25519/B970A976D18403BF 2021-12-28  XXXX XXXX <email>
gpg: Note: signature key B970A976D18403BF has been revoked
gpg: Note: signature key B970A976D18403BF has been revoked
gpg: Note: signature key B970A976D18403BF has been revoked
gpg: Note: signature key B970A976D18403BF has been revoked
gpg: Note: signature key B970A976D18403BF has been revoked
gpg: Note: signature key B970A976D18403BF has been revoked
gpg: Note: signature key B970A976D18403BF has been revoked
gpg: Note: signature key B970A976D18403BF has been revoked
gpg: Note: signature key B970A976D18403BF has been revoked
gpg: Note: signature key B970A976D18403BF has been revoked
gpg: Note: signature key B970A976D18403BF has been revoked
gpg: /tmp/tmp.e5QpFUYpgq/trustdb.gpg: trustdb created
gpg: using pgp trust model
gpg: key B970A976D18403BF: public key "XXXX XXXX <email>" imported
gpg: no running gpg-agent - starting '/usr/bin/gpg-agent'
gpg: waiting for the agent to come up ... (5s)
gpg: connection to the agent established
gpg: Total number processed: 1
gpg:               imported: 1

$ gpg --list-keys
/tmp/tmp.e5QpFUYpgq/pubring.kbx
-------------------------------
pub   ed25519 2021-12-28 [SC] [revoked: 2023-02-15]
      40F509939F782D3AE9BCA37DB970A976D18403BF
uid           [ revoked] XXXX XXXX <email>
```


#### gnupg tips

``` shell
$ gpg --list-keys

$ gpg --verbose --search-keys <value>

$ gpg --recv-keys <value>

# public key

$ gpg --armor --export

# secret key
$ gpg --export-secret-keys <value>
```


Where are the keys located?

``` shell
gpg --list-secret-keys --with-keygrip jirib79@gmail.com
sec   rsa2048 2021-09-17 [SCEA]
      F178D4D326B55EB03F8A23A55B9E7F688216D470
      Keygrip = 533E713DA4C40370164DB8C00E9F7BF158860754
uid           [ultimate] Jiří Bělka <jirib79@gmail.com>
ssb   rsa2048 2021-09-17 [SEA]
      Keygrip = D1D82AE03624312E06E5FAC166818CED5CF9F7BC

$ find .gnupg/private-keys-v1.d/ | grep D1D8
.gnupg/private-keys-v1.d/D1D82AE03624312E06E5FAC166818CED5CF9F7BC.key
```


#### hockeypuck PGP server

It's written in Golang, for a test purpose (after cloning the repo);
[they tell you to mirror keydump pgp
files](https://github.com/hockeypuck/hockeypuck#quick-start-with-docker-compose-for-testing),
it was 33GB, so I gave up. Here is a workaround:

How does it start?

``` shell
$ cd ~/tmp/hockeypuck/contrib/docker-compose/devel
$  docker run --rm -t -i --entrypoint=/bin/cat devel-hockeypuck /hockeypuck/bin/startup.sh | grep pgp
  if ! ls $keydump/*.pgp >/dev/null 2>&1
    $bin/hockeypuck-load -config $config $keydump/\*.pgp || exit 1
  find $keydump -name "*.pgp" -newer $timestamp -print0 | \
```

So it wants a PGP file there:

``` shell
$ gpg --export 1F3FF65CAACE78999CFE4510E5B7D78BB970380F > keydump/<email>.pgp
$ docker-compose up -d
[+] Running 2/2
 ⠿ Container devel-postgres-1    Started                                                                                                                                                                                                 0.5s
 ⠿ Container devel-hockeypuck-1  Started                                                                                                                                                                                                 1.1s

$ gpg --verbose --keyserver hkp://127.0.0.1:11371 --search-keys <email>
gpg: searching for "<email>" from hkp server 127.0.0.1
(1)     XXXX XXXX <email>
          263 bit unknown key B970380F, created: 2023-02-15
Keys 1-1 of 1 for "<email>".  Enter number(s), N)ext, or Q)uit >
```

Voila!


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


### sudo

Environment variables for commands, see
https://unix.stackexchange.com/questions/13240/etc-sudoers-specify-env-keep-for-one-command-only.

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

and here we can see syntax error (double backslash) found:

```
Oct  5 10:43:06 sudo[77046] sudo_get_grlist: user foobar@int.example.com is a member of group domain users@int.example.com
Oct  5 10:43:06 sudo[77046] sudo_get_grlist: user foobar@int.example.com is a member of group nict-linuxserversadmins@int.example.com
Oct  5 10:43:06 sudo[77046] sudo_get_grlist: user foobar@int.example.com is a member of group nict-rdptemporaryusers@int.example.com
...
Oct  5 10:43:06 sudo[77046] sudo_getgrgid: gid 292601238 [] -> group nict-linuxserversadmins@int.example.com [] (cached)
Oct  5 10:43:06 sudo[77046] sudo_get_grlist: user foobar@int.example.com is a member of group nict-linuxserversadmins@int.example.com
Oct  5 10:43:06 sudo[77046] user_in_group: user foobar@int.example.com NOT in group EXAMPLE\\nict-linuxserversadmins
Oct  5 10:43:06 sudo[77046] user foobar@int.example.com matches group EXAMPLE\\nict-linuxserversadmins: false @ usergr_matches() ./match.c:1071
Oct  5 10:44:11 sudo[77056] sudo_getgrgid: gid 292601238 [] -> group nict-linuxserversadmins@int.example.com [] (cached)
Oct  5 10:44:11 sudo[77056] sudo_get_grlist: user foobar@int.example.com is a member of group nict-linuxserversadmins@int.example.com
Oct  5 10:44:11 sudo[77056] user_in_group: user foobar@int.example.com NOT in group EXAMPLE\\nict-linuxserversadmins
Oct  5 10:44:11 sudo[77056] user foobar@int.example.com matches group EXAMPLE\\nict-linuxserversadmins: false @ usergr_matches() ./match.c:1071
Oct  5 10:44:20 sudo[77056] user_in_group: user foobar@int.example.com NOT in group EXAMPLE\\nict-linuxserversadmins
Oct  5 10:44:20 sudo[77056] user foobar@int.example.com matches group EXAMPLE\\nict-linuxserversadmins: false @ usergr_matches() ./match.c:1071
Oct  5 10:46:32 sudo[77150] user_in_group: user foobar NOT in group EXAMPLE\\nict-linuxserversadmins
Oct  5 10:46:32 sudo[77150] user foobar matches group EXAMPLE\\nict-linuxserversadmins: false @ usergr_matches() ./match.c:1071
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


### tor

Tor running via obfs4 bridge - the bridge is taken from
https://bridges.torproject.org/bridges?transport=obfs4 .

``` shell
$ grep -Pv '^\s*(#|$)' /etc/tor/torrc
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
UseBridges 1
Bridge obfs4 72.18.53.189:9112 AEE382129C10C1F6364AC05311E900485D50F4BF cert=NZQCi8tZaDjQxeQl1uni5VKU6DinIzomV3ZWOw60cTwNUPsdOCx41BYAX7/HjkRwHgJFCw iat-mode=0
```

`FascistFirewall` will make Tor to use also HTTPS (or also HTTP?) ports:

``` shell
$ grep -Pv '^\s*(#|$)' /etc/tor/torrc
FascistFirewall 1

$ # ss -tnp | grep tor
ESTAB 0      0        192.168.1.55:46554  23.111.179.98:443   users:(("tor",pid=248157,fd=11))
ESTAB 0      0           127.0.0.1:9050       127.0.0.1:45616 users:(("tor",pid=248157,fd=14))
ESTAB 0      0        192.168.1.55:35430 38.154.239.242:443   users:(("tor",pid=248157,fd=10))
```

There are more pluggable transports, like snowflake, meek etc...

``` shell
$ w3m -dump -M https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/raw/main/projects/tor-expert-bundle/pt_config.json </dev/null
{
  "recommendedDefault" : "obfs4",
  "pluggableTransports" : {
    "lyrebird" : "ClientTransportPlugin meek_lite,obfs2,obfs3,obfs4,scramblesuit,webtunnel exec ${pt_path}lyrebird${pt_extension}",
    "snowflake" : "ClientTransportPlugin snowflake exec ${pt_path}snowflake-client${pt_extension}",
    "conjure" : "ClientTransportPlugin conjure exec ${pt_path}conjure-client${pt_extension} -registerURL https://registration.refraction.network/api"
  },
  "bridges" : {
    "meek-azure" : [
      "meek_lite 192.0.2.18:80 BE776A53492E1E044A26F17306E1BC46A55A1625 url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com"
    ],
    "obfs4" : [
      "obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 cert=qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgzUKQtQ7GRqqUvs7P+tG43RtAqdhLOALP7DJQ iat-mode=1",
      "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0",
      "obfs4 85.31.186.98:443 011F2599C0E9B27EE74B353155E244813763C3E5 cert=ayq0XzCwhpdysn5o0EyDUbmSOx3X/oTEbzDMvczHOdBJKlvIdHHLJGkZARtT4dcBFArPPg iat-mode=0",
      "obfs4 85.31.186.26:443 91A6354697E6B02A386312F68D82CF86824D3606 cert=PBwr+S8JTVZo6MPdHnkTwXJPILWADLqfMGoVvhZClMq/Urndyd42BwX9YFJHZnBB3H0XCw iat-mode=0",
      "obfs4 193.11.166.194:27015 2D82C2E354D531A68469ADF7F878FA6060C6BACA cert=4TLQPJrTSaDffMK7Nbao6LC7G9OW/NHkUwIdjLSS3KYf0Nv4/nQiiI8dY2TcsQx01NniOg iat-mode=0",
      "obfs4 193.11.166.194:27020 86AC7B8D430DAC4117E9F42C9EAED18133863AAF cert=0LDeJH4JzMDtkJJrFphJCiPqKx7loozKN7VNfuukMGfHO0Z8OGdzHVkhVAOfo1mUdv9cMg iat-mode=0",
      "obfs4 193.11.166.194:27025 1AE2C08904527FEA90C4C4F8C1083EA59FBC6FAF cert=ItvYZzW5tn6v3G4UnQa6Qz04Npro6e81AP70YujmK/KXwDFPTs3aHXcHp4n8Vt6w/bv8cA iat-mode=0",
      "obfs4 209.148.46.65:443 74FAD13168806246602538555B5521A0383A1875 cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNinLmxQDpVa+7kTOa9/m+tGWT1SmSYpQ9uTBGa6Hw iat-mode=0",
      "obfs4 146.57.248.225:22 10A6CD36A537FCE513A322361547444B393989F0 cert=K1gDtDAIcUfeLqbstggjIw2rtgIKqdIhUlHp82XRqNSq/mtAjp1BIC9vHKJ2FAEpGssTPw iat-mode=0",
      "obfs4 45.145.95.6:27015 C5B7CD6946FF10C5B3E89691A7D3F2C122D2117C cert=TD7PbUO0/0k6xYHMPW3vJxICfkMZNdkRrb63Zhl5j9dW3iRGiCx0A7mPhe5T2EDzQ35+Zw iat-mode=0",
      "obfs4 51.222.13.177:80 5EDAC3B810E12B01F6FD8050D2FD3E277B289A08 cert=2uplIpLQ0q9+0qMFrK5pkaYRDOe460LL9WHBvatgkuRr/SL31wBOEupaMMJ6koRE6Ld0ew iat-mode=0"
    ],
    "snowflake" : [
      "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn",
      "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.net:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn"
    ]
  }
}
```

Snowflake bridges are taken from above JSON. `snowflace-client` log file must be in allowed by tor unit:

``` shell
$ systemctl show tor@default | grep /log/
ReadWritePaths=-/proc -/var/lib/tor -/var/log/tor -/run

$ systemd-cgls -u tor@default
Unit tor@default.service (/system.slice/system-tor.slice/tor@default.service):
├─255824 /usr/bin/tor --defaults-torrc /usr/share/tor/tor-service-defaults-torrc -f /etc/tor/torrc --RunAsDaemon 0
└─255825 /usr/bin/snowflake-client -log /var/log/tor/snowflake.log

$ grep -Pv '^\s*(#|$)' /etc/tor/torrc
UseBridges 1
ClientTransportPlugin snowflake exec /usr/bin/snowflake-client -log /var/log/tor/snowflake.log
Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn
Bridge snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.net:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn
```

Brave browser has Tor built-in:

``` shell
$ find .config/BraveSoftware/ -type f -name '*brave*'
.config/BraveSoftware/Brave-Browser/biahpgbdmdkfgndcmfiipgcebobojjkp/1.0.36/tor-0.4.8.10-linux-brave-2
.config/BraveSoftware/Brave-Browser/apfggiafobakjahnkchiecbomjgigkkn/1.0.6/tor-snowflake-brave
.config/BraveSoftware/Brave-Browser/apfggiafobakjahnkchiecbomjgigkkn/1.0.6/tor-obfs4-brave

# get ControlPort

$ ss -tnlp | grep -f <(pgrep -f 'brave.*/tor') | grep -Po '127\.0\.0\.1:\K(\d+)' | \
    xargs -I {} bash -c "echo -e 'PROTOCOLINFO\r\n' | \
    nc 127.0.0.1 {} | grep -Pq '^[0-9]{3}-' && echo {}"
43143

$ echo -e 'PROTOCOLINFO\r\n' | nc 127.0.0.1 $CONTROLPORT
250-PROTOCOLINFO 1
250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="/home/jiri/.config/BraveSoftware/Brave-Browser/tor/watch/control_auth_cookie"
250-VERSION Tor="0.4.8.10"
250 OK
514 Authentication required.

# controlport is cookie protected

$ COOKIED=$(hexdump -e '32/1 "%02x""\n"' /home/jiri/.config/BraveSoftware/Brave-Browser/tor/watch/control_auth_cookie)

$ echo -e 'AUTHENTICATE '${COOKIED}'\r\nGETCONF ClientTransportPlugin\r\nQUIT\r\n' | \
    nc 127.0.0.1 $CONTROLPORT
250 OK
250-ClientTransportPlugin=snowflake exec ../../apfggiafobakjahnkchiecbomjgigkkn/1.0.6/tor-snowflake-brave -url https://snowflake-broker.torproject.net.global.prod.fastly.net/ -front cdn.sstatic.net -ice stun:stun.l.google.com:19302,stun:stun.voip.blackberry.com:3478,stun:stun.altar.com.pl:3478,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.com:3478,stun:stun.sonetel.net:3478,stun:stun.stunprotocol.org:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478
250 ClientTransportPlugin=meek_lite,obfs2,obfs3,obfs4,scramblesuit exec ../../apfggiafobakjahnkchiecbomjgigkkn/1.0.6/tor-obfs4-brave
250 closing connection

```

Tor commands are at [Tor Specification](https://spec.torproject.org/control-spec/commands.html).


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

#### sending mail via mailx to a relay requiring authentication

See [`mailx`](#mailx) how to setup authentication in `mailx`.

Generally, Vixie Cron, allows to override default `sendmail` command
used to send mails via `-m` option.

``` shell
$ man 8 cron | col -b | grep -A1 -P '^\s+-m' | fmt -w80
       -m     This option allows you to specify a shell command to use for
       sending Cron mail output instead of using sendmail(8) This command
       must accept a fully formatted mail message (with headers) on standard
       input and send it as
              a mail message to the recipients specified in the mail headers.
              Specifying the string off (i.e., crond -m off) will disable
              the sending of mail.
```

On SLES one has to override cron's systemd service unit to add `-m`
defining a shell wrapper if specific mail commands options are
needed. See [Delivering cron and logwatch emails to gmail in RHEL
](https://web.archive.org/web/20220923100759/https://lukas.zapletalovi.com/2018/09/delivering-cron-emails-to-gmail-in-rhel.html)
for details.

#### shell in cron

By default cron runs all jobs with `/bin/sh` shell, and on SLES it means BASH
shell in Bourne Shell compatibility mode.

If BASH is used as `/bin/sh` it thus does NOT read ~/.profile which most likely
in some way includes for example `.sapenv.sh` (SAP env conf file which provides
SAP <SID> specific environment variables).

``` shell
$ man bash | grep -A 10 'When bash is started non-interactively' | fmt -w 80
       When bash is started non-interactively, to run a shell script,
       for example, it looks for the variable BASH_ENV in the environment,
       expands its value if it appears there, and uses the expanded value
       as the name of  a  file  to read and execute.  Bash behaves as if
       the following command were executed:
              if [ -n "$BASH_ENV" ]; then . "$BASH_ENV"; fi
       but the value of the PATH variable is not used to search for the
       filename.

       If  bash is invoked with the name sh, it tries to mimic the startup
       behavior of historical versions of sh as closely as possible,
       while conforming to the POSIX standard as well.  When invoked as an
       interactive login shell, or a non-interactive shell with the --login
       option, it first attempts to read and execute commands from /etc/profile
       and ~/.profile, in that order.  The --noprofile option may be used
       to inhibit this behavior.  When  invoked  as an  interactive shell
       with the name sh, bash looks for the variable ENV, expands its value
       if it is defined, and uses the expanded value as the name of a file
       to read and execute.  Since a shell invoked as sh does not attempt to
       read and execute commands from any other startup files, the --rcfile
       option has no effect.  A non-interactive shell invoked with the name
       sh does not attempt to read any other startup files.  When invoked
       as sh,  bash  en- ters posix mode after the startup files are read.
```

As for CSH, if you would use `/bin/csh` as SHELL for the cron job, it will read
`~/.cshrc` by default.

``` shell
$ man csh | grep 'Non-login' | fmt -w 80
       Non-login shells read only /etc/csh.cshrc and ~/.tcshrc or ~/.cshrc
       on startup.
```

An example which assumes these are already user cron jobs:

``` shell
SHELL=/bin/bash
ENV=/usr/sap/ABC/abcadm/.profile
* * * * * echo $- $SAPSYSTEMNAME > /tmp/bash_test
```

``` shell
# please note CSH does not know $- variable!
SHELL=/bin/csh
* * * * * echo $SAPSYSTEMNAME > /tmp/csh_test
```


## shell and utils


Various shell startup files are described at [Some differences between
BASH and TCSH](https://web.fe.up.pt/~jmcruz/etc/unix/sh-vs-csh.html)
and [Shell
Startup](https://docs.nersc.gov/environment/shell_startup/).


### awk

A block-by-block matching...

``` shell
$ cat /tmp/vhost.awk
#!/usr/bin/awk -f
BEGIN { out="" }
!/<VirtualHost/ && out == "" {
    next;
}
/<VirtualHost/ {
    out=$0;
    next;
}
/<\/VirtualHost/ {
    out=out RS $0;
    printf("%s", (out ~ lookup_pattern ? out""RS : ""));
    out="";
    next;
}
{ out=out RS $0;  next; }

$ awk -f /tmp/vhost.awk web.txt
<VirtualHost 172.25.43.81:443>
    DocumentRoot /htdocs/
    <Directory /htdocs/>
     Options Indexes
     <RequireAll>
     Require all granted
     </RequireAll>
    </Directory>
    ServerName example.com
        SSLEngine on
        Protocols h2 http/1.1
        SSLCertificateFile /etc/apache2/ssl.csr/example.com.crt
        SSLCertificateKeyFile /etc/apache2/ssl.csr/CA.key
        SSLCertificateChainFile /etc/apache2/ssl.csr/example.com.txt
    </VirtualHost>
```

And the same with here document...

``` shell
$ awk -v lookup_pattern="Protocols" -f - web.txt <<- EOD
!/<VirtualHost/ && out == "" { next; }
/<VirtualHost/ { out=\$0; next; }
/<\/VirtualHost/ { out=out RS \$0;
    printf("%s", (out ~ lookup_pattern ? out""RS : ""));
}
{ out=out RS \$0; next; }
EOD
<VirtualHost 172.25.43.81:443>
    DocumentRoot /htdocs/
    <Directory /htdocs/>
     Options Indexes
     <RequireAll>
     Require all granted
     </RequireAll>
    </Directory>
    ServerName example.com
        SSLEngine on
        Protocols h2 http/1.1
        SSLCertificateFile /etc/apache2/ssl.csr/example.com.crt
        SSLCertificateKeyFile /etc/apache2/ssl.csr/CA.key
        SSLCertificateChainFile /etc/apache2/ssl.csr/example.com.txt
    </VirtualHost>
```


### bash

- shortcuts:
  ``` shell
  >file 2>&1
  2>file
  ```
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
- creating array from stdout
  ``` shell
  mapfile -t fstab < <(cat /etc/fstab)
  ```
- looping over an array with spaces in element value
  ``` shell
  for ((i = 0; i < ${#udevblk[@]}; i++)); do
    echo ${udevblk[$i]}
  done
  ```
- bash associative array aka hash
  ``` shell
  declare -A myhash
  ```
  Cf. [Bash Associative Array Cheat Sheet](https://lzone.de/cheat-sheet/Bash%20Associative%20Array)
- how to print a character couple of times with `printf`?
  ``` shell
  $ printf -- 'x%.0s' {1..5} ; echo
  xxxxx
  $ printf -- 'x%.0s\n' {1..5} ; echo
  x
  x
  x
  x
  x
  ```
- comparing lines in two files:
  ``` shell
  grep -F -x -v -f file2 file1
  ```
- removal "accents":
  ``` shell
  iconv -f utf8 -t ascii//TRANSLIT test1
  ```


### coreutils

``` shell
$ date --date='last friday' +%d # to see date of last Friday
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

Replacing multiple blank lines with just one:

``` shell
$ sed '/^$/N;/^\n$/D' << EOF
> one
> two
>
> three
>
>
> four
>
>
>
> five
> EOF
one
two

three

four

five
```


### tar

Changing permissions of extract tar archive:

``` shell
$ curl -Ls https://github.com/zmwangx/ets/releases/download/v0.2.1/ets_0.2.1_linux_amd64.tar.gz | \
    tar -xvzf - \
    --to-command='mkdir -m <mode> -p -- "$(dirname -- "$TAR_FILENAME")" && install -m <mode> /dev/null "$TAR_FILENAME"; cat > "$TAR_FILENAME"' \
    ets

# an alternative
$ curl -Ls https://github.com/zmwangx/ets/releases/download/v0.2.1/ets_0.2.1_linux_amd64.tar.gz | \
    bash -c 'umask 244; tar -xvz --no-same-owner --no-same-permissions -f - ets'
```


### tricks

Prepending each line with a timestamp can be done nicely with moreutils's `ts`.

``` shell
$ echo -e "foo\nbar\nbaz" | ts '[%Y-%m-%d %H:%M:%S]'
[2011-12-13 22:07:03] foo
[2011-12-13 22:07:03] bar
[2011-12-13 22:07:03] baz
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


## system troubleshooting and performance

What is attached to my network interface?

``` shell
$ grep ^iff: /proc/*/fdinfo/* 2>/dev/null
/proc/26241/fdinfo/7:iff:       tun0

$ ps -eo user,pid,comm | grep '[2]6241'
nm-open+ 26241 openvpn
```


## tftp

``` shell
# for libvirt network only
$ systemctl cat tftp.socket
# /usr/lib/systemd/system/tftp.socket
[Unit]
Description=Tftp Server Activation Socket

[Socket]
ListenDatagram=69

[Install]
WantedBy=sockets.target


# /etc/systemd/system/tftp.socket.d/override.conf
[Socket]
ListenDatagram=192.168.122.1:69

# how to disable ipv6?
$ ss -tunlp | grep :69
udp   UNCONN 0      0        192.168.122.1:69         0.0.0.0:*    users:(("systemd",pid=1,fd=59))
udp   UNCONN 0      0                    *:69               *:*    users:(("systemd",pid=1,fd=58))
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

### vmware

#### esxi

A bit old boot parameters are described at [ESXi 7.0 Update 3i Build
20842708 Kernel Settings
](https://github.com/lamw/esxi-advanced-and-kernel-settings/blob/master/esxi-70u3i-kernel-settings.md).


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

#### govc

`govc` is "vSphere" CLI, written in golang.

``` shell
$ printenv | grep ^GOVC
GOVC_PASSWORD=password
GOVC_URL=https://example.com
GOVC_USERNAME=user
GOVC_INSECURE=1

$ govc about
FullName:     VMware vCenter Server 8.0.3 build-24022515
Name:         VMware vCenter Server
Vendor:       VMware, Inc.
Version:      8.0.3
Build:        24022515
OS type:      linux-x64
API type:     VirtualCenter
API version:  8.0.3.0
Product ID:   vpx
UUID:         fe57421e-0e49-4b8e-932e-a05a94ee260e

$ govc ls /Datacenter/host/
/Datacenter/host/192.168.100.3

$ govc host.info /Datacenter/host/192.168.100.3
Name:              192.168.100.3
  Path:            /Datacenter/host/192.168.100.3/192.168.100.3
  Manufacturer:    Red Hat
  Logical CPUs:    8 CPUs @ 2200MHz
  Processor type:  Intel(R) Xeon(R) Silver 4114 CPU @ 2.20GHz
  CPU usage:       123 MHz (0.7%)
  Memory:          8168MB
  Memory usage:    2655 MB (32.5%)
  Boot time:       2024-09-02 09:15:14.069137 +0000 UTC
  State:           connected

$ govc vm.info jirib-test01
Name:           jirib-test01
  Path:         /ha-datacenter/vm/jirib-test01
  UUID:         564d5d7a-57dc-7a82-55f6-563e0421f161
  Guest name:   SUSE Linux Enterprise 15 (64-bit)
  Memory:       2048MB
  CPU:          2 vCPU(s)
  Power state:  poweredOn
  Boot time:    2024-08-22 13:24:40 +0000 UTC
  IP address:
  Host:         example.com
```

``` shell
$ govc vm.info -e external=true  /Datacenter/vm/jirib-test01 | grep -m1 -Po 'guestinfo.userdata:\s*\K(.*)' | base64 -d | zcat -
#cloud-config

users:
- default
- name: jiri
  primary_group: jiri
  sudo: ALL=(ALL) NOPASSWD:ALL
  groups: sudo, wheel
  lock_passwd: true
  ssh_authorized_keys:
  - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE1x+93H1K9QT62tvFbO3M8Ze5JvjtDB4QeslJJx60xi jiri
```


#### tools & Guest OS Customization

VMware Tools are _open-vm-tools_ now.

``` shell
$ rpm -q open-vm-tools
open-vm-tools-12.4.0-150600.1.3.x86_64
```

``` shell
$ grep -Pv '^\s*(#|$)' /etc/vmware-tools/tools.conf
[powerops]
[vmsvc]
[vmtools]
[vmtray]
[desktopevents]
[logging]
log=true
deployPkg.level = debug
vmtoolsd.level = debug
[guestinfo]
[unity]
```

VMware Tools might do
vSphere [Guest OS Customization](https://knowledge.broadcom.com/external/article/311864/how-does-vsphere-guest-os-customization.html)
(GOSC).

GOSC via VMware Tools might conflict with _cloud-init_; in case of
GOSC, _cloud-init_ should provide only _user data_. And if
_cloud-init_ takes too long, VMware Tools can have increased timeout:

``` shell
$ grep cloud /etc/vmware-tools/tools.conf.example
# This "wait-cloudinit-timeout" option controls how long does guest
# customization wait for cloud-init execution done when it detects cloud-init
# Guest customization will continue executing as soon as it detects cloud-init
# If cloud-init is still running beyond this option's value in seconds, guest
# customization will continue executing regardless cloud-init execution status.
#wait-cloudinit-timeout=30

$ vmware-toolbox-cmd config set deployPkg wait-cloudinit-timeout 60
$ vmware-toolbox-cmd config get deployPkg wait-cloudinit-timeout
[deployPkg] wait-cloudinit-timeout = 60
$ grep '^wait-cloudinit-timeout' /etc/vmware-tools/tools.conf
wait-cloudinit-timeout=60
```

Interaction with _cloud-init_ requires version >= 18.4, ideally >=
23.1 (would use 'Datasource VMware').

``` shell
$ rpm -q cloud-init
cloud-init-23.3-150100.8.79.2.x86_64
```

_cloud-init_ is able to use various datasources, eg. OVF of VMware;
see how it behaves when no VM _guestinfo_ is set:

``` shell
$ vmtoolsd --cmd "info-get guestinfo.userdata"
No value found

$ DEBUG_LEVEL=1 DI_LOG=stderr /usr/lib/cloud-init/ds-identify --force
[up 350482.07s] ds-identify --force
policy loaded: mode=search report=false found=all maybe=all notfound=disabled
no datasource_list found, using default: MAAS ConfigDrive NoCloud AltCloud Azure Bigstep CloudSigma CloudStack DigitalOcean Vultr AliYun Ec2 GCE OpenNebula OpenStack OVF SmartOS Scaleway Hetzner IBMCloud Oracle Exoscale RbxCloud UpCloud VMware LXD NWCS Akamai
DMI_PRODUCT_NAME=VMware20,1
DMI_SYS_VENDOR=VMware, Inc.
DMI_PRODUCT_SERIAL=VMware-42 03 d4 64 38 b9 fa d1-5c 91 80 20 ca 47 ca a5
DMI_PRODUCT_UUID=64d40342-b938-d1fa-5c91-8020ca47caa5
PID_1_PRODUCT_NAME=unavailable
DMI_CHASSIS_ASSET_TAG=No Asset Tag
DMI_BOARD_NAME=440BX Desktop Reference Platform
FS_LABELS=BOOTFS,EFIFS,EFIFS,EFI,EFI,ROOT
ISO9660_DEVS=
KERNEL_CMDLINE=BOOT_IMAGE=/boot/vmlinuz-6.4.0-150600.21-default root=UUID=5832c91b-2e72-477f-bd2f-99382788517a rw systemd.show_status=1 console=ttyS0,115200 console=tty0 quiet
VIRT=vmware
UNAME_KERNEL_NAME=Linux
UNAME_KERNEL_RELEASE=6.4.0-150600.21-default
UNAME_KERNEL_VERSION=#1 SMP PREEMPT_DYNAMIC Thu May 16 11:09:22 UTC 2024 (36c1e09)
UNAME_MACHINE=x86_64
UNAME_NODENAME=jbelka-test2
UNAME_OPERATING_SYSTEM=GNU/Linux
DSNAME=
DSLIST=MAAS ConfigDrive NoCloud AltCloud Azure Bigstep CloudSigma CloudStack DigitalOcean Vultr AliYun Ec2 GCE OpenNebula OpenStack OVF SmartOS Scaleway Hetzner IBMCloud Oracle Exoscale RbxCloud UpCloud VMware LXD NWCS Akamai
MODE=search
ON_FOUND=all
ON_MAYBE=all
ON_NOTFOUND=disabled
pid=11335 ppid=10717
is_container=false
is_ds_enabled(IBMCloud) = true.
ec2 platform is 'Unknown'.
is_ds_enabled(IBMCloud) = true.
Running on vmware but rpctool query returned 1: No value found
No ds found [mode=search, notfound=disabled]. Disabled cloud-init [1]
[up 350482.42s] returning 1
```

Now with _cloud-init_ user data:

``` shell
$ cat > userdata.yaml <<EOF
#cloud-config

users:
- default
- name: jiri
  primary_group: jiri
  sudo: ALL=(ALL) NOPASSWD:ALL
  groups: sudo, wheel
  lock_passwd: true
  ssh_authorized_keys:
  - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE1x+93H1K9QT62tvFbO3M8Ze5JvjtDB4QeslJJx60xi jiri
EOF

$ vmtoolsd --cmd "info-set guestinfo.userdata.encoding gzip+base64"
$ vmtoolsd --cmd "info-set guestinfo.userdata $(gzip -c9 < userdata.yaml | { base64 -w0 2>/dev/null || base64; })"

$ vmtoolsd --cmd "info-get guestinfo.userdata" | base64 -d | zcat -
#cloud-config

users:
- default
- name: jiri
  primary_group: jiri
  sudo: ALL=(ALL) NOPASSWD:ALL
  groups: sudo, wheel
  lock_passwd: true
  ssh_authorized_keys:
  - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE1x+93H1K9QT62tvFbO3M8Ze5JvjtDB4QeslJJx60xi jiri


$  DEBUG_LEVEL=1 DI_LOG=stderr /usr/lib/cloud-init/ds-identify --force
[up 350912.78s] ds-identify --force
policy loaded: mode=search report=false found=all maybe=all notfound=disabled
no datasource_list found, using default: MAAS ConfigDrive NoCloud AltCloud Azure Bigstep CloudSigma CloudStack DigitalOcean Vultr AliYun Ec2 GCE OpenNebula OpenStack OVF SmartOS Scaleway Hetzner IBMCloud Oracle Exoscale RbxCloud UpCloud VMware LXD NWCS Akamai
DMI_PRODUCT_NAME=VMware20,1
DMI_SYS_VENDOR=VMware, Inc.
DMI_PRODUCT_SERIAL=VMware-42 03 d4 64 38 b9 fa d1-5c 91 80 20 ca 47 ca a5
DMI_PRODUCT_UUID=64d40342-b938-d1fa-5c91-8020ca47caa5
PID_1_PRODUCT_NAME=unavailable
DMI_CHASSIS_ASSET_TAG=No Asset Tag
DMI_BOARD_NAME=440BX Desktop Reference Platform
FS_LABELS=BOOTFS,EFIFS,EFIFS,EFI,EFI,ROOT
ISO9660_DEVS=
KERNEL_CMDLINE=BOOT_IMAGE=/boot/vmlinuz-6.4.0-150600.21-default root=UUID=5832c91b-2e72-477f-bd2f-99382788517a rw systemd.show_status=1 console=ttyS0,115200 console=tty0 quiet
VIRT=vmware
UNAME_KERNEL_NAME=Linux
UNAME_KERNEL_RELEASE=6.4.0-150600.21-default
UNAME_KERNEL_VERSION=#1 SMP PREEMPT_DYNAMIC Thu May 16 11:09:22 UTC 2024 (36c1e09)
UNAME_MACHINE=x86_64
UNAME_NODENAME=jbelka-test2
UNAME_OPERATING_SYSTEM=GNU/Linux
DSNAME=
DSLIST=MAAS ConfigDrive NoCloud AltCloud Azure Bigstep CloudSigma CloudStack DigitalOcean Vultr AliYun Ec2 GCE OpenNebula OpenStack OVF SmartOS Scaleway Hetzner IBMCloud Oracle Exoscale RbxCloud UpCloud VMware LXD NWCS Akamai
MODE=search
ON_FOUND=all
ON_MAYBE=all
ON_NOTFOUND=disabled
pid=11381 ppid=10717
is_container=false
is_ds_enabled(IBMCloud) = true.
ec2 platform is 'Unknown'.
is_ds_enabled(IBMCloud) = true.
Running on vmware but rpctool query returned 1: No value found
check for 'VMware' returned found
Found single datasource: VMware
[up 350913.15s] returning 0
```

Voila! 'VMware' datasource found!

GOSC works based on 'VM Customization Specifications' policy/profile; the policy might be something like this:

``` xml
<ConfigRoot>
  <_type>vim.CustomizationSpecItem</_type>
  <info>
    <_type>vim.CustomizationSpecInfo</_type>
    <changeVersion>1725551416</changeVersion>
    <description>jbelka test</description>
    <lastUpdateTime>2024-09-05T15:50:16Z</lastUpdateTime>
    <name>jbelka-test</name>
    <type>Linux</type>
  </info>
  <spec>
    <_type>vim.vm.customization.Specification</_type>
    <globalIPSettings>
      <_type>vim.vm.customization.GlobalIPSettings</_type>
      <dnsServerList>
        <_length>1</_length>
        <_type>string[]</_type>
        <e id="0">1.1.1.1</e>
      </dnsServerList>
      <dnsSuffixList>
        <_length>1</_length>
        <_type>string[]</_type>
        <e id="0">example.com</e>
      </dnsSuffixList>
    </globalIPSettings>
    <identity>
      <_type>vim.vm.customization.LinuxPrep</_type>
      <domain>example.com</domain>
      <hostName>
        <_type>vim.vm.customization.UnknownNameGenerator</_type>
      </hostName>
      <hwClockUTC>true</hwClockUTC>
      <scriptText/>
      <timeZone>Europe/Prague</timeZone>
    </identity>
    <nicSettingMap>
      <_length>1</_length>
      <_type>vim.vm.customization.AdapterMapping[]</_type>
      <e id="0">
        <_type>vim.vm.customization.AdapterMapping</_type>
        <adapter>
          <_type>vim.vm.customization.IPSettings</_type>
          <ip>
            <_type>vim.vm.customization.UnknownIpGenerator</_type>
          </ip>
          <primaryWINS/>
          <secondaryWINS/>
        </adapter>
      </e>
    </nicSettingMap>
    <options>
      <_type>vim.vm.customization.LinuxOptions</_type>
    </options>
  </spec>
</ConfigRoot>
```

Then, when creating new VM from template, in 'Select clone options'
part of the 'New VM' wizard, there's 'Customize the operating system'
which would ask in 'User settings' dialog customization specification,
eg. 'Computer Name', IPv4 address' etc...

The final GOSC data with _cloud-init_ user data might be the following:

``` shell
$ govc vm.info -e external=true  /Datacenter/vm/jirib-test01 | grep -P '(deployPkg|guestinfo.userdata)' | fold -w80
    tools.deployPkg.fileName:      imcf-KCr7iB
    guestinfo.userdata:            H4sIAHJE4GYCAz2OzYrCQBCE73mKBi8ra2BjVtEBD9Eom
nWjoiB4CWOmNaOjE+ZHY57e0YXtQ9P9VVFUIxfSMj+X1wM/ep7VqDTxfGB4oFYYd13pBQmcuOIeQKn4h
apHdlTSlv9UWyYJRPP54MOtJqSLZbReb2PiPie/zZq8bS24F4jCUSHzc1ZSre+MgFEWX0G6yKg1hVS8R
pad8eHKAPgQuRmFaU1HgdjFsyDdjDsvNhsH1Wc/nAY//dWm2za3yX4R/vZ22EluJxMPv1eoRZJU3a+K/
7V9AqeO4QnxAAAA
    guestinfo.userdata.encoding:   gzip+base64
```

`tools.deployPkg.filename` is, in fact, a file on the datastore, in
the same directory where the VM data are located:

``` shell
$ govc datastore.ls jirib-test01/
jirib-test01.vmsd
jirib-test01-00a5fe75.hlog
imcf-KCr7iB
jirib-test01.vmx
jirib-test01.vmdk
jirib-test01-flat.vmdk

$ govc datastore.download jirib-test01/imcf-KCr7iB /tmp/imcf-KCr7iB
[10-09-24 10:31:56] Downloading... OK

$ 7z l /tmp/imcf-KCr7iB | sed -n '/Listing/,$p' | head -n 12
Listing archive: /tmp/imcf-KCr7iB

--
Path = /tmp/imcf-KCr7iB
Type = Cab
Offset = 512
Physical Size = 628197
Method = MSZip
Blocks = 1
Volumes = 1
Volume Index = 0
ID = 0

$ 7z e -so /tmp/imcf-KCr7iB cust.cfg
[NETWORK]
NETWORKING = yes
BOOTPROTO = dhcp
HOSTNAME = jirib-test01
DOMAINNAME = example.com

[NIC-CONFIG]
NICS = NIC1

[NIC1]
MACADDR = 00:50:56:83:ab:39
PRIMARY = yes
ONBOOT = yes
IPv4_MODE = BACKWARDS_COMPATIBLE
BOOTPROTO = static
IPADDR = 192.168.100.201
NETMASK = 255.255.255.0
GATEWAY = 192.168.100.1


[DNS]
DNSFROMDHCP=no
SUFFIX|1 = example.com
NAMESERVER|1 = 1.1.1.1

[DATETIME]
TIMEZONE = Europe/Prague
UTC = yes

[CUSTOM-SOURCE]
CUSTOMIZATION_SOURCE=vcenter-clone
```

...and `toolsDeployPkg.log` extracts are the following:

``` shell
$ grep -i command /var/log/vmware-imc/toolsDeployPkg.log
[2024-09-10T14:36:14.575Z] [    info] Original deployment command: '/usr/bin/perl -I/tmp/.vmware/linux/deploy/scripts /tmp/.vmware/linux/deploy/scripts/Customize.pl /tmp/.vmware/linux/deploy/cust.cfg'.
[2024-09-10T14:36:14.575Z] [    info] Actual deployment command: '/usr/bin/perl -I/var/run/.vmware-imgcust-dh0Ta7i/scripts /var/run/.vmware-imgcust-dh0Ta7i/scripts/Customize.pl /var/run/.vmware-imgcust-dh0Ta7i/cust.cfg'.
[2024-09-10T14:36:14.594Z] [   debug] Command to exec : '/usr/bin/cloud-init'.
[2024-09-10T14:36:16.198Z] [    info] Customization command output:
[2024-09-10T14:36:16.199Z] [   debug] Command to exec : '/usr/bin/perl'.
[2024-09-10T14:36:25.136Z] [    info] Customization command output:
2024-09-10T14:36:16 DEBUG: Command: 'cat /etc/issue'
2024-09-10T14:36:16 DEBUG: Command: 'cat /etc/issue'
2024-09-10T14:36:16 DEBUG: Command: 'perl --version'
2024-09-10T14:36:16 DEBUG: Command: 'hostname 2>/dev/null'
2024-09-10T14:36:16 DEBUG: TimedCommand: 'hostname -f 2>/dev/null' with timeout of 5 sec
2024-09-10T14:36:16 DEBUG: Command: '/bin/cat /etc/machine-id'
2024-09-10T14:36:16 DEBUG: Command: '/bin/rm -f /etc/machine-id'
2024-09-10T14:36:16 DEBUG: Command: 'dbus-uuidgen --ensure=/etc/machine-id'
2024-09-10T14:36:16 DEBUG: Command: '/bin/cat /etc/machine-id'
2024-09-10T14:36:16 DEBUG: Command: 'hostname jirib-test01'
2024-09-10T14:36:16 DEBUG: Command: 'chmod 644 /etc/HOSTNAME'
2024-09-10T14:36:16 DEBUG: Command: 'hostname jirib-test01'
2024-09-10T14:36:24 DEBUG: Command: 'modprobe pcnet32 2> /dev/null'
2024-09-10T14:36:24 DEBUG: Command: '/sbin/ifconfig eth0 2> /dev/null'
2024-09-10T14:36:24 DEBUG: Command: 'whereis ip'
2024-09-10T14:36:24 DEBUG: Command: '/usr/sbin/ip addr show 2>&1'
2024-09-10T14:36:24 DEBUG: Command: 'whereis ip'
2024-09-10T14:36:24 DEBUG: Command: '/usr/sbin/ip addr show 2>&1'
2024-09-10T14:36:24 DEBUG: Command: 'chmod 644 /etc/sysconfig/network/ifcfg-eth0'
2024-09-10T14:36:24 DEBUG: Command: 'chmod 644 /etc/hosts'
2024-09-10T14:36:24 DEBUG: Command: 'chmod 644 /etc/nsswitch.conf'
2024-09-10T14:36:24 DEBUG: Command: 'readlink -f "/etc/resolv.conf"'
2024-09-10T14:36:24 DEBUG: Command: 'chmod 644 /etc/sysconfig/network/config'
2024-09-10T14:36:24 DEBUG: Command: 'chmod 644 /etc/sysconfig/network/config'
2024-09-10T14:36:24 DEBUG: Command: 'chmod 644 /etc/sysconfig/network/config'
2024-09-10T14:36:24 DEBUG: Command: 'netconfig update -f'
2024-09-10T14:36:24 DEBUG: Command: 'chmod 644 /etc/sysconfig/network/dhcp'
2024-09-10T14:36:24 DEBUG: Command: 'ln -sf /usr/share/zoneinfo/Europe/Prague /etc/localtime'
2024-09-10T14:36:24 DEBUG: Command: 'chmod 644 /etc/sysconfig/clock'
2024-09-10T14:36:24 DEBUG: Command: 'whereis timedatectl'
2024-09-10T14:36:24 DEBUG: Command: '/usr/bin/timedatectl set-local-rtc 0 2>/tmp/guest.customization.stderr'
[2024-09-10T14:36:31.150Z] [   debug] Command to exec : '/bin/rm'.
[2024-09-10T14:36:31.254Z] [    info] Customization command output:
[2024-09-10T14:36:31.254Z] [   debug] Command to exec : '/usr/bin/cloud-init'.
[2024-09-10T14:36:32.157Z] [    info] Customization command output:
[2024-09-10T14:36:37.193Z] [   debug] Command to exec : '/usr/bin/cloud-init'.
[2024-09-10T14:36:38.321Z] [    info] Customization command output:
[2024-09-10T14:36:46.030Z] [   debug] Command to exec : '/usr/bin/cloud-init'.
[2024-09-10T14:36:47.768Z] [    info] Customization command output:
[2024-09-10T14:36:58.976Z] [   debug] Command to exec : '/usr/bin/cloud-init'.
[2024-09-10T14:37:00.706Z] [    info] Customization command output:
[2024-09-10T14:37:00.707Z] [   debug] Command to exec : '/bin/readlink'.
[2024-09-10T14:37:00.808Z] [    info] Customization command output:
[2024-09-10T14:37:00.808Z] [   debug] Command to exec : '/sbin/telinit'.
[2024-09-10T14:37:00.909Z] [    info] Customization command output:
[2024-09-10T14:37:01.909Z] [   debug] Command to exec : '/sbin/telinit'.
[2024-09-10T14:37:02.636Z] [    info] Customization command output:
[2024-09-10T14:37:02.636Z] [   error] Customization command failed with stderr: 'Failed to set wall message, ignoring: Refusing activation, D-Bus is shutting down.
```

KB articles & other sources of information:
- https://knowledge.broadcom.com/external/article/311864/how-does-vsphere-guest-os-customization.html
- https://knowledge.broadcom.com/external/article?legacyId=59557
- https://cloudinit.readthedocs.io/en/latest/reference/datasources/vmware.html


#### VCSA

JSON answer aka template file, only needed when deploying via the
installer to ESXi/vSphere:

``` json
{
  "__version": "2.13.0",
  "new_vcsa": {
    "esxi": {
      "hostname": "<ip>",
      "username": "root",
      "password": "********,
      "deployment_network": "VM Network",
      "datastore": "vcsa"
    },
    "appliance": {
      "thin_disk_mode": true,
      "deployment_option": "tiny",
      "name": "Embedded-vCenter-Server-Appliance"
    },
    "network": {
      "ip_family": "ipv4",
      "mode": "static",
      "system_name": "vcsa.example.com",
      "ip": "<ip>",
      "prefix": "<prefix>",
      "gateway": "<default_gw>",
      "dns_servers": [
        "<dns_ip>"
      ]
    },
    "os": {
      "password": "********,
      "ntp_servers": "<ip_or_host>",
      "ssh_enable": true
    },
    "sso": {
      "password": "********,
      "domain_name": "vsphere.local"
    }
  },
  "ceip": {
    "settings": {
      "ceip_enabled": false
    }
  }
}
```

VCSA ISO has OVA file:

``` shell
$ bsdtar xOf VMware-VCSA-all-8.*iso 'vcsa/VMware-vCenter-Server-Appliance-8.*.ova' | bsdtar tf -
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10.ovf
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10.mf
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10.cert
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10-file1.json
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10-file2.rpm
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10-disk1.vmdk
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10-disk2.vmdk
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10-disk3.vmdk
```

According to a blog, the appliance needs couple of additional disks
attached (they need to be attached if "extracting" the appliance
_outside_ of ESXi/vSphere (in "VMware" environment, the appliance
would create the disk itself during deployment via the installer):

``` shell
$ bsdtar xOf VMware-VCSA-all-8.*iso 'vcsa/VMware-vCenter-Server-Appliance-8.*.ova' | \
    bsdtar xOf - '*.json' | \
    jq -r '.tiny | to_entries[] | select(.key | startswith("disk")) | (.key | split("-"; null)[1]), .value' | \
    xargs -n2 | nl
     1  root 48GB
     2  swap 25GB
     3  core 25GB
     4  log 10GB
     5  db 10GB
     6  dblog 15GB
     7  seat 10GB
     8  netdump 1GB
     9  autodeploy 10GB
    10  imagebuilder 10GB
    11  updatemgr 100GB
    12  archive 50GB
    13  vtsdb 10GB
    14  vtsdblog 5GB
    15  lifecycle 100GB
    16  lvm_snapshot 150GB
```

Deployment from VCSA ISO:

``` shell
$ lin64/vcsa-deploy install --accept-eula --no-esx-ssl-verify --no-ssl-certificate-verification embedded_vCSA_on_ESXi.json
```

Importing VCSA into libvirt/KVM - I can't explain why but totally
there should be _17_ disks, even though there are 16 disks in the json
file !!! The following therefore works for me:

``` shell
# creating additional vcenter disks
$ bsdtar xOf /tmp/data/iso/VMware-VCSA-all-8*.iso 'vcsa/VMware-vCenter-Server-Appliance-8.*.ova' | \
    bsdtar -xOf - '*.json' | \
    jq -r '.tiny | to_entries[] | select(.key | startswith("disk")) | (.key | split("-"; null)[1]), .value' | \
    xargs -n2 | nl | \
    sed -n '3,$p' | while read number name size ; do \
        qemu-img create -f qcow2 vcenter-disk${number}.qcow2 ${size//GB/G} ; done

$ ls -1 vcenter-disk*.qcow2 | sort -V
vcenter-disk4.qcow2
vcenter-disk5.qcow2
vcenter-disk6.qcow2
vcenter-disk7.qcow2
vcenter-disk8.qcow2
vcenter-disk9.qcow2
vcenter-disk10.qcow2
vcenter-disk11.qcow2
vcenter-disk12.qcow2
vcenter-disk13.qcow2
vcenter-disk14.qcow2
vcenter-disk15.qcow2
vcenter-disk16.qcow2

# extracting vmdk from the ova
$ bsdtar xOf /tmp/data/iso/VMware-VCSA-all-8*.iso 'vcsa/VMware-vCenter-Server-Appliance-8.*.ova' | \
    bsdtar -xf - 'VMware-vCenter-Server-Appliance-8*.vmdk'

$ ls -1 *.vmdk
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10-disk1.vmdk
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10-disk2.vmdk
VMware-vCenter-Server-Appliance-8.0.3.00000-24022515_OVF10-disk3.vmdk

# converting vmdk to qcow2
$ (i=1; while read line; do \
    qemu-img convert -f vmdk -O qcow2 $line vcenter-disk${i}.qcow2; ((i++)); \
    done) < <(ls -1 *.vmdk)

$ ls -1 vcenter-disk[1-3].qcow2
vcenter-disk1.qcow2
vcenter-disk2.qcow2
vcenter-disk3.qcow2

$ while read name size; do \
    qemu-img resize vcenter-${name}.qcow2 $((size * 1024 * 1024)) ; \
    done << EOF
disk1  49728
disk2  7040
disk3  25600
disk4  25600
disk5  10240
disk6  10240
disk7  15360
disk8  10240
disk9  1024
disk10  10240
disk11  10240
disk12  102400
disk13  51200
disk14  10240
disk15  5120
disk16  102400
disk17  153600
EOF

# 'tiny' profile CPU and memory settings
# inside vcenter appliance there's `/usr/sbin/verify_disk_size.py` which does some internal
# check and based on CPU and memory it requires a specific storage configuration

$ bsdtar xOf /tmp/data/iso/VMware-VCSA-all-8*.iso 'vcsa/VMware-vCenter-Server-Appliance-8.*.ova' | \
    bsdtar -xOf - '*.json' | \
    jq '.tiny | to_entries[] | select((.key == "cpu") or .key == "memory") | (.key, .value)' | xargs -n2
cpu 2
memory 14336

$ virt-install \
    --name vcenter \
    --memory 14336 \
    --vcpus 2 \
    --cpu host-passthrough,check=none,migratable=on \
    $(printf -- ' --disk /var/lib/libvirt/images/vsphere/vcenter-disk%d.qcow2,bus=sata' $(seq 1 17)) \
    --os-variant linux2022 \
    --network model=e1000e,network=vsphere \
    --wait 0 \
    --import
```

Then, open the VM console, change root password (you can also enable shell and SSH); login via HTTPS on 5480 port,
and follow the wizard.

vCenter appliance console UI is idiotic, however networking (do it
before configuring vCenter via web UI!) can be done via
`/opt/vmware/share/vami/vami_config_net`.


### Xen


#### kdump

`crashkernel` options is passed to the Xen kernel itself:

``` shell
$ xl info | grep xen_commandline
xen_commandline        : com2=115200,8n1 console=com2,vga dom0_mem=6G crashkernel=380M<4G

$ grep -Pv '^\s*(#|$)' /etc/default/grub | grep -P 'CMDLINE(_LINUX)?_XEN(_REPLACE)?_DEFAULT'
GRUB_CMDLINE_LINUX_XEN_REPLACE_DEFAULT="splash=none barrier=off mitigations=auto security=apparmor console=hvc0 console=xvc0,115200,8n1 earlyprintk=xen"
GRUB_CMDLINE_XEN_DEFAULT="com2=115200,8n1 console=com2,vga dom0_mem=6G crashkernel=380M\<4G"
```

How to trigger crash via serial console (eg. SOL)? Trigger it via `CTRL-a`:

``` shell
...
pancetta login:
(XEN) *** Serial input to Xen (type 'CTRL-a' three times to switch input)
(XEN) 'C' pressed -> triggering crashdump
(XEN) Executing kexec image on cpu5
(XEN) Shot down all CPUs
[    0.000000][    T0] microcode: microcode updated early to revision 0xf0, date = 2021-11-12
[    0.000000][    T0] Linux version 5.14.21-150500.55.52-default (geeko@buildhost) (gcc (SUSE Linux) 7.5.0, GNU ld (GNU Binutils; SUSE Linux Enterprise 15) 2.41.0.20230908-150100.7.46) #1 SMP PREEMPT_DYNAMIC Tue Mar 5 16:53:41 UTC 2024 (a62851f)
[    0.000000][    T0] Command line: barrier=off mitigations=auto security=apparmor console=xvc0,115200,8n1 earlyprintk=xen sysrq=yes reset_devices acpi_no_memhotplug cgroup_disable=memory nokaslr numa=off irqpoll nr_cpus=1 root=kdump rootflags=bind rd.udev.children-max=8 disable_cpu_apicid=0  console=ttyS1,115200,8n1 panic=1 acpi_rsdp=0x7dced000 elfcorehdr=1955572K kexec_jump_back_entry=0x000000005fa00041
...
Extracting dmesg
-------------------------------------------------------------------------------

The dmesg log is saved to /kdump/mnt0/var/crash/2024-04-12-14:27/dmesg.txt.

makedumpfile Completed.
-------------------------------------------------------------------------------
Saving dump using makedumpfile
-------------------------------------------------------------------------------
Copying data                                      : [100.0 %] |           eta: 0s

The dumpfile is saved to /kdump/mnt0/var/crash/2024-04-12-14:27/vmcore.

makedumpfile Completed.
-------------------------------------------------------------------------------
Generating README              Finished.
Copying System.map             Finished.
Copying kernel                 Finished.

Dump saving completed.
Type 'reboot -f' to reboot the system or 'exit' to
resume the boot process.
sh-4.4# ls -l /kdump/mnt0/var/crash/2024-04-12-14:27/vmcore*
-rw------- 1 root root 554122716 Apr 12 14:28 /kdump/mnt0/var/crash/2024-04-12-14:27/vmcore
```

Note, that Linux crashkernel needs to be told what is its console - if used - in its "native" way;
that is, `console=ttyS1,115200` (see above).

``` shell
# cat /etc/fstab
UUID=3196abbb-ecbf-4703-82b2-2cdb105cf3ed /kdump/mnt0 xfs defaults 0 2

# /kdump/mnt0/usr/bin/grep '^KDUMP_COMMANDLINE' /kdump/mnt0/etc/sysconfig/kdump
KDUMP_COMMANDLINE="barrier=off mitigations=auto security=apparmor console=xvc0,115200,8n1 earlyprintk=xen sysrq=yes reset_devices acpi_no_memhotplug cgroup_disable=memory nokaslr numa=off
KDUMP_COMMANDLINE_APPEND="console=ttyS1,115200,8n1"
```

The first line is a workaround; only the second line is important
since the last `console` options is the effective `/dev/console` for
Linux kernel.

Some intersting links:
- https://xenbits.xen.org/docs/4.17-testing/misc/kexec_and_kdump.txt
- https://xenbits.xen.org/docs/4.10-testing/misc/xen-command-line.html

A crash image will be available after reboot...:

``` shell
(XEN) Enabled directed EOI with ioapic_ack_old on!
(XEN) Enabling APIC mode.  Using 1 I/O APICs
(XEN) ENABLING IO-APIC IRQs
(XEN) Allocated console ring of 16 KiB.
(XEN) VMX: Supported advanced features:
(XEN)  - APIC MMIO access virtualisation
(XEN)  - APIC TPR shadow
(XEN)  - Extended Page Tables (EPT)
(XEN)  - Virtual-Processor Identifiers (VPID)
(XEN)  - Virtual NMI
(XEN)  - MSR direct-access bitmap
(XEN)  - Unrestricted Guest
(XEN)  - VMCS shadowing
(XEN)  - VM Functions
(XEN)  - Virtualisation Exceptions
(XEN)  - Page Modification Logging
(XEN) HVM: ASIDs enabled.
(XEN) VMX: Disabling executable EPT superpages due to CVE-2018-12207
(XEN) HVM: VMX enabled
(XEN) HVM: Hardware Assisted Paging (HAP) detected
(XEN) HVM: HAP page sizes: 4kB, 2MB, 1GB
(XEN) Brought up 8 CPUs
(XEN) Scheduling granularity: cpu, 1 CPU per sched-resource
(XEN) Initializing Credit2 scheduler
(XEN) Dom0 has maximum 856 PIRQs
(XEN)  Xen  kernel: 64-bit, lsb
(XEN)  Dom0 kernel: 64-bit, PAE, lsb, paddr 0x1000000 -> 0x4a00000
(XEN) PHYSICAL MEMORY ARRANGEMENT:
(XEN)  Dom0 alloc.:   0000001040000000->0000001048000000 (1534445 pages to be allocated)
(XEN)  Init. ramdisk: 00000010765ed000->0000001077bff0c6
(XEN) VIRTUAL MEMORY ARRANGEMENT:
(XEN)  Loaded kernel: ffffffff81000000->ffffffff84a00000
(XEN)  Phys-Mach map: 0000008000000000->0000008000c00000
(XEN)  Start info:    ffffffff84a00000->ffffffff84a004b8
(XEN)  Page tables:   ffffffff84a01000->ffffffff84a2a000
(XEN)  Boot stack:    ffffffff84a2a000->ffffffff84a2b000
(XEN)  TOTAL:         ffffffff80000000->ffffffff84c00000
(XEN)  ENTRY ADDRESS: ffffffff82fab1c0
(XEN) Dom0 has maximum 8 VCPUs
(XEN) Bogus DMIBAR 0xfed18001 on 0000:00:00.0
(XEN) Initial low memory virq threshold set at 0x4000 pages.
(XEN) Scrubbing Free RAM in background
(XEN) Std. Loglevel: Errors and warnings
(XEN) Guest Loglevel: Nothing (Rate-limited: Errors and warnings)
(XEN) ***************************************************
(XEN) Booted on L1TF-vulnerable hardware with SMT/Hyperthreading
(XEN) enabled.  Please assess your configuration and choose an
(XEN) explicit 'smt=<bool>' setting.  See XSA-273.
(XEN) ***************************************************
(XEN) Booted on MLPDS/MFBDS-vulnerable hardware with SMT/Hyperthreading
(XEN) enabled.  Mitigations will not be fully effective.  Please
(XEN) choose an explicit smt=<bool> setting.  See XSA-297.
(XEN) ***************************************************
(XEN) 3... 2... 1...
(XEN) Xen is relinquishing VGA console.
(XEN) *** Serial input to DOM0 (type 'CTRL-a' three times to switch input)
(XEN) Freed 2048kB init memory
mapping kernel into physical memory
about to get started...
...
```

#### XCP-ng

The ISO installation creates only the Xen dom0 - virt host; it deploys
a mgmt VM on top of itself.

``` shell
$ /usr/lib64/xen/bin/qemu-system-i386 -version
QEMU emulator version 4.2.1
Copyright (c) 2003-2019 Fabrice Bellard and the QEMU Project developers

$ xl list | grep alpine
alpine01                                     7   256     1     -b----       4.4

$ ps -eo pid,args  | grep -P '^\d+ qemu-dm-7'
11350 qemu-dm-7 -machine
pc-0.10,accel=xen,max-ram-below-4g=4026531840,allow-unassigned=true,trad_compat=True
-vnc unix:/var/run/xen/vnc-7,lock-key-sync=off -monitor null -pidfile
/var/run/xen/qemu-dm-7.pid -xen-domid 7 -m size=248 -boot order=cdn
-usb -device usb-tablet,port=2 -smp 1,maxcpus=1 -serial pty -display
none -nodefaults -trace enable=xen_platform_log -sandbox
on,obsolete=deny,elevateprivileges=allow,spawn=deny,resourcecontrol=deny
-S -global PIIX4_PM.revision_id=0x1 -global ide-hd.ver=0.10.2 -global
piix3-ide-xen.subvendor_id=0x5853 -global
piix3-ide-xen.subsystem_id=0x0001 -global
piix3-usb-uhci.subvendor_id=0x5853 -global
piix3-usb-uhci.subsystem_id=0x0001 -global rtl8139.subvendor_id=0x5853
-global rtl8139.subsystem_id=0x0001 -parallel null -qmp
unix:/var/run/xen/qmp-libxl-7,server,nowait -qmp
unix:/var/run/xen/qmp-event-7,server,nowait -device
xen-platform,addr=3,device-id=0x0001,revision=0x2,class-id=0x0100,subvendor_id=0x5853,subsystem_id=0x0001
-drive
file=/dev/sm/backend/9cd6a591-b9d2-32d3-3051-79a0ca6d4962/7461b3ff-001c-4b56-ada9-6e73bc78db44,if=none,id=ide1-cd1,auto-read-only=off,read-only=on,format=raw
-device ide-cd,drive=ide1-cd1,bus=ide.1,unit=1 -drive
file=/dev/sm/backend/02504265-dde6-dd00-2bfd-273d8b219639/893ce470-01fe-47b0-8649-71ba22a42819,if=none,id=ide0-hd0,auto-read-only=off,format=raw
-device ide-hd,drive=ide0-hd0,bus=ide.0,unit=0,bios-chs-trans=forcelba
-drive
file=/dev/sm/backend/02504265-dde6-dd00-2bfd-273d8b219639/c0da21e6-9a4d-41cf-8ab5-2b615a009718,if=none,id=ide0-hd1,auto-read-only=off,format=raw
-device ide-hd,drive=ide0-hd1,bus=ide.0,unit=1,bios-chs-trans=forcelba
-drive
file=/dev/sm/backend/02504265-dde6-dd00-2bfd-273d8b219639/cd9821c6-96be-44f4-9c87-33178daf784f,if=none,id=ide1-hd0,auto-read-only=off,format=raw
-device ide-hd,drive=ide1-hd0,bus=ide.1,unit=0,bios-chs-trans=forcelba
-device rtl8139,netdev=tapnet0,mac=72:11:a1:77:59:b9,addr=4 -netdev
tap,id=tapnet0,fd=7 -device
VGA,vgamem_mb=8,addr=2,romfile=,rombar=1,subvendor_id=0x5853,subsystem_id=0x0001,qemu-extended-regs=false
-vnc-clipboard-socket-fd 4 -xen-domid-restrict -chroot
/var/xen/qemu/root-7 -runas 65542:997

$ ls -l /proc/11350/exe
lrwxrwxrwx 1 65542 cgred 0 Feb 26 12:12 /proc/11350/exe -> /usr/lib64/xen/bin/qemu-system-i386
```

Another details:

``` shell
$ xl list | grep alpine
alpine01                                     9   256     1     -b----       0.6

$ ps -eo pid,args  | grep -P '^\d+ qemu-dm-9' | grep -oP 'drive \w+=\K[^,]+'
/dev/sm/backend/9cd6a591-b9d2-32d3-3051-79a0ca6d4962/7461b3ff-001c-4b56-ada9-6e73bc78db44
/dev/sm/backend/02504265-dde6-dd00-2bfd-273d8b219639/c0da21e6-9a4d-41cf-8ab5-2b615a009718

$ ps -eo pid,args  | grep -P '^\d+ qemu-dm-9' | grep -oP 'drive \w+=\K[^,]+' | xargs -I {} fdisk -l {} 2>/dev/null

Disk /dev/sm/backend/9cd6a591-b9d2-32d3-3051-79a0ca6d4962/7461b3ff-001c-4b56-ada9-6e73bc78db44: 66 MB, 66060288 bytes, 129024 sectors
Units = sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disk label type: dos
Disk identifier: 0x124bb11a

                                                                                     Device Boot      Start         End      Blocks   Id  System
/dev/sm/backend/9cd6a591-b9d2-32d3-3051-79a0ca6d4962/7461b3ff-001c-4b56-ada9-6e73bc78db44p1   *           0      129023       64512    0  Empty
/dev/sm/backend/9cd6a591-b9d2-32d3-3051-79a0ca6d4962/7461b3ff-001c-4b56-ada9-6e73bc78db44p2             308        3187        1440   ef  EFI (FAT-12/16/32)

Disk /dev/sm/backend/02504265-dde6-dd00-2bfd-273d8b219639/c0da21e6-9a4d-41cf-8ab5-2b615a009718: 2147 MB, 2147483648 bytes, 4194304 sectors
Units = sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

$ strings /dev/sm/backend/9cd6a591-b9d2-32d3-3051-79a0ca6d4962/7461b3ff-001c-4b56-ada9-6e73bc78db44 | head
fSfQ
xpu
isolinux.bin missing or corrupt.
f`f1
{fRfP
Operating system load error.
EFI PART
2025021@
0031455
2025021@
```

So, the first is the ISO, while XCP-ng doing some fancy tricks.

Each VM disk seems to be, in fact, a LV:

``` shell
$ xe vm-disk-list vm=alpine01 | grep -A 4 VDI | grep -P '(uuid|size)' | \
    perl -pe 's#(\d{2,})#sprintf("%.2f", $1 / 2**20)#ge if /virtual-size/i'
uuid ( RO)             : d633713d-db6b-48e7-aadf-9f5d6db4d44a
     virtual-size ( RO): 30.00
uuid ( RO)             : dad63f15-8420-498d-813a-eaf6f6c4c3c2
     virtual-size ( RO): 2048.00
uuid ( RO)             : a21607bf-5f02-46e2-98f9-3a0bffeb9214
     virtual-size ( RO): 20.00
uuid ( RO)             : b555fcac-0f3c-4e3c-9896-3a05cc78a410
     virtual-size ( RO): 1024.00

$ xe vm-disk-list vm=alpine01 | grep -A 4 VDI | grep -Po 'uuid.*: \K(.*)' | sort | nl
     1  a21607bf-5f02-46e2-98f9-3a0bffeb9214
     2  b555fcac-0f3c-4e3c-9896-3a05cc78a410
     3  d633713d-db6b-48e7-aadf-9f5d6db4d44a
     4  dad63f15-8420-498d-813a-eaf6f6c4c3c2

$ lvs --noheading -o name | grep -P '('"$(xe vm-disk-list vm=alpine01 | \
    grep -A 4 VDI | \
    grep -Po 'uuid.*: \K(.*)' | sort | tr '\n' '|' | sed 's/|$//')"')' | nl
     1    VHD-a21607bf-5f02-46e2-98f9-3a0bffeb9214
     2    VHD-b555fcac-0f3c-4e3c-9896-3a05cc78a410
     3    VHD-d633713d-db6b-48e7-aadf-9f5d6db4d44a
     4    VHD-dad63f15-8420-498d-813a-eaf6f6c4c3c2
```


#### Xen on KVM

``` shell
# check your baremetal host supports nested virtualization

$ cat > /etc/modprobe.d/kvm.conf <<EOF
options kvm ignore_msrs=1 report_ignored_msrs=0
options kvm_amd nested=1
EOF

$ modprobe kvm
```

``` shell
# libvirt domain tunning

$ virsh dumpxml s153qu01 | xmllint --xpath '//*/cpu' -
<cpu mode="host-passthrough" check="none" migratable="on"/>
```

TODO: This needs some modifications!

``` shell
# Xen virthost

$ cat /proc/cmdline
root=UUID=751fee4a-0c5a-4aef-9ab5-8324a767503b noresume splash=none mitigations=auto console=xvc0,115200,8n1 console=hvc0 earlyprintk=xen  noresume splash=none mitigations=auto

$ grep -P 'CMDLINE' /etc/default/grub
GRUB_CMDLINE_LINUX="console=ttyS0,115200n console=tty0"
GRUB_CMDLINE_LINUX_DEFAULT="noresume splash=none mitigations=auto"
GRUB_CMDLINE_LINUX_XEN_REPLACE="noresume splash=none mitigations=auto console=xvc0,115200,8n1 console=hvc0 earlyprintk=xen"
GRUB_CMDLINE_XEN_DEFAULT="loglvl=all guest_loglvl=all com1=115200,8n1 console=com1,vga"
```

Autostarting VMs on Xen/libvirt host:

``` shell
$ find /etc/libvirt/libxl/ -ls
   517551      0 drwxr-xr-x   1 root     root           44 Feb 28 18:26 /etc/libvirt/libxl/
   517561      0 drwxr-xr-x   1 root     root           26 Feb 28 18:26 /etc/libvirt/libxl/autostart
   517562      4 lrwxrwxrwx   1 root     root           32 Feb 28 18:26 /etc/libvirt/libxl/autostart/alp317-01.xml -> /etc/libvirt/libxl/alp317-01.xml
   517563      4 -rw-------   1 root     root         2261 Feb 28 18:26 /etc/libvirt/libxl/alp317-01.xml


$ virsh list
 Id   Name        State
---------------------------
 0    Domain-0    running
 2    alp317-01   running

$ virsh version
Compiled against library: libvirt 8.0.0
Using library: libvirt 8.0.0
Using API: Xen 8.0.0
Running hypervisor: Xen 4.16.0
```


## web

### apache http server

#### SLES

A typical spaghetti configuration, here is an example of TLS vhost on SLES 12.5:

``` shell
$ grep -Pv '^\s*($|#)' /etc/sysconfig/apache2
APACHE_CONF_INCLUDE_FILES=""
APACHE_CONF_INCLUDE_DIRS=""
APACHE_MODULES="authz_host actions alias authz_groupfile authz_user authn_file auth_basic autoindex cgi dir include log_config mime negotiation setenvif status userdir asis imagemap authz_core authn_core socache_shmcb reqtimeout http2 ssl"
APACHE_SERVER_FLAGS="SSL"
APACHE_HTTPD_CONF=""
APACHE_MPM="worker"
APACHE_SERVERADMIN=""
APACHE_SERVERNAME=""
APACHE_START_TIMEOUT="2"
APACHE_SERVERSIGNATURE="off"
APACHE_LOGLEVEL="warn"
APACHE_ACCESS_LOG="/var/log/apache2/access_log combined"
APACHE_USE_CANONICAL_NAME="off"
APACHE_SERVERTOKENS="ProductOnly"
APACHE_EXTENDED_STATUS="off"

$ apache2ctl -S
VirtualHost configuration:
*:443                  s125qb01.example.com (/etc/apache2/vhosts.d/s125qb01.example.com.conf:4)
ServerRoot: "/srv/www"
Main DocumentRoot: "/srv/www/htdocs"
Main ErrorLog: "/var/log/apache2/error_log"
Mutex mpm-accept: using_defaults
Mutex ssl-stapling-refresh: using_defaults
Mutex ssl-stapling: using_defaults
Mutex ssl-cache: using_defaults
Mutex default: dir="/run/" mechanism=default
PidFile: "/var/run/httpd.pid"
Define: SYSCONFIG
Define: SSL
Define: DUMP_VHOSTS
Define: DUMP_RUN_CFG
User: name="wwwrun" id=30
Group: name="www" id=8

$ cat /etc/apache2/vhosts.d/s125qb01.example.com.conf
<IfDefine SSL>
<IfDefine !NOSSL>

<VirtualHost _default_:443>
        DocumentRoot "/srv/www/htdocs"
        ServerName s125qb01.example.com:443
        ServerAdmin webmaster@example.com
        ErrorLog /var/log/apache2/error_log
        LogFormat "%v %h %l %u %t \"%r\" %>s %b"
        TransferLog /var/log/apache2/access_log
        SSLEngine on
        SSLCertificateFile /etc/apache2/ssl.crt/vhost-s125qb01.example.com.crt
        SSLCertificateKeyFile /etc/apache2/ssl.key/vhost-s125qb01.example.com.key
        CustomLog /var/log/apache2/ssl_request_log   ssl_combined
        Protocols h2 http/1.1
</VirtualHost>
</IfDefine>
</IfDefine>

$ rpm -qa apache2\* | grep -P -- '-(prefork|worker|event)'
apache2-prefork-2.4.51-35.19.1.x86_64
apache2-worker-2.4.51-35.19.1.x86_64

$ curl -sL -k -o /dev/null  --http2 -w 'Used protocol: %{http_version}\n' https://s125qb01.example.com
Used protocol: 2
$ cat /var/log/apache2/access_log
s125qb01.example.com 127.0.0.1 - - [30/Sep/2022:09:23:58 +0200] "GET / HTTP/2.0" 200 45
```

Enabling a module, eg. one for WebDAV, on SLES:

``` shell
$ grep dav /etc/sysconfig/apache2 | fmt -w80
APACHE_MODULES="actions alias auth_basic authn_core authn_file authz_host
authz_groupfile authz_core authz_user autoindex cgi dav dav_fs dav_lock dir
env expires include log_config mime negotiation setenvif ssl socache_shmcb
userdir reqtimeout"

# after stop-start

$ grep -IR 'LoadModule' /etc/apache2/ | grep -m3 dav
/etc/apache2/sysconfig.d/loadmodule.conf:LoadModule dav_module /usr/lib64/apache2-prefork/mod_dav.so
/etc/apache2/sysconfig.d/loadmodule.conf:LoadModule dav_fs_module /usr/lib64/apache2-prefork/mod_dav_fs.so
/etc/apache2/sysconfig.d/loadmodule.conf:LoadModule dav_lock_module /usr/lib64/apache2-prefork/mod_dav_lock.so

# needs also some auth* modules !!!

$ grep -Pv '^\s*(#|$)' /etc/apache2/conf.d/webdav.conf
<IfModule dav_module>
DavLockDB "/srv/www/var/DavLock"
Alias /uploads "/srv/www/uploads"
<Directory "/srv/www/uploads">
  Dav On
  AuthType Digest
  AuthName DAV-upload
  AuthUserFile "/srv/www/user.passwd"
  AuthDigestProvider file
  <RequireAny>
    Require method GET POST OPTIONS
    Require user admin
  </RequireAny>
</Directory>
BrowserMatch "Microsoft Data Access Internet Publishing Provider" redirect-carefully
BrowserMatch "MS FrontPage" redirect-carefully
BrowserMatch "^WebDrive" redirect-carefully
BrowserMatch "^WebDAVFS/1.[01234]" redirect-carefully
BrowserMatch "^gnome-vfs/1.0" redirect-carefully
BrowserMatch "^XML Spy" redirect-carefully
BrowserMatch "^Dreamweaver-WebDAV-SCM1" redirect-carefully
BrowserMatch " Konqueror/4" redirect-carefully
</IfModule>

$ mkdir -p /srv/www/{uploads,var}
$ chown wwwrun:wwwrun /srv/www/{uploads,var}

# the client test, eg. curl

$ awk '{ print $1,$2,$3,"user password yyy" }' ~/.netrc
machine 192.168.122.188 login user password yyy

$ curl -s --digest -n -X PROPFIND -H 'Depth: 1' -k https://192.168.122.188/uploads/ | grep -C 5 text.txt
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
<D:response xmlns:lp2="http://apache.org/dav/props/" xmlns:lp1="DAV:">
<D:href>/uploads/text.txt</D:href>
<D:propstat>
<D:prop>
<lp1:resourcetype/>
<lp1:creationdate>2024-08-09T11:37:51Z</lp1:creationdate>
<lp1:getcontentlength>12</lp1:getcontentlength>

# davfs2

$ grep -IRHPv '^\s*(#|$)' /etc/davfs2/{secrets,davfs2.conf}
/etc/davfs2/secrets:127.0.0.1 admin yyy
/etc/davfs2/secrets:https://192.168.122.16/uploads admin yyy
/etc/davfs2/secrets:https://192.168.122.188/uploads admin yyy
/etc/davfs2/davfs2.conf:[/mnt]
/etc/davfs2/davfs2.conf:use_proxy 1
/etc/davfs2/davfs2.conf:proxy 127.0.0.1
/etc/davfs2/davfs2.conf:trust_ca_cert server1.pem
/etc/davfs2/davfs2.conf:trust_server_cert server1.pem
/etc/davfs2/davfs2.conf:[/tmp/mnt]
/etc/davfs2/davfs2.conf:trust_ca_cert server2.pem
/etc/davfs2/davfs2.conf:trust_server_cert server2.pem
```

### nikola

``` shell
$ pipx install nikola
$ pipx runpip nikola install 'nikola[extras]'

$ nikola init mysite # 'mysite' is the final directory
$ cd mysite

$ nikola build
$ ls -1 output/
archive.html
assets
categories
galleries
images
index.html
listings
robots.txt
rss.xml
sitemapindex.xml
sitemap.xml

$ w3m -dump http://localhost:8000
Skip to main content
My Nikola Site

  • Archive
  • Tags
  • RSS feed

Contents © 2025 Nikola Tesla - Powered by Nikola
```

Configuration is a Python script:

``` shell
$ grep -Pv '^\s*(#|$)' conf.py  | head
import time
BLOG_AUTHOR = "Nikola Tesla"  # (translatable)
BLOG_TITLE = "My Nikola Site"  # (translatable)
SITE_URL = "http://t14s.example.com/"
BLOG_EMAIL = "n.tesla@example.com"
BLOG_DESCRIPTION = "This is a demo site for Nikola."  # (translatable)
DEFAULT_LANG = "en"
TRANSLATIONS = {
    DEFAULT_LANG: "",
}
```

Content of `mysite`:

``` shell
$ ls -1F
cache/
conf.py
files/
galleries/
images/
listings/
output/
pages/
posts/
__pycache__/
```

$ find p{ages,osts}/
pages/
posts/
```

Create a new page with hacks...

``` shell
$ tmpfile=$(mktemp)
$ curl -sL -X POST lipsum.com/feed/json | jq -r '.feed.lipsum' | \
    tr '\n' 'X' | sed 's/X.*//' > $tmpfile

$ env EDITOR="fold -w80" nikola new_page -t 'About Me' -a 'Jiri Belka' -f markdown -i $tmpfile -e
Importing Existing Page
-----------------------

Title: About Me
Scanning posts........done!
[2025-02-17 16:21:04] INFO: new_page: Your page's text is at: pages/about-me.md
<!--
.. title: About Me
.. slug: about-me
.. date: 2025-02-17 16:21:04 UTC+01:00
.. tags: 
.. category: 
.. link: 
.. description: 
.. type: text
.. author: Jiri Belka
-->

Lorem ipsum dolor sit amet, consectetur adipiscing elit. Maecenas dapibus arcu v
el mauris euismod, in semper enim ornare. Fusce laoreet, enim ultricies tempor b
landit, nisl felis tempor enim, vel consequat tortor nisi a mi. Maecenas loborti
s arcu sit amet quam dictum, ut mollis nulla pretium. Praesent at quam ut ligula
 congue ultricies. Duis ex dui, dignissim at lorem vel, porta auctor ipsum. Aliq
uam erat volutpat. Duis commodo, libero in eleifend condimentum, dolor turpis ul
trices justo, et tempor sapien ligula eget orci. Cras tempus pulvinar arcu, pulv
inar gravida elit fermentum ut. Donec dignissim dignissim nibh, nec auctor lorem
 auctor scelerisque. Aenean erat turpis, elementum sit amet faucibus quis, effic
itur non odio. Duis auctor erat id ultrices viverra. Sed in lorem eget ligula co
nvallis consequat. Suspendisse feugiat lorem et libero sagittis porttitor. Suspe
ndisse urna lacus, mollis sed diam vel, dapibus tincidunt metus. Nam accumsan ia
culis lorem, quis posuere velit elementum tempus. Aenean at felis eu arcu sceler
isque eleifend sit amet nec erat.

$ nikola build
$ ls -1 output/pages/about-me/
index.html
index.md
```

Funny.


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


### recovery partiton

To recreate recovery partition, follow this guides:
- https://support.microsoft.com/en-us/topic/kb5028997-instructions-to-manually-resize-your-partition-to-install-the-winre-update-400faa27-9343-461c-ada9-24c8229763bf
- https://www.tenforums.com/backup-restore/150234-recovery-partition.html#post1837415

The latter is especially useful since it describes how to get
`WinRE.wim` and `ReAgent.xml` from the installation media via _7zip_
to copy it into `C:\Windows\system32\recovery`.


### templating windoze

Install all drivers, eg. virtio-win drivers.

```
> %windir%\system32\sysprep\sysprep.exe /?
> %windir%\system32\sysprep\sysprep.exe /generalize /shutdown
```


### WinPE

Download [ADK for
Windows](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install)
plus *Windows PE add-on*. Then run as an admin user *Deployment and
Imaging Tools Environment* from menu.

``` shell
$ copype amd64 C:\winpe
$ MakeWinPEMedia /ISO C:\winpe <output iso>
```

Putting files into WinPE could be done (more details at [burp
wiki](https://github.com/grke/burp/wiki/Windows-disaster-recovery-with-WinPE-and-burp):

``` shell
$ Dism /Mount-Image /ImageFile:"C:\winpe\media\sources\boot.wim" /index:1 /MountDir:"C:\winpe\mount"
...
$ Dism /Unmount-Image /MountDir:"C:\winpe\mount" /commit
```
