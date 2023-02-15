# My cheatsheet

## acl

- *mask* is maximum permission for users (other than the owner) and groups!
- `chmod` incluences mask of ACL file/dir!
- default ACL of a directory for inheritance


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

- `sss_cache -E` invalidate all cached entries, with the exception of sudo rules
- `sss_cache -u <username>`, invalidate a specific user entries
- `systemctl stop sssd; rm -rf /var/lib/sss/db/*; systemctl restart sssd`

Note that *sssd* caches, so do not run `nscd` caching `passwd` and `group` DBs.

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
- *CRM* - `crmd`/`pacemaker-controld`, cluster resource manager, CRM, part of
  resource allocation layer, `crmd` is main process
- *CIB* - `cib`/`pacemaker-based`, cluster information base, configuration,
  current status,
  pacemaker, part of resource allocation layer; shared copy of state, versioned
- *DC* - designated coordinator, in-memory state, member managing the master
  copy of the *CIB*, so-called master node, communicate changes of the CIB copy
  to other nodes via CRM
- *PE* - `pegnine`/`pacemaker-schedulerd`, policy engine, running on DC, the
  brain of the cluster,
  monitors CIB and calculates changes required to align with desired
  state, informs CRM
- *LRM* - `lrm`/`pacemaker-exec`, local resource manager, instructed from CRM
  what to do
- *RA* - resource agent, logic to start/stop/monitor a resource,
  called from LRM and return values are passed to the CRM, ideally
  OCF, LSB, systemd service units or STONITH
- *OCF* - open cluster framework, standardized resource agents
- *STONITH* - "shoot the other node in the head", fencing resource
  agent, eg. via IPMI…
- *DLM* - distributed lock manager, cluster wide locking (`ocf:pacemaker:controld`)
- *CLVM* - cluster logical volume manager, `lvmlockd`, protects LVM
  metadata on shared storage


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
- *unicast*, usually better

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
-

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

*sbd* watches both *corosync* and *pacemaker*:

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

As for pacemaker watcher, it seems it uses libs to query the Pacemaker:

``` shell
$ ldd `which sbd` | grep -Po ' \K(/lib[^ ]+)(?=.*)' | while read f; do
      rpm --qf '%{NAME}\n' -qf $f | grep pacemaker
  done | sort -u
libpacemaker3
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

## diff / patch

To extract hunks from a diff, see https://stackoverflow.com/questions/1990498/how-to-patch-only-a-particular-hunk-from-a-diff.

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

#### tricks & tips

- Get GH PR as raw diff/patch, an example:
  https://github.com/weppos/whois/pull/90.diff
  https://github.com/weppos/whois/pull/90.patch


### json

A [playgroun](https://jqplay.org/) for `jq`.


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


### analysis

NOTE: VM snapshot from VMware environement (`.vmsn` and `.vmem` files)
can be analyzed directly with `crash` tool

Same kernel and kernel debug files have to be present.

``` shell
$ strings /home/vmcore | grep -m 1 -i osrelease
OSRELEASE=5.14.21-150400.24.18-default

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

crash>
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
crash> log | sed -n '/RTC time:/s/.* time: \([^,]*\), date: \(.*\)/\2 \1/p'
2022-12-06 15:02:29
crash> !date --date='2022-12-06 15:02:29' +"%s"
1670335349
crash> log | perl -pe 's/(\d+)/localtime(1670335349+$1)/e' | tail
[Fri Jan  6 11:19:20 2023.058462] RBP: 0000000000000000 R08: 0000000000000000 R09: 0138cb8651caaf7d
[Fri Jan  6 11:19:20 2023.058462] R10: ffffffff88803e20 R11: 00000000000aae9e R12: 0000000000000000
[Fri Jan  6 11:19:20 2023.058462] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[Fri Jan  6 11:19:20 2023.090572]  ? __sched_text_end+0x7/0x7
[Fri Jan  6 11:19:20 2023.090572]  default_idle+0x1c/0x150
[Fri Jan  6 11:19:20 2023.090572]  do_idle+0x1bf/0x270
[Fri Jan  6 11:19:20 2023.090572]  cpu_startup_entry+0x19/0x20
[Fri Jan  6 11:19:20 2023.090572]  start_kernel+0x559/0x57e
[Fri Jan  6 11:19:20 2023.090572]  secondary_startup_64_no_verify+0xc2/0xd0
[Fri Jan  6 11:19:20 2023.090572] Kernel Offset: 0x6000000 from 0xffffffff81000000 (relocation range: 0xffffffff80000000-0xffffffffbfffffff)

crash> log | perl -pe 's/(\d+)/localtime(1670335349+$1)/e' | grep -m1 -C 10 sysrq
[Wed Jan  4 20:00:14 2023.778249] floppy: error 10 while reading block 0
[Thu Jan  5 03:00:03 2023.339826] blk_update_request: I/O error, dev fd0, sector 0 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 0
[Thu Jan  5 03:00:03 2023.346777] floppy: error 10 while reading block 0
[Thu Jan  5 12:30:15 2023.884118] blk_update_request: I/O error, dev fd0, sector 0 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 0
[Thu Jan  5 12:30:15 2023.892338] floppy: error 10 while reading block 0
[Thu Jan  5 20:00:14 2023.847606] blk_update_request: I/O error, dev fd0, sector 0 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 0
[Thu Jan  5 20:00:14 2023.854650] floppy: error 10 while reading block 0
[Fri Jan  6 03:00:03 2023.135697] blk_update_request: I/O error, dev fd0, sector 0 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 0
[Fri Jan  6 03:00:03 2023.144006] floppy: error 10 while reading block 0
[Fri Jan  6 11:14:24 2023.829289] CIFS: VFS: \\FFISOFS has not responded in 180 seconds. Reconnecting...
[Fri Jan  6 11:19:19 2023.962359] sysrq: Trigger a crash
[Fri Jan  6 11:19:19 2023.965234] Kernel panic - not syncing: sysrq triggered crash
[Fri Jan  6 11:19:19 2023.966333] CPU: 0 PID: 0 Comm: swapper/0 Kdump: loaded Tainted: G               X    5.3.18-150300.59.98-default #1 SLE15-SP3
[Fri Jan  6 11:19:19 2023.966333] Hardware name: Microsoft Corporation Virtual Machine/Virtual Machine, BIOS 090008  12/07/2018
[Fri Jan  6 11:19:19 2023.966333] Call Trace:
[Fri Jan  6 11:19:19 2023.966333]  <IRQ>
[Fri Jan  6 11:19:19 2023.966333]  dump_stack+0x66/0x8b
[Fri Jan  6 11:19:19 2023.966333]  panic+0xfe/0x2e3
[Fri Jan  6 11:19:19 2023.966333]  ? printk+0x52/0x72
[Fri Jan  6 11:19:19 2023.966333]  sysrq_handle_crash+0x11/0x20
[Fri Jan  6 11:19:19 2023.966333]  __handle_sysrq+0x89/0x140
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


###### resizing luns

``` shell
$ targetcli /iscsi/iqn.2021-12.com.example:cl0/tpg1/luns/lun2 info
alias: 8ae1d462e7
alua_tg_pt_gp_name: default_tg_pt_gp
index: 2
storage_object: /backstores/fileio/testresize

$ targetcli /backstores/fileio/testresize info
aio: False
dev: /suse/vms/testresize.raw
name: testresize
plugin: fileio
size: 4194304
write_back: True
wwn: 4e06ac05-b742-4f7f-b391-368fba4ba080

$  cat /sys/kernel/config/target/core/fileio_*/testresize/info
Status: ACTIVATED  Max Queue Depth: 0  SectorSize: 512  HwMaxSectors: 16384
        TCM FILEIO ID: 0        File: /suse/vms/testresize.raw  Size: 4194304  Mode: Buffered-WCE Async: 0
```

``` shell
$  lsscsi -is 0:0:0:2
[0:0:0:2]    disk    LIO-ORG  testresize       4.0   /dev/sdb   360014054e06ac05b7424f7fb391368fb  4.19MB
```

``` shell
$ truncate -s +6M testresize.raw
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

### RHEL

#### sosreport

- `sos_commands/systemd/journalctl_--list-boots`
- `sos_commands/block/lsblk{,_-f_-a_-l}`
- `etc/fstab`
- `{free,proc/meminfo}`

### SLES

#### installation

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


## shell

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

### Xen

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

### templating windoze

Install all drivers, eg. virtio-win drivers.

```
> %windir%\system32\sysprep\sysprep.exe /?
> %windir%\system32\sysprep\sysprep.exe /generalize /shutdown
```
