# Network cheatsheet


## Applications


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


## DNS


### Bind / named

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


### Bind / named: dynamic DNS updates

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


### dnsmasq


#### dnsmasq: as authoritative dns server

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

#### dnsmasq: as dhcp server for multiple networks

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

#### dnsmasq: as pxe/tftp

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

## HTTP proxy

### proxy.py

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


## TFTP

Starting an tftpd server via systemd.socket(5).

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


## Mail


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


## TLS / SSL


### OpenSSL

A simple https webserver

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


## Tor

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


## Network tracing


### tcpdump

See [A tcpdump tutorial with
examples...](https://web.archive.org/web/20210826070406/https://danielmiessler.com/study/tcpdump/)
for some cool examples.


### Wireshark / tshark

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


#### Wireshark: LACP protocol

LLDP can be used to get announcements from a switch about 802.3ad, see
below part from LLDP part obtained with `tshark`:


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

#### Wireshark: LLDP / CDP protocol(s)

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

#### Wireshark: tips and tricks

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


#### Wireshark: SSH protocol

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


### Network tracing tips & tricks

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

One way to modify a network trace is to use
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
