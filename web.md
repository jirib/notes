# web

## apache http server

### SLES

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

## nikola - a static web generator

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
