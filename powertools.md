# UNIX/Linux tools

## AWK

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

`awk` using external command and working with its output:

``` awk
# an example showing content of relevant initramfs files, that is,
# parsing listing output and if real file try to show its content if
# not empty

$ lsinitrd | awk '
/^(d|l)/ { next;}
!/(etc\/(cmdline.d[^[:space:]]+$|systemd[^[:space:]]+(\.device(\.d.*$)?)))/ { next;}
{
    cmd1 = sprintf("lsinitrd -f \"%s\"", $NF)
    cmd1 | getline out1
    close(cmd1)
    if (out1 != "") {
        printf("# %s\n%s\n", $NF, out1)
    }
}'
# etc/cmdline.d/00-btrfs.conf
 rd.driver.pre=btrfs
# etc/cmdline.d/95resume.conf
 resume=UUID=16382811-4011-4745-bc15-f5ea3f84d773
# etc/cmdline.d/95root-dev.conf
 root=UUID=d0c229fb-f298-4147-919b-8317cb863e79 rootfstype=btrfs rootflags=rw,relatime,ssd,discard=async,space_cache,subvolid=266,subvol=/@/.snapshots/1/snapshot,subvol=@/.snapshots/1/snapshot
# etc/systemd/system/dev-disk-by\x2duuid-715D\x2d8BBE.device.d/timeout.conf
[Unit]
```


## Coreutils

``` shell
$ date --date='last friday' +%d # to see date of last Friday
```


## Backup applications


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


### plakar

``` shell
$ $ plakar info -errors cde5730e
/home/jiri/.mozilla/firefox/sgofny49.default/cert9.db: open /home/jiri/.mozilla/firefox/sgofny49.default/cert9.db: permission denied
/home/jiri/.mozilla/firefox/sgofny49.default/key4.db: open /home/jiri/.mozilla/firefox/sgofny49.default/key4.db: permission denied
/home/jiri/.mozilla/firefox/sgofny49.default/pkcs11.txt: open /home/jiri/.mozilla/firefox/sgofny49.default/pkcs11.txt: permission denied
```

Check the backup for errors!

- `~/.plakar` is used as default kloset store


## bugzilla

For bugzilla reports in CSV, just add `&ctype=csv` in the URL.


## Mail


### IMAP/mbsync

Migrating mail from imap server to another:

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




## Schedulers


### CRON


#### CRON: random delay for a job

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

#### CRON: sending mail via mailx to a relay requiring authentication

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


## Security


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


### sudo

WARNING: Wildcares, take care, see [Dangerous Sudoers Entries – PART
4:
Wildcards](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-4-wildcards/).

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


## Shells

Various shell startup files are described at [Some differences between
BASH and TCSH](https://web.fe.up.pt/~jmcruz/etc/unix/sh-vs-csh.html)
and [Shell
Startup](https://docs.nersc.gov/environment/shell_startup/).


### BASH

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


## sed

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
p
three

four

five
```

## TAR

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


## TMUX


### TMATE

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
