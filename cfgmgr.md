# Configuration management cheatsheet


## Saltstack aka salt

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


### Salt on Debian

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


### Salt on SLES

Default `/etc/salt/master` on SLES:

``` shell
$ grep -Pv '^\s*(#|$)' /etc/salt/master
user: salt
syndic_user: salt

```

### salt-master

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


### salt git fileserver_backend

``` shell
$ grep -RPv '^\s*(#|$)' /etc/salt/master* | sed 's/pat_.*/pat_XXXXXXXXXXXXXXXXXXXXX/'
/etc/salt/master:user: salt
/etc/salt/master.d/local.conf:gitfs_provider: pygit2
/etc/salt/master.d/pillar_git.conf:ext_pillar:
/etc/salt/master.d/pillar_git.conf:  - git:
/etc/salt/master.d/pillar_git.conf:    - main https://github.com/jirib/salt-pillars.git:
/etc/salt/master.d/pillar_git.conf:      - root: pillar
/etc/salt/master.d/pillar_git.conf:      - env: base
/etc/salt/master.d/pillar_git.conf:      - user: github_pat_XXXXXXXXXXXXXXXXXXXXX
/etc/salt/master.d/pillar_git.conf:      - password: x-oauth-basic
/etc/salt/master.d/fileserver_git.conf:fileserver_backend:
/etc/salt/master.d/fileserver_git.conf:  - git
/etc/salt/master.d/fileserver_git.conf:gitfs_base: main
/etc/salt/master.d/fileserver_git.conf:gitfs_remotes:
/etc/salt/master.d/fileserver_git.conf:  - "https://github.com/jirib/salt-states.git"
```

*WARNING!*: There's some odd Salt caching in
`/var/cache/salt/master/gitfs/` and since I use _main_ branch instead
of _master_ which is by default mapped to _base_ env, it took me long
time to map _main_ to _master_. It has started to work via
`gitfs_base: main` only after `rm -rf /var/cache/salt/master/gitfs/*`!

An example of `/etc/motd` management:

``` shell
$ salt-run fileserver.update
True

$ salt-run fileserver.file_list base
- motd/files/default
- motd/init.sls
- top.sls
```

``` shell
$ basename -s .git "$(git config --get remote.origin.url)"
salt-states

$ git ls-tree -r HEAD --name-only
motd/files/default
motd/init.sls
top.sls

$ cat top.sls 
base:
  '*'
    - motd

$ cat motd/init.sls 
{% set motd_text = salt['pillar.get']('motd_content', '') %}
{% if not motd_text %}
{% set motd_text = salt['cp.get_file_str']('salt://motd/files/default') %}
{% endif %}
 
/etc/motd:
  file.managed:
    - contents: {{ motd_text | yaml_encode }}

$ cat motd/files/default 
Hello world!

$ basename -s .git "$(git config --get remote.origin.url)"
salt-pillars

$ git ls-tree -r HEAD --name-only
pillar/avocado_pillar.sls
pillar/top.sls

$  head -n 9 pillar/avocado_pillar.sls
motd_content: |
  {% set full_text = "Welcome to " ~ grains['fqdn'] -%}
  {% set banner_width = 70 -%}
  {% set banner_padding = banner_width - 2 - full_text|length -%}
 
  #######################################################################
  # {{ full_text ~ (" " * banner_padding) }}#
  # BE NICE!!! IT IS A SHARED SLL9 KVM HOST; DO NOT FORGET SELINUX !    #
  #######################################################################
```

Above there's a hacky solution how to create fixed width motd ;)


### salt-minion

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


#### salt-minion: masterless

To use Salt without a server is to use Salt Standalone Mode via
`salt-call'.


##### salt-minion masterless: under root

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


##### salt-minon masterless: under normal user

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


### salt modules

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

#### salt pillars

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
