# Configuration management cheatsheet


## Ansible

``` shell
$ mise list | grep ansible
ansible-core   2.21.0   ~/Sync/Documents/personal/src/github.com/jirib/mise.toml  latest

$ ansible --version
ansible [core 2.21.0]
  config file = /home/jiri/Sync/Documents/personal/src/github.com/jirib/student-lab/ansible/ansible.cfg
  configured module search path = ['/home/jiri/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
  ansible python module location = /home/jiri/.local/share/mise/installs/ansible-core/2.21.0/ansible-core/lib/python3.13/site-packages/ansible
  ansible collection location = /home/jiri/.ansible/collections:/usr/share/ansible/collections
  executable location = /home/jiri/.local/share/mise/installs/ansible-core/latest/bin/ansible
  python version = 3.13.7 (main, Sep 18 2025, 19:47:49) [Clang 20.1.4 ] (/home/jiri/.local/share/mise/installs/ansible-core/2.21.0/ansible-core/bin/python)
  jinja version = 3.1.6
  pyyaml version = 6.0.3 (with libyaml v0.2.5)
```

In a project:

``` shell
$ grep -HPv '^\s*(#|$)' mise.toml requirements.yml 
mise.toml:[tools]
mise.toml:ansible-core = "2.21.0"
mise.toml:[tasks.ansible-collection-install]
mise.toml:description = "Install Ansible collections"
mise.toml:run = """
mise.toml:ansible-galaxy collection install -r requirements.yml
mise.toml:"""
mise.toml:[tasks.ansible-collection-check]
mise.toml:run = """
mise.toml:ansible-galaxy collection list
mise.toml:"""
requirements.yml:---
requirements.yml:collections:
requirements.yml:  - name: community.libvirt
requirements.yml:  - name: community.general
```

### Inventory

``` shell
$ find ./inventory/ ! -name '*~'
./inventory/
./inventory/development
./inventory/development/group_vars
./inventory/development/group_vars/.keep
./inventory/development/hosts.yml
./inventory/development/host_vars
./inventory/development/host_vars/.keep

$ ansible-inventory -i inventory/development/hosts.yml --graph
@all:
  |--@ungrouped:
  |--@hypervisors:
  |  |--@lab_hypervisors:
  |  |  |--tom
  |--@lab_hypervisors:
  |  |--tom

$ ansible -i inventory/development/ lab_hypervisors -m ping
tom | SUCCESS => {
    "changed": false,
    "ping": "pong"
}
```


### Secrets in Ansible


#### Handling secrets in Ansible with SOPS

See [SOPS](#SOPS) for basics and [Protecting Ansible secrets with
SOPS](https://docs.ansible.com/projects/ansible/latest/collections/community/sops/docsite/guide.html).

Have `community.sops` in _collections_ in your `requirements.yml`.

``` shell
$ yq '.collections' ansible/requirements.yml  | grep sops
- name: community.sops
```

Tip: add a _mise_ task to install the defined collections via
`ansible-galaxy`.

``` shell
$ ansible-doc community.sops -l
community.sops.load_vars    Load SOPS-encrypted variables from files, dynamically within a task
community.sops.sops_encrypt Encrypt data with SOPS
```

A quick start with GPG:

1. Go to your ansible project directory (usually one with `ansible.cfg`).
2. Configure `.sops.yaml`:
   ``` shell
   $ gpg --list-key --with-colons | grep -B1 -P 'jirib' | head -n1 | grep -oE '[A-Z0-9]+'
   F178D4D326B55EB03F8A23A55B9E7F688216D470
   $ GPG_FPR=$(gpg --list-key --with-colons | grep -B1 -P 'jirib' | head -n1 | grep -oE '[A-Z0-9]+')
   $ cat > .sops.yaml <<'EOF'
   creation_rules:
     - pgp: $GPG_FPR
   EOF
   $ cat .sops.yaml 
   creation_rules:
     - pgp: F178D4D326B55EB03F8A23A55B9E7F688216D470
   ```
3. Create a test secrets (in the input editor mode: modify and save; or via here-doc):
   ``` shell
   $ sops test.sops.yaml
   $ cat test.sops.yaml
   ```
   ``` shell
   $ sops --input-type yaml --output-type yaml -e <(cat <<EOF
   hello: world
   foo:
     - bar
     - baz
   EOF
   ) | tee test.sops.yaml
   hello: ENC[AES256_GCM,data:CtZLZII=,iv:pZkmqGbvOhsKEN6ZQZwVvuMkaM4f7g6vETPfuuPbctc=,tag:USC0CiwFOvBlqbdK5lWPzQ==,type:str]
   foo:
       - ENC[AES256_GCM,data:gI29,iv:YZ4AaX74Q9ckpWOdNIPlnBYz1C3QXoV8aVZ1KdiekHQ=,tag:lRYBvrdD8iRC7JkViHikuA==,type:str]
       - ENC[AES256_GCM,data:B7wa,iv:W66vT4M4pp7r2ibpi9Qv3CM1lYSwV0eqnZHQsjq+xBU=,tag:kqgH/voqwvhjT0Qu8cDt2A==,type:str]
   sops:
       lastmodified: "2026-05-27T11:21:54Z"
       mac: ENC[AES256_GCM,data:yICvG/ixM+56JCwZxnkXBQhBgXXotmaaf6fpm0F0MOZUTkh2J2sQmhqHiVoUIFqhPxq20PSQgGrnCwFwe5u9a7LzqIDY7t+7h2MIy+QeJ18B9b2BoqcnnI5mh4o/4UWajGJ693MD8q3PQV0civhJb/ajlsI0VAO21MZwrC/Hn3g=,iv:ONiAIxY+YZK9/Rv3Ui0UpBm49viKvU/HvKJsqEM92QQ=,tag:6otEbQinFG40wYwbs8UX0g==,type:str]
       pgp:
           - created_at: "2026-05-27T11:21:54Z"
             enc: |-
               -----BEGIN PGP MESSAGE-----
   
               hQEMA8qKidnXP+8cAQgAhHlhxnb5wC7afi0GvITSWJ8Tr3LS7yUmvOgql3BHgzkG
               3cS29H5en2/lV4wXgARYPA/1xjM6o5CEMBp/W//AY2Nv1uF3LYsaLkgZ2xCXawrQ
               8SlXGokbUMa6qdXz2mHw5UROT1+b4q2VtSZp0iATwJ8s5a2xALA+AiuJmpEZopIC
               E4aSQpeHKORWLJC1xmlWGgRS7rqIiZVCoL9Zr4bI/urF47zV/IVPi1bLQtqLsWu4
               KFB+VAKX4lE/AN2/4qiDNfJVbkYzKxkTfU710nWgbVEmN/Pd9eiRI9hj0BPrsRFJ
               aqOfe2sTUtLpMp84p5GB4w34xsiScRn1c1M9I1xtXtJeAX53WKO1WSa0saFxutDY
               aFALQCGToqFPMbd7I5I8Or/Mfiga2e0vmp+1M0pXiXUERvbZ92iIwvGWYiw9QT5C
               LY7PHlpqt3JBR2Svd/yzYwxKhkK0HPvtw1qztM84FQ==
               =LyFk
               -----END PGP MESSAGE-----
             fp: F178D4D326B55EB03F8A23A55B9E7F688216D470
       unencrypted_suffix: _unencrypted
       version: 3.11.0
   ```


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


### Salt on Fedora

``` shell
$ dnf install salt salt-minion salt-master

$ rpm -qa salt\* | xargs -I {} sh -c 'rpm -ql $1 | cut -d"/" -f1-4' -- {} \
  | sort -u | grep -Pv '(/etc|/usr/share/(fish|man)|/usr/lib/systemd)' | xargs ls -ld
drwxr-xr-x. 7 root root 4096 Feb 13 16:28 /opt/saltstack/salt
lrwxrwxrwx. 1 root root   24 Feb 13 16:28 /usr/bin/salt -> /opt/saltstack/salt/salt
lrwxrwxrwx. 1 root root   29 Feb 13 16:28 /usr/bin/salt-call -> /opt/saltstack/salt/salt-call
lrwxrwxrwx. 1 root root   27 Feb 13 16:28 /usr/bin/salt-cp -> /opt/saltstack/salt/salt-cp
lrwxrwxrwx. 1 root root   28 Feb 13 16:28 /usr/bin/salt-key -> /opt/saltstack/salt/salt-key
lrwxrwxrwx. 1 root root   31 Feb 13 16:28 /usr/bin/salt-master -> /opt/saltstack/salt/salt-master
lrwxrwxrwx. 1 root root   31 Feb 13 16:28 /usr/bin/salt-minion -> /opt/saltstack/salt/salt-minion
lrwxrwxrwx. 1 root root   28 Feb 13 16:28 /usr/bin/salt-pip -> /opt/saltstack/salt/salt-pip
lrwxrwxrwx. 1 root root   30 Feb 13 16:28 /usr/bin/salt-proxy -> /opt/saltstack/salt/salt-proxy
lrwxrwxrwx. 1 root root   28 Feb 13 16:28 /usr/bin/salt-run -> /opt/saltstack/salt/salt-run
lrwxrwxrwx. 1 root root   23 Feb 13 16:28 /usr/bin/spm -> /opt/saltstack/salt/spm
drwxr-xr-x. 4 root root   34 Feb 13 16:28 /var/cache/salt
drwxr-xr-x. 2 root root   45 Feb 13 16:28 /var/log/salt
drwxr-xr-x. 4 root root   80 Feb 13 16:29 /var/run/salt

$ find /opt/saltstack/salt/ -path '*/bin/python*' -type f
/opt/saltstack/salt/bin/python3.10
/opt/saltstack/salt/bin/python3.10-config

$/opt/saltstack/salt/bin/python3.10 -c 'import sys; print(sys.path)'
['', '/opt/saltstack/salt/extras-3.10', '/opt/saltstack/salt/lib/python310.zip', '/opt/saltstack/salt/lib/python3.10', '/opt/saltstack/salt/lib/python3.10/lib-dynload', '/opt/saltstack/salt/lib/python3.10/site-packages']
```

The Salt project ships Salt with its python version.

### Salt on SLES

If one is using upstream Salt, then it is a bit funny since they ship
all versions in the same repo and `zypper` doesn't support
exclude/include:

``` shell
$ curl -fsSL https://github.com/saltstack/salt-install-guide/releases/latest/download/salt.repo | sed -rn -e '1,/^$/{/^$/q; s/-*repo[^]]+//ig;/^(exclude|enabled_metadata|skip|prio)/d;p}' | tee /etc/zypp/repos.d/salt.repo 
[salt]
name=Salt 
baseurl=https://packages.broadcom.com/artifactory/saltproject-rpm/
enabled=1
gpgcheck=1
gpgkey=https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public

$ zypper -v in --details -r salt-repo-3006-lts 'salt-minion<3007' 'salt-master<3007'

# no surprises, same as on Fedora
$ rpm -qa salt\* | xargs -I {} sh -c 'rpm -ql $1 | cut -d"/" -f1-4' -- {} | \
  sort -u | grep -Pv '(/etc|/usr/share/(fish|man)|/usr/lib/systemd)' | xargs ls -ld
drwxr-xr-x. 1 root root 290 Feb 13 17:30 /opt/saltstack/salt
lrwxrwxrwx. 1 root root  24 Feb 13 17:30 /usr/bin/salt -> /opt/saltstack/salt/salt
lrwxrwxrwx. 1 root root  29 Feb 13 17:30 /usr/bin/salt-call -> /opt/saltstack/salt/salt-call
lrwxrwxrwx. 1 root root  27 Feb 13 17:30 /usr/bin/salt-cp -> /opt/saltstack/salt/salt-cp
lrwxrwxrwx. 1 root root  28 Feb 13 17:30 /usr/bin/salt-key -> /opt/saltstack/salt/salt-key
lrwxrwxrwx. 1 root root  31 Feb 13 17:30 /usr/bin/salt-master -> /opt/saltstack/salt/salt-master
lrwxrwxrwx. 1 root root  31 Feb 13 17:30 /usr/bin/salt-minion -> /opt/saltstack/salt/salt-minion
lrwxrwxrwx. 1 root root  28 Feb 13 17:30 /usr/bin/salt-pip -> /opt/saltstack/salt/salt-pip
lrwxrwxrwx. 1 root root  30 Feb 13 17:30 /usr/bin/salt-proxy -> /opt/saltstack/salt/salt-proxy
lrwxrwxrwx. 1 root root  28 Feb 13 17:30 /usr/bin/salt-run -> /opt/saltstack/salt/salt-run
lrwxrwxrwx. 1 root root  23 Feb 13 17:30 /usr/bin/spm -> /opt/saltstack/salt/spm
drwxr-xr-x. 1 root root  24 Feb 13 17:30 /var/cache/salt
drwxr-xr-x. 1 root root  30 Feb 11 01:00 /var/log/salt
drwxr-xr-x. 3 root root  60 Feb 13 17:30 /var/run/salt

$ zypper al salt salt-master salt-minion
Specified locks have been successfully added.
$ zypper ll

# | Name        | Type    | Repository | Comment
--+-------------+---------+------------+--------
1 | salt        | package | (any)      | 
2 | salt-master | package | (any)      | 
3 | salt-minion | package | (any)      | 
```

### Salt PIP libs

There might not be all python libs needed!

``` shell
$ salt-pip list | grep -ic git
0

$ salt-pip install --root-user-action ignore pygit2
Requirement already satisfied: pygit2 in /opt/saltstack/salt/extras-3.10 (1.18.2)
Requirement already satisfied: cffi>=1.17.0 in /opt/saltstack/salt/lib/python3.10/site-packages (from pygit2) (2.0.0)
Requirement already satisfied: pycparser in /opt/saltstack/salt/lib/python3.10/site-packages (from cffi>=1.17.0->pygit2) (2.21)

$ salt-pip list | grep -i git
pygit2             1.18.2
```


### Salt Grains

- static, system-level facts
- calculated at minion start time
- defined in Python or `/etc/salt/grains`

``` shell
$ salt-call --local grains.items --out json | jq '.local | with_entries(select(.key | match("^os")))'
{
  "os": "Fedora",
  "os_family": "RedHat",
  "oscodename": "",
  "osfullname": "Fedora Linux",
  "osrelease": "43",
  "osarch": "x86_64",
  "osrelease_info": [
    43
  ],
  "osmajorrelease": 43,
  "osfinger": "Fedora Linux-43"
}
```

``` shell
$ salt-call --local grains.get os
local:
    Fedora
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

- using x-oauth personal token

``` shell
# validation
$ read -s TOKEN
github_pat_XXXX

$ curl -L -H "Authorization: Bearer ${TOKEN}" https://api.github.com/repos/<user>/<repo>
```

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

- using GIT backend

Note: I'm using x-oauth personal token here.

``` shell
# validation
$ read -s TOKEN
github_pat_XXXX

$ curl -L -H "Authorization: Bearer ${TOKEN}" https://api.github.com/repos/<user>/<repo>
```

``` shell
$ grep -Pv '^\s*(#|$)' /etc/salt/master{,.d/{local,pillar_git}.conf}
/etc/salt/master:user: salt
/etc/salt/master.d/local.conf:gitfs_provider: pygit2
/etc/salt/master.d/pillar_git.conf:ext_pillar:
/etc/salt/master.d/pillar_git.conf:  - git:
/etc/salt/master.d/pillar_git.conf:      - main https://github.com/jirib/salt-pillars:
/etc/salt/master.d/pillar_git.conf:          - root: pillar
/etc/salt/master.d/pillar_git.conf:          - env: base
/etc/salt/master.d/pillar_git.conf:          - user: github_pat_XXXX
/etc/salt/master.d/pillar_git.conf:          - password: x-oauth-basic
```

``` shell
$ systemctl restart salt-master

# if git repo was recently updated
$ salt-run fileserver.update
```

GIT data are cached in `/var/cache/salt/master/git_pillar`.

``` shell
$ cat /var/cache/salt/master/git_pillar/remote_map.txt 
# git_pillar_remote map as of 17 Feb 2026 13:29:51.649877
M5v5FS7Ih4FoPxRGranJ00N824FI3c7Sp8OsAHJ4UlQ= = main https://github.com/jirib/salt-pillars
8oM4Bd+Cs0xSyFesj6JOFLuPF21oYGJWEBpYvMXqIGM= = main https://github.com/jirib/salt-inventory
```

Note that the GIT branch is checked out only when it is actually needed, for example,
after calling:

``` shell
$ salt-call pillar.ls
local:
    - motd_content
```

``` shell
$ awk '/salt-pillars/ { print $1 }' /var/cache/salt/master/git_pillar/remote_map.txt | \
  xargs -I {} sh -c 'su -s /bin/sh salt -c "git -C /var/cache/salt/master/git_pillar/$1/_ branch --show-current"' -- {}
main

$ awk '/salt-pillars/ { print $1 }' /var/cache/salt/master/git_pillar/remote_map.txt | \
  xargs -I {} sh -c 'su -s /bin/sh salt -c "git -C /var/cache/salt/master/git_pillar/$1/_ rev-parse HEAD"' -- {}
2a35d5541e61c271b8ac4f83dffa13ce7bb91a48
```

- using filesystem

For example in Ansible's [Alternative directory
layout](https://docs.ansible.com/ansible/latest/tips_tricks/sample_setup.html#alternative-directory-layout),
one would in inventories define data/variables for hosts, groups... Similar could be done with *pillar*.

``` shell
$ grep -Pv '^\s*(#|$)' /etc/salt/master | sed -n '/^pillar/,/^[a-z]/p'
pillar_roots:
  base:
    - /srv/pillar

```


## SOPS

> SOPS is an editor of encrypted files that supports YAML, JSON, ENV,
> INI and BINARY formats and encrypts with AWS KMS, GCP KMS, Azure Key
> Vault, HuaweiCloud KMS, age, and PGP.
> https://github.com/getsops/sops

Have _sops_ installed (`mise` can do it).

``` shell
$ yq -oy '.tools' mise.toml 
ansible-core: 2.21.0
sops: latest
```

Quick start:

1. Have a secret GPG key and get its fingerprint:
   ``` shell
   $ gpg --list-key --with-colons | grep -B1 -P 'jirib'
   fpr:::::::::F178D4D326B55EB03F8A23A55B9E7F688216D470:
   uid:u::::1631887954::10EA444A6F4075760D4B84C64A568AF0D5E40566::Jiří XXXX <jiribXXXX>::::::::::0:
   $ gpg --list-key --with-colons | grep -B1 -P 'jirib' | head -n1 | grep -oE '[A-Z0-9]+'
   F178D4D326B55EB03F8A23A55B9E7F688216D470

   $ SOPS_PGP_FP=$(gpg --list-key --with-colons | grep -B1 -P 'jirib' | head -n1 | grep -oE '[A-Z0-9]+')
   ```
2. Encrypt:
   ``` shell
   $ sops --pgp $SOPS_PGP_FP --input-type dotenv --output-type dotenv -e <(cat <<EOF
   name=foo
   password=bar
   EOF
   )
   name=ENC[AES256_GCM,data:m3z7,iv:AIjNEtIYJNiS5SbvPjNDr5S/pggSRtLF231VMbU0SqA=,tag:CrBycoaxT7ZvY56aNwzl8A==,type:str]
   password=ENC[AES256_GCM,data:OEPt,iv:L5g37jFhENA0k5YafcWXqa1gmxVo+6p1wGRhhH1axsM=,tag:U6+MUYAj7sBO5aPxt8oanw==,type:str]
   sops_lastmodified=2026-02-16T15:50:36Z
   sops_mac=ENC[AES256_GCM,data:jKR9N7t1mhA0JC/aLYlWD6hsqzjvmdHEYsqLo0OPuQBBcm6NpbhiNf8cEdlw+nCids5kzequokhPh7nmPapgYtosy4KRwfQNB/zSsLzts/1z11uCxFKnpaAmkPL2qOWI9MnoXmPb5JBAuTNWU+nrh0yZ+Kk1FLggawmczW+zeXg=,iv:Y8tvZriVOlU27CSiCuqwYWBihrKSlUUfO2ItgroGz90=,tag:1rHYHOg14JL70JR8MCsVlA==,type:str]
   sops_pgp__list_0__map_created_at=2026-02-16T15:50:36Z
   sops_pgp__list_0__map_enc=-----BEGIN PGP MESSAGE-----\n\nhQIMA8Wk1m/ZPLjOAQ//fKQqXeDM8kYP1qEugOe8HSoj4IkrlKsfAvCiuV9oszW8\nuynz2weuDU624M/22xcwZTds5NEgYQGdJgkbclFLHnBVImT5HDs/iguXifwUGDMz\nd5RhxwAt7Gp9794K0uiPK6xpLCuSHDmCIHVzRCjLur17D1gc8egaFpBCaRTMW2cL\nkRnwUlPOxTqUUC3jphgsE8r85VXiqcLddrDRUz4MJIXqiLhzcfqdx1JhswzijYnZ\noQ1i5pFmeHiglKvHhHyS7At5pQ3drs/XKMX7QS3Fqe/VlBJ5cuBYmOVVhUmt8+Eh\nBaVtqeC/idqU8WTod5TfycOfvHdZj3HYa630gDvOV/a7UmyhRK8yu5LUBvLVyx/h\ncCVbxdOQsNHvWnTg9/FSoOb+SQ0JP0Rzy+fTt5Rn2gI+HspaUy5p8ydE8MfV4vRy\nkQYXBREWRMn0QmHxCzI+SbXIN9u9HPY/1d0pHxc4HQ7gDLbB4L8o9Fj8TsfnhyOT\nzNYAfG2pCtULoj5pKa3kqoOz+ioKKm98FHe64fnr3xVyK4wI870YDaxTswkh7kQc\nPepUYY5MLGU+dTfSDBXsklCVSClE4mWBVCjYjTP7682b3YkVJVCO7bF+Z/syRWIl\n2S6bI6Z6uqJDpPGi4piK4Ng5RwCGdVVOMVJw27gsGtkNvTG+L1TtLyW1uv/3BU7S\nXgGQIIFGig3WxrApMuoYT03JNcwlYi8J7oO52qKxDT1DPwAk0RW6MZmaxzOC73IM\nhGH3iwXTJqK6ee6OmmsPNubFF6m1N4l+MCklh5SPHMUA6GqlKh6HFpBgS3G6lG4=\n=BFDy\n-----END PGP MESSAGE-----
   sops_pgp__list_0__map_fp=F0586B61E630A3E4E71338D2E1D94F2BA791470A
   sops_unencrypted_suffix=_unencrypted
   sops_version=3.11.0
   ```
