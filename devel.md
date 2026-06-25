# Development cheatsheet


## Applications


### Diffs and patches

To extract hunks from a diff, see https://stackoverflow.com/questions/1990498/how-to-patch-only-a-particular-hunk-from-a-diff.

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


### GitHub CLI

``` shell
$ gh auth status
github.com
  ✓ Logged in to github.com account jiri-belka (keyring)
  - Active account: true
  - Git operations protocol: ssh
  - Token: ghp_************************************
  - Token scopes: 'admin:org', 'admin:public_key', 'delete_repo', 'project', 'repo', 'workflow'

  ✓ Logged in to github.com account jirib (keyring)
  - Active account: false
  - Git operations protocol: ssh
  - Token: gho_************************************
  - Token scopes: 'delete_repo', 'gist', 'read:org', 'repo', 'workflow'
```

``` shell
$ gh repo list --visibility public

Showing 12 of 12 repositories in @jirib that match your search

NAME                      DESCRIPTION                                                                                                             INFO          UPDATED             
jirib/linux-tuning-audit                                                                                                                          public        about 58 minutes ago
jirib/notes                                                                                                                                       public        about 14 hours ago
jirib/wb-country-stats                                                                                                                            public        about 15 hours ago
jirib/sccpkgsearch                                                                                                                                public        about 3 days ago
jirib/anki                                                                                                                                        public        about 3 months ago
jirib/salt-states                                                                                                                                 public        about 10 months ago
jirib/scribus             Community mirror of the official Scribus SVN svn://scribus.net. Please submit PRs & Bugs to https://bugs.scribus.net .  public, fork  about 1 year ago
jirib/scribus-scripts     my scribus python scripts                                                                                               public        about 1 year ago
jirib/nicola-plugins      Extra plugins for Nikola                                                                                                public, fork  about 1 year ago
jirib/pyragegui                                                                                                                                   public        about 2 years ago
jirib/ansible             ansible                                                                                                                 public        about 5 years ago
jirib/vagrant-boxes       Scripts to generate vagrant box files                                                                                   public, fork  about 6 years ago

$ gh auth switch
✓ Switched active account for github.com to jiri-belka

$ gh repo list --visibility public

Showing 2 of 2 repositories in @jiri-belka that match your search

NAME                     DESCRIPTION                                                           INFO          UPDATED          
jiri-belka/supportutils  SUSE Linux Enterprise support utilities. Gathers system information.  public, fork  about 2 days ago
jiri-belka/doc-sleha     Official SUSE Linux Enterprise High Availability documentation        public, fork  about 3 years ago
```


### (GNU) MAKE

AN example how to automate creating of vCenter in KVM:

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


### IDE & editors


#### Emacs

- [TRAMP](https://www.gnu.org/software/tramp/): Transparent Remote Access, Multi Protocol - a built-in
  package allowing seamlessly edit files on remote servers

- [Eglog](https://github.com/joaotavora/eglot): Emacs client for the Languae Server Protocol (LSP)

- Corfu: in-buffer completion with a small completion popup

- [Dape](https://github.com/svaante/dape): [Debug Adapter
  Protocol](https://github.com/microsoft/debug-adapter-protocol) for
  Emacs - a client for DAP, aiming to establish a common API for
  (debugging and) programming tools


##### TRAMP

``` shell
$ emacs '/ssh:10.156.233.50:.'
```
```
  1   /ssh:10.156.233.50:/root: (3.8 GiB available)                                              
  2   drwx------. 1 root           root                 1516 Jun 25 11:32 .                      
  3   drwxr-xr-x. 1 root           root                  210 Jun 10 11:47 ..                     
  4   drwxr-xr-x. 1 root           root                   20 Apr 24 15:47 ~                      
  5   drwx------. 1 root           root                    6 May 31 23:29 .ansible               
  6   -rw-------. 1 root           root                   64 Jun 24 16:29 .authinfo              
  7   -rw-------. 1 root           root                54084 Jun 25 11:32 .bash_history          
  8   -rw-r--r--. 1 root           root                   46 Apr 15 12:48 .bashrc                
  9   drwxr-xr-x. 1 root           root                  100 Apr  7 14:16 bin                    
 10   drwxr-xr-x. 1 root           root                  126 Jun 24 16:29 .cache                 
 11   -rw-r-----. 1 root           root                 1959 Jun 13 03:42 ca.crt                 
 12   -rw-r--r--. 1 root           root                 3999 May 14 21:14 check_pam.py           
-UUU:%%@  F1  ~                   Top   (4,70)     (Dired by name) ------------------------------
```

If a jumphost is needed, then:

``` shell
$ emacs '/ssh:jumphost|ssh:root@192.168.252.150:/root/'
```


##### Eglot

Eglot is a client for the LSP. An example:

``` lisp
(require 'eglot)

(setq eglot-autoshutdown t)
(setq eglot-confirm-server-initiated-edits nil)
(setq eglot-events-buffer-size 0)

;; Language server commands.
;;
;; These commands are executed on the remote host when the buffer is opened via
;; TRAMP, provided the binaries are in tramp-remote-path.
(add-to-list 'eglot-server-programs
             '(python-mode . ("pyright-langserver" "--stdio")))

(add-to-list 'eglot-server-programs
             '(go-mode . ("gopls")))

(add-to-list 'eglot-server-programs
             '(yaml-mode . ("yaml-language-server" "--stdio")))

;; Prefer Taplo for TOML if installed.
(add-to-list 'eglot-server-programs
             '(toml-mode . ("taplo" "lsp" "stdio")))
```

**WARNING**: If you define full path for LSP, this full path is propaged via TRAMP too!

My workaround, comments inline:

``` shell
solved

$ grep -H '' .config/emacs/lisp/{lib-tools,init-eglot}.el
now tools are started via wrapper, which checks if mise is present, if so, using mise x -- <tool> if not using the tool command literally (comments inline):
$ grep -H '' .config/emacs/lisp/{lib-tools,init-eglot}.el
.config/emacs/lisp/lib-tools.el:;;; lib-tools.el -*- lexical-binding: t; -*-
.config/emacs/lisp/lib-tools.el:
.config/emacs/lisp/lib-tools.el:(defun jiri/tool-command (program &rest args)  <---+--- wrapper
.config/emacs/lisp/lib-tools.el:  (let ((cmd (mapconcat #'shell-quote-argument
.config/emacs/lisp/lib-tools.el:                        (cons program args)
.config/emacs/lisp/lib-tools.el:                        " ")))
.config/emacs/lisp/lib-tools.el:    (list
.config/emacs/lisp/lib-tools.el:     "sh" "-c"
.config/emacs/lisp/lib-tools.el:     (format
.config/emacs/lisp/lib-tools.el:      "if command -v mise >/dev/null 2>&1; then exec mise x -- %s; else exec %s; fi"  <---+--- testing mise, works even remotely
.config/emacs/lisp/lib-tools.el:      cmd cmd))))
.config/emacs/lisp/lib-tools.el:
.config/emacs/lisp/lib-tools.el:(defun jiri/project-root ()
.config/emacs/lisp/lib-tools.el:  "Return current project root, or `default-directory' if no project exists."
.config/emacs/lisp/lib-tools.el:  (if-let ((project (project-current nil)))
.config/emacs/lisp/lib-tools.el:      (project-root project)
.config/emacs/lisp/lib-tools.el:    default-directory))
.config/emacs/lisp/lib-tools.el:
.config/emacs/lisp/lib-tools.el:(defun jiri/project-python ()
.config/emacs/lisp/lib-tools.el:  "Return project-local .venv Python if present, otherwise plain python3."
.config/emacs/lisp/lib-tools.el:  (let* ((root (jiri/project-root))
.config/emacs/lisp/lib-tools.el:         (python (expand-file-name ".venv/bin/python" root)))
.config/emacs/lisp/lib-tools.el:    (if (file-executable-p python)
.config/emacs/lisp/lib-tools.el:        python
.config/emacs/lisp/lib-tools.el:      "python3")))
.config/emacs/lisp/lib-tools.el:
.config/emacs/lisp/lib-tools.el:(defun jiri/project-command (program &rest args)
.config/emacs/lisp/lib-tools.el:  "Run PROGRAM ARGS through project .venv if present, otherwise maybe mise.
.config/emacs/lisp/lib-tools.el:
.config/emacs/lisp/lib-tools.el:For Python tools inside a project, prefer .venv/bin/PROGRAM.
.config/emacs/lisp/lib-tools.el:Otherwise use `jiri/tool-command'."
.config/emacs/lisp/lib-tools.el:  (let* ((root (jiri/project-root))
.config/emacs/lisp/lib-tools.el:         (venv-program (expand-file-name
.config/emacs/lisp/lib-tools.el:                        (concat ".venv/bin/" program)
.config/emacs/lisp/lib-tools.el:                        root)))
.config/emacs/lisp/lib-tools.el:    (if (file-executable-p venv-program)
.config/emacs/lisp/lib-tools.el:        (cons venv-program args)
.config/emacs/lisp/lib-tools.el:      (apply #'jiri/tool-command program args))))
.config/emacs/lisp/lib-tools.el:
.config/emacs/lisp/lib-tools.el:(provide 'lib-tools)
.config/emacs/lisp/init-eglot.el:;;; init-eglot.el -*- lexical-binding: t; -*-
.config/emacs/lisp/init-eglot.el:
.config/emacs/lisp/init-eglot.el:(require 'eglot)
.config/emacs/lisp/init-eglot.el:(require 'lib-tools)
.config/emacs/lisp/init-eglot.el:
.config/emacs/lisp/init-eglot.el:(setq eglot-autoshutdown t)
.config/emacs/lisp/init-eglot.el:(setq eglot-confirm-server-initiated-edits nil)
.config/emacs/lisp/init-eglot.el:(setq eglot-events-buffer-size 0)
.config/emacs/lisp/init-eglot.el:
.config/emacs/lisp/init-eglot.el:(with-eval-after-load 'eglot
.config/emacs/lisp/init-eglot.el:  ;; Python
.config/emacs/lisp/init-eglot.el:  (setf (alist-get 'python-mode eglot-server-programs)
.config/emacs/lisp/init-eglot.el:        (lambda (_interactive)
.config/emacs/lisp/init-eglot.el:          (jiri/tool-command "pyright-langserver" "--stdio")))  <---+--- wrapper use
.config/emacs/lisp/init-eglot.el:
.config/emacs/lisp/init-eglot.el:  ;; BASH
.config/emacs/lisp/init-eglot.el:  (setf (alist-get 'shell-mode eglot-server-programs)
.config/emacs/lisp/init-eglot.el:        (lambda (_interactive)
.config/emacs/lisp/init-eglot.el:          (jiri/tool-command "bash-language-server" "--stdio")))
.config/emacs/lisp/init-eglot.el:  ;; Go
.config/emacs/lisp/init-eglot.el:  (setf (alist-get 'go-mode eglot-server-programs)
.config/emacs/lisp/init-eglot.el:        (lambda (_interactive)
.config/emacs/lisp/init-eglot.el:          (jiri/tool-command "gopls")))
.config/emacs/lisp/init-eglot.el:
.config/emacs/lisp/init-eglot.el:  ;; YAML
.config/emacs/lisp/init-eglot.el:  (setf (alist-get 'yaml-mode eglot-server-programs)
.config/emacs/lisp/init-eglot.el:        (lambda (_interactive)
.config/emacs/lisp/init-eglot.el:          (jiri/tool-command "yaml-language-server" "--stdio")))
.config/emacs/lisp/init-eglot.el:
.config/emacs/lisp/init-eglot.el:  ;; TOML
.config/emacs/lisp/init-eglot.el:  (setf (alist-get 'toml-mode eglot-server-programs)
.config/emacs/lisp/init-eglot.el:        (lambda (_interactive)
.config/emacs/lisp/init-eglot.el:          (jiri/tool-command "taplo" "lsp" "stdio")))
.config/emacs/lisp/init-eglot.el:
.config/emacs/lisp/init-eglot.el:  ;; Ansible
.config/emacs/lisp/init-eglot.el:  (setf (alist-get 'ansible-mode eglot-server-programs)
.config/emacs/lisp/init-eglot.el:        (lambda (_interactive)
.config/emacs/lisp/init-eglot.el:          (jiri/tool-command "ansible-language-server" "--stdio"))))
.config/emacs/lisp/init-eglot.el:
.config/emacs/lisp/init-eglot.el:(global-set-key (kbd "C-c l f") #'eglot-format)
.config/emacs/lisp/init-eglot.el:(global-set-key (kbd "C-c l r") #'eglot-rename)
.config/emacs/lisp/init-eglot.el:(global-set-key (kbd "C-c l a") #'eglot-code-actions)
.config/emacs/lisp/init-eglot.el:(global-set-key (kbd "C-c l d") #'xref-find-definitions)
.config/emacs/lisp/init-eglot.el:(global-set-key (kbd "C-c l R") #'xref-find-references)
.config/emacs/lisp/init-eglot.el:(global-set-key (kbd "C-c l e") #'flymake-show-buffer-diagnostics)
.config/emacs/lisp/init-eglot.el:
.config/emacs/lisp/init-eglot.el:(provide 'init-eglot)
```


#### Visual Studio Code

Cool extensions:
- GitLens
- Better Jinja (_Samuel Colvin_'s one because it supports, eg. jinja-shell...)
- Prettier - Code Formatter
- Todo Tree
- YAML (from Red Hat)


##### Debugging in VSCode

_VSCode_ uses `.vscode/launch.json` to provide more specific configuration for
debugging (if such a configuration does not exists, the debugging
would use currently open file, this is helpful if an application
consists of multiple files/modules/libraries).

An example for a python app, here debugging the app with a specific argument:

``` json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "list-indicators argument",
            "type": "debugpy",
            "request": "launch",
            "module": "wb_country_stats",
            "args": ["--list-indicators"],
            "cwd": "${workspaceFolder}",
            "console": "integratedTerminal",
            "justMyCode": true
        },
        {
            "name": "help argument",
            "type": "debugpy",
            "request": "launch",
            "module": "wb_country_stats",
            "args": ["--help"],
            "cwd": "${workspaceFolder}",
            "console": "integratedTerminal",
            "justMyCode": true
        }
    ]
}
```

* _type_: indicates a debugger
* _request_: how to associate to debugging, either _launch_ (launching
  the app) or _attach_ (attaching to a runnnig process)
* _name_: a friendly name of the configuration


##### VSCode Remote-SSH

For SLES to act as SSH target, _jitter_ needs to be disabled in `/etc/ssl/openssl.cnf`.

Also, do not forget that if you want to "export" local
directory/project code to a remote system, you need to sync or use
"reverse SSHFS", the latter is possible via a reverse port forwarding.


### Mise

> \[[Mise\]](https://mise.jdx.dev/) installs and activates the right tools, loads the right env vars, and wires up
> the right tasks for the commands you run.

``` shell
$ tail -n1 ~/.bashrc
eval "$(${HOME}/.local/bin/mise activate bash)"
```

Just use `mise` to install Python version you need.

``` shell
$ mkdir test_project
$ cd $_
$ ls -1a
.

$ mise use python@3.14.3

$ ls -1a
.
..
mise.toml
$ cat mise.toml 
[tools]
python = "3.14.3"

$ which python3
~/.local/share/mise/installs/python/3.14.3/bin/python3

$ (cd ~ ; which python3)
/usr/bin/python3
```

Now, let's assume we just need the latest Python 3.14:

``` shell
$ python3 -V
Python 3.14.3

$ sed -i 's/3.14.3/3.14/' mise.toml

$ mise which python3
/home/jiri/.local/share/mise/installs/python/3.14/bin/python3

$ mise up
$ mise use python@3.14
$ mise which python3
/home/jiri/.local/share/mise/installs/python/3.14/bin/python3

$ python3 -V
Python 3.14.5
```

Tasks are another cool feature in _Mise_, an example `mise.toml`.

``` toml
min_version = "2026.2.4"

[env]
_.python.venv = { path = ".venv", create = true }

[tools]
python = "3.12"
uv = "latest"
ruff = "latest"

[tasks.setup]
description = "Install dependencies and local package in editable mode with dev components"
run = "uv sync"

[tasks.lint]
description = "Lint the code"
run = "ruff check src/"

[tasks."run:sssd-inspector"]
description = "Execute sssd-inspector instantly using local source code"
run = "uv run sssd-inspector"

[tasks."run:supportconfig2sssd-logs"]
description = "Execute supportconfig2sssd-logs instantly using local source code"
run = "uv run supportconfig2sssd-logs"

[tasks.typecheck]
description = "Verify type compliance using pyright"
run = "uv run pyright src/"

[tasks.test]
description = "Run tests"
run = "uv run pytest"

[tasks."install-global"]
description = "Install the finished application locally into an isolated path"
run = "uv tool install . --force"
```

``` shell
$ mise run lint
[lint] $ ruff check src/
All checks passed!

$ mise run typecheck
[typecheck] $ uv run pyright src/
0 errors, 0 warnings, 0 informations
```

Thus, _Mise_ can be used as a build tool in CI too.

For VSCode, there's _Mise VSCode_ extension.


#### Mise on Windows

1. `winget install jdx.mise`
2. `mise use -g uv@latest`
3. `mise exec -- uv run <script>`

An alternative solution, for example if one needs to use an HTTP proxy.

1. powershell
2. `Set-ExecutionPolicy RemoteSigned -scope CurrentUser`
3. `(irm https://astral.sh/uv/install.ps1) -replace '\bexit\b', '#exit removed' | iex`
4. `$env:Path = "C:\Users\user\.local\bin;$env:Path"`
5. Use a [PEP 723](https://peps.python.org/pep-0723/) comfortant
   script, see https://realpython.com/python-script-structure/
6. `uv run <python script>`
   ```
   PS C:\Users\user> uv run .\a5_to_a4.py input.pdf output.pdf
   Installed 1 package in 103ms
   Done: output.pdf
   ```


### OSC

``` shell
$ env PAGER=cat osc list PTF:29457
pacemaker.SUSE_SLE-15-SP5_Update
patchinfo

$ env PAGER=cat osc log PTF:29457/pacemaker.SUSE_SLE-15-SP5_Update
----------------------------------------------------------------------------
r5 | user1 | 2025-03-11 11:15:33 | 3a79f5bc93d2ffb859841d69fb452b60 | unknown | 

PTF build PTF:29457 for example.com. Seqno: 3. Type: TEST

----------------------------------------------------------------------------
r4 | user1 | 2025-03-11 11:05:23 | 970b974c9f39225b9cc57327aefd42bc | unknown | 

PTF build PTF:29457 for example.com. Seqno: 2. Type: TEST

----------------------------------------------------------------------------
r3 | user1 | 2025-03-11 10:13:36 | 241ff8808bad51b1cb6e06842175a3cb | unknown | 

PTF build PTF:29457 for example.com. Seqno: 1. Type: TEST

----------------------------------------------------------------------------
r2 | user1 | 2025-03-11 10:09:25 | 7c16bb24a8ce4ef29216c198429b7bae | unknown | 

Start of the L3 process

Customer: example.com
Incident: YYYYY
Bug:      XXXXXXX


----------------------------------------------------------------------------
r1 | user1 | 2025-03-11 10:08:53 | d66e23590259b751536b371ced1ae32a | unknown | 

<no message>
```

``` shell
$ osc rdiff SUSE:SLE-15-SP5:Update pacemaker PTF:29457 pacemaker.SUSE_SLE-15-SP5_Update | grep -P -- '^(\-{3}|\+{3})\s'
--- pacemaker.changes (revision 6)
+++ pacemaker.changes (revision 5)
--- pacemaker.spec (revision 6)
+++ pacemaker.spec (revision 5)
--- _ptf (added)
+++ _ptf (revision 5)
--- bsc#1238519-libpe_status-consider-parents-of-an-unmanaged-resource-active-on-the-node.patch (added)
+++ bsc#1238519-libpe_status-consider-parents-of-an-unmanaged-resource-active-on-the-node.patch (revision 5)
```

``` shell
$ osc ls | grep REQUEST:366096
SUSE:Maintenance:REQUEST:366096
```

There's also `_servicedata` file which points to OBS internal metadata.


## Programming and markup languages


### C / C++

``` shell
$ nm -D <shared_library> | awk '$2 == "T" { print $NF }' | sort -u # get global library symbols

$ objdump -T <shared_library> | \
  awk 'NR>4 && $2 == "g" && NF ~ /^[a-z]/ { print $NF }' | \
  sort -u                                                        # get global library symbols

$ readelf -sW <shared_library> | \
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


### JSON

Not really a langue or markup format but anyway... A [playgroun](https://jqplay.org/)
for `jq`.


### Perl

For Perl command line, See https://www.perl.com/pub/2004/08/09/commandline.html/.

- `-e` - definition of code to be compiled
- `-n -e` - add implicit loop for code
- `-p -e` - add implitic loop for code and also prints each iteration
  (as *continue* in *while* loop)
- `-a` - *autosplit*, input is split and saved in `@F` array
- `-F` - defines value for split the record (as used in `-a`),
  defaults to whitespace


#### Perl: regex

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


#### Perl: CPAN

How to add a lib/module into a Perl application, or generally, how to use CPAN:

``` shell
# here using `cpan' to add `Mail::SPF' into `~vscan' user home directory
vscan@jb125qb02:~> rm -rf .cpan perl*
vscan@jb125qb02:~> cpan
...
Would you like to configure as much as possible automatically? [yes]
...
What approach do you want?  (Choose 'local::lib', 'sudo' or 'manual')
 [local::lib]
...
Would you like me to automatically choose some CPAN mirror
sites for you? (This means connecting to the Internet) [yes]
...

cpan[1]> install Mail::SPF
...
cpan[1]> exit

vscan@jb125qb02:~> PATH="/var/spool/amavis/perl5/bin${PATH:+:${PATH}}"; export PATH; \
  PERL5LIB="/var/spool/amavis/perl5/lib/perl5${PERL5LIB:+:${PERL5LIB}}"; export PERL5LIB; \
  PERL_LOCAL_LIB_ROOT="/var/spool/amavis/perl5${PERL_LOCAL_LIB_ROOT:+:${PERL_LOCAL_LIB_ROOT}}"; \
  export PERL_LOCAL_LIB_ROOT; \
  PERL_MB_OPT="--install_base \"/var/spool/amavis/perl5\""; export PERL_MB_OPT; \
  PERL_MM_OPT="INSTALL_BASE=/var/spool/amavis/perl5"; export PERL_MM_OPT;

vscan@jb125qb02:~> perl -I$HOME/perl5/lib/perl5 -MMail::SPF -e1; echo $?
0

# a way to "extend" Amavisd to use this perl lib path

$ head -n2 /etc/amavisd.conf 
use strict;
use lib '/var/spool/amavis/perl5/lib/perl5';
```


### PHP

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


#### PHP: PECL

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


### PYTHON

See [python.md](python.md).


### XML

XML Entity Includes allow including an external XML file:

``` shell
$ nl server.xml | sed -n -e '1,4p' -e '/\&connector1-config/p'
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


## Version Control systems


### GIT


#### git-archive

``` shell
$ git archive \
  --format=tar.gz \
  --prefix=foo-0.1.0/ \
  -o ~/rpmbuild/SOURCES/foo-0.1.0.tar.gz \
  HEAD
```

``` shell
$ git tag v0.1.0
$ git archive \
  --format=tar.gz \
  --prefix=foo-0.1.0/ \
  -o ~/rpmbuild/SOURCES/foo-0.1.0.tar.gz \
  v0.1.0
```


#### GIT attributes

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


#### GIT over SSH

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


#### GIT operations

cloning a huge repo could take ages because of its history, adding `--depth 1`
will copy only the latest revision of everything in the repository.

``` shell
$ git clone --depth 1 git@github.com:torvalds/linux.git
```


#### GIT submodules

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

Specific branch for submodules and specific local path for that:

``` shell
$ cat ../.gitmodules ; \
  grep third_party ansible.cfg ; \
  PAGER=cat ansible-doc -t module ansible.legacy.targetcli_iscsi_tpg | grep Ji
[submodule "ansible_ng/third_party/ansible.targetcli_modules"]
	path = ansible_ng/third_party/ansible.targetcli_modules
	url = https://github.com/jirib/ansible.targetcli_modules.git
	branch = jirib-improvements
library = ./third_party/ansible.targetcli_modules/plugins/modules
AUTHOR: Jiří Bělka (@jirib79)
```


#### GIT-LFS

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


#### GIT tricks & tips

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


## SVN

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
```

SVN diff with function context:

``` shell
$ svn diff --diff-cmd=diff -x '-uNp'
Index: scribus/ui/printdialog.cpp
===================================================================
--- scribus/ui/printdialog.cpp  (revision 26874)
+++ scribus/ui/printdialog.cpp  (working copy)
@@ -501,6 +501,7 @@ void PrintDialog::storeValues()
        {
                m_doc->Print_Options.printerCommand = altCommand->text();
                m_doc->Print_Options.useAltPrintCommand = true;
+               m_doc->Print_Options.toFile = false;
        }
        else
                m_doc->Print_Options.useAltPrintCommand = false;
@@ -543,6 +544,7 @@ void PrintDialog::setStoredValues(const
        {
                selectCommand();
                altCommand->setText(m_doc->Print_Options.printerCommand);
+               m_doc->Print_Options.toFile = false;
        }
        printAllRadio->setChecked(prefs->getBool("PrintAll", true));
        printCurrentRadio->setChecked(prefs->getBool("CurrentPage", false));
```
