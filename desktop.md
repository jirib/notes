# Unix/Linux Desktop cheatsheet


## Audio


### Pipewire

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


### Pulseaudio

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


## GTK

For version 3, 4... one can customize the themes this way:

``` shell
$ gsettings set org.gnome.desktop.interface font-name 'DejaVu Sans 9'
$ gsettings set org.gnome.desktop.interface icon-theme bloom-classic-dark
$ gsettings set org.gnome.desktop.interface gtk-theme Arc-Dark
```


### GTK: file-chrooser

``` shell
dconf write /org/gtk/settings/file-chooser/sort-directories-first true # dirs first
cat  ~/.config/gtk-3.0/bookmarks # output: file://<absolute_path> <label>
```


## Internet browsers


### Brave browser

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

### Chromium-based browserpass extension

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


## JAVA Icedtea-web

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


## Linux specific desktop tips & tricks

- see monitors
  ``` shell
  ls /sys/class/drm/*/edid | \
    xargs -i {} sh -c "echo {}; parse-edid < {}" 2>/dev/null # get info about monitors
  ```


## Remote desktop


### RDP

[freerdp](https://github.com/FreeRDP/FreeRDP) is newer alternative to
`rdesktop`; it has nice features:

``` shell
$ printf '/u:foo\n/d:.\\\n/v:192.168.100.176\n/cert:ignore\n/auth-pkg-list:ntlm,!kerberos\n/sec:nla' | \
    env FREERDP_ASKPASS='pass show hw/t14s/win11' /opt/freerdp-nightly/bin/xfreerdp3 /args-from:stdin
```


## Utils


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


### File syncing


#### Syncthing

Excluding all but a directory (see
https://docs.syncthing.net/users/ignoring.html for details):

```
!/directory-to-include
// Ignore everything else:
*
```


## Video


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


## Wayland


### foot

Systems might miss `foot` terminfo, so terminal might be broken after
`ssh` etc...

```
$ echo $TERM
foot
$ infocmp $TERM
#	Reconstructed via infocmp from file: /usr/share/terminfo/f/foot
foot|foot terminal emulator,
	am, bce, bw, ccc, hs, mir, msgr, npc, xenl,
	colors#0x100, cols#80, it#8, lines#24, pairs#0x10000,
	acsc=``aaffggiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz{{||}}~~,
	bel=^G, blink=\E[5m, bold=\E[1m, cbt=\E[Z, civis=\E[?25l,
	clear=\E[H\E[2J, cnorm=\E[?12l\E[?25h, cr=\r,
	csr=\E[%i%p1%d;%p2%dr, cub=\E[%p1%dD, cub1=^H,
	cud=\E[%p1%dB, cud1=\n, cuf=\E[%p1%dC, cuf1=\E[C,
	cup=\E[%i%p1%d;%p2%dH, cuu=\E[%p1%dA, cuu1=\E[A,
	cvvis=\E[?12;25h, dch=\E[%p1%dP, dch1=\E[P, dim=\E[2m,
	dl=\E[%p1%dM, dl1=\E[M, dsl=\E]2;\E\\, ech=\E[%p1%dX,
	ed=\E[J, el=\E[K, el1=\E[1K, flash=\E]555\E\\, fsl=\E\\,
	home=\E[H, hpa=\E[%i%p1%dG, ht=^I, hts=\EH, ich=\E[%p1%d@,
	ich1=\E[@, il=\E[%p1%dL, il1=\E[L, ind=\n, indn=\E[%p1%dS,
	initc=\E]4;%p1%d;rgb:%p2%{255}%*%{1000}%/%2.2X/%p3%{255}%*%{1000}%/%2.2X/%p4%{255}%*%{1000}%/%2.2X\E\\,
	invis=\E[8m, is2=\E[!p\E[4l\E>, kDC=\E[3;2~,
	kEND=\E[1;2F, kHOM=\E[1;2H, kIC=\E[2;2~, kLFT=\E[1;2D,
	kNXT=\E[6;2~, kPRV=\E[5;2~, kRIT=\E[1;2C, kbs=^?,
	kcbt=\E[Z, kcub1=\EOD, kcud1=\EOB, kcuf1=\EOC, kcuu1=\EOA,
	kdch1=\E[3~, kend=\EOF, kf1=\EOP, kf10=\E[21~, kf11=\E[23~,
	kf12=\E[24~, kf13=\E[1;2P, kf14=\E[1;2Q, kf15=\E[1;2R,
	kf16=\E[1;2S, kf17=\E[15;2~, kf18=\E[17;2~,
	kf19=\E[18;2~, kf2=\EOQ, kf20=\E[19;2~, kf21=\E[20;2~,
	kf22=\E[21;2~, kf23=\E[23;2~, kf24=\E[24;2~,
	kf25=\E[1;5P, kf26=\E[1;5Q, kf27=\E[1;5R, kf28=\E[1;5S,
	kf29=\E[15;5~, kf3=\EOR, kf30=\E[17;5~, kf31=\E[18;5~,
	kf32=\E[19;5~, kf33=\E[20;5~, kf34=\E[21;5~,
	kf35=\E[23;5~, kf36=\E[24;5~, kf37=\E[1;6P, kf38=\E[1;6Q,
	kf39=\E[1;6R, kf4=\EOS, kf40=\E[1;6S, kf41=\E[15;6~,
	kf42=\E[17;6~, kf43=\E[18;6~, kf44=\E[19;6~,
	kf45=\E[20;6~, kf46=\E[21;6~, kf47=\E[23;6~,
	kf48=\E[24;6~, kf49=\E[1;3P, kf5=\E[15~, kf50=\E[1;3Q,
	kf51=\E[1;3R, kf52=\E[1;3S, kf53=\E[15;3~, kf54=\E[17;3~,
	kf55=\E[18;3~, kf56=\E[19;3~, kf57=\E[20;3~,
	kf58=\E[21;3~, kf59=\E[23;3~, kf6=\E[17~, kf60=\E[24;3~,
	kf61=\E[1;4P, kf62=\E[1;4Q, kf63=\E[1;4R, kf7=\E[18~,
	kf8=\E[19~, kf9=\E[20~, khome=\EOH, kich1=\E[2~,
	kind=\E[1;2B, kmous=\E[<, knp=\E[6~, kpp=\E[5~,
	kri=\E[1;2A, nel=\EE, oc=\E]104\E\\, op=\E[39;49m, rc=\E8,
	rep=%p1%c\E[%p2%{1}%-%db, rev=\E[7m, ri=\EM,
	rin=\E[%p1%dT, ritm=\E[23m, rmacs=\E(B, rmam=\E[?7l,
	rmcup=\E[?1049l\E[23;0;0t, rmir=\E[4l, rmkx=\E[?1l\E>,
	rmm=\E[?1036h\E[?1034l, rmso=\E[27m, rmul=\E[24m,
	rs1=\Ec, rs2=\E[!p\E[4l\E>, sc=\E7,
	setab=\E[%?%p1%{8}%<%t4%p1%d%e%p1%{16}%<%t10%p1%{8}%-%d%e48:5:%p1%d%;m,
	setaf=\E[%?%p1%{8}%<%t3%p1%d%e%p1%{16}%<%t9%p1%{8}%-%d%e38:5:%p1%d%;m,
	sgr=%?%p9%t\E(0%e\E(B%;\E[0%?%p6%t;1%;%?%p5%t;2%;%?%p2%t;4%;%?%p1%p3%|%t;7%;%?%p4%t;5%;%?%p7%t;8%;m,
	sgr0=\E(B\E[m, sitm=\E[3m, smacs=\E(0, smam=\E[?7h,
	smcup=\E[?1049h\E[22;0;0t, smir=\E[4h, smkx=\E[?1h\E=,
	smm=\E[?1036l\E[?1034h, smso=\E[7m, smul=\E[4m,
	tbc=\E[3g, tsl=\E]2;, u6=\E[%i%d;%dR, u7=\E[6n,
	u8=\E[?%[;0123456789]c, u9=\E[c, vpa=\E[%i%p1%dd,

$ ssh somewhere

~> echo $TERM
foot
~> infocmp
infocmp: couldn't open terminfo file /usr/share/terminfo/f/foot.
~> exit

$ infocmp $TERM | ssh somewhere 'tic -x - -o ~/.terminfo'

# or use /etc/terminfo since root's .terminfo is not read for security reasons!

~root> tic -x foot.terminfo -o /etc/terminfo
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


## Word processors


### LibreOffice

- `$HOME/.config/libreoffice/4/user/backup`: super important
  directory! If you, by a mistake, delete a file, you might be
  successful to find it here!!!

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

A Python based LibreOffice extension? An example:

Jak přidat položky do menu pomocí Pythonového rozšíření:

1. **Definice příkazů (commands):**
   - Každá položka menu musí být spojena s příkazem, který definuje akci (např. spuštění funkce).

2. **Registrace položek menu:**
   - Přes XML soubor `menubar.xml` specifikujete, kam bude položka přidána.

3. **Kódování akcí v Pythonu:**
   - V Pythonu vytvoříte logiku, která bude spuštěna při kliknutí na položku.

Struktura rozšíření

Vytvoříme složku s následující strukturou:

``` shell
my_extension/
├── META-INF/
│   └── manifest.xml
├── description.xml
├── Addons.xcu
├── python/
│   ├── __init__.py
│   ├── main.py
├── menus/
│   └── menubar.xml
```

Definice jednotlivých souborů

1\. `manifest.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="http://openoffice.org/2001/manifest">
    <manifest:file-entry manifest:media-type="application/vnd.sun.star.configuration-data" manifest:full-path="Addons.xcu"/>
    <manifest:file-entry manifest:media-type="application/vnd.sun.star.uno-python" manifest:full-path="python/"/>
    <manifest:file-entry manifest:media-type="" manifest:full-path="menus/menubar.xml"/>
</manifest:manifest>
```

2\. `Addons.xcu`

Tento soubor registruje vaše rozšíření a propojuje ho s definicí menu.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<oor:component-data xmlns:oor="http://openoffice.org/2001/registry"
                    xmlns:lo="http://libreoffice.org/2011/extensions"
                    oor:name="Addons" oor:package="org.example.myextension">
    <node oor:name="AddonUI">
        <node oor:name="org.example.myextension.commands">
            <prop oor:name="Title" oor:type="xs:string">
                <value>Můj příkaz</value>
            </prop>
        </node>
    </node>
</oor:component-data>
```

3\. `menubar.xml`

Tento soubor definuje strukturu menu a položky, které chcete přidat.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<menu:menu xmlns:menu="http://openoffice.org/2001/menu">
    <menu:menu-item menu:id="org.example.myextension.commands" menu:label="Můj Příkaz"/>
</menu:menu>
```

4\. `main.py`

Pythonový kód obsahuje logiku, která se provede při kliknutí na menu.

```python
import uno

def my_command():
    ctx = uno.getComponentContext()
    smgr = ctx.ServiceManager
    desktop = smgr.createInstanceWithContext("com.sun.star.frame.Desktop", ctx)
    model = desktop.getCurrentComponent()
    
    # Zobrazení jednoduchého dialogového okna
    msg_box = smgr.createInstanceWithContext("com.sun.star.awt.Toolkit", ctx).createMessageBox(
        None, 0, "informationbox", 1, "Informace", "Spustil se můj příkaz!"
    )
    msg_box.execute()
```

Postup pro vytvoření a instalaci

1. **Zabalte rozšíření:**
   ```bash
   zip -r my_extension.oxt *
   ```

2. **Nainstalujte rozšíření:**
   - Otevřete LibreOffice > **Nástroje > Správce rozšíření > Přidat**.
   - Vyberte vytvořený `.oxt` soubor a restartujte LibreOffice.

3. **Testování:**
   - Po restartu LibreOffice se v hlavním menu objeví vaše položka.
   - Kliknutím na položku spustíte Pythonový příkaz.

Rozšíření a vylepšení

1. **Přidání podnabídek:**
   - V `menubar.xml` můžete definovat hierarchii menu.

2. **Přidání tlačítek na panel nástrojů:**
   - Lze definovat podobným způsobem pomocí souborů `toolbar.xml`.

3. **Více příkazů:**
   - Registrujte více příkazů v `Addons.xcu` a vytvořte odpovídající akce v Pythonu.


Zdroje a dokumentace:
- **UNO API Reference:** [LibreOffice API](https://api.libreoffice.org)
- **Příklady rozšíření:** [LibreOffice Extensions](https://wiki.documentfoundation.org/Development/Extensions)

S tímto přístupem můžete snadno rozšířit funkčnost LibreOffice a přizpůsobit menu vašim potřebám! 😊


## X11


### Window Managers


#### i3WM

To make tray on primary display, do:

``` shell
bar {
    status_command i3status
    tray_output primary
}
```


### XDG

``` shell
xdg-mime query filetype <file>     # returns mime type
xdg-mime query default <mime_type> # returns desktop file
```

To override *exec* like for an `.desktop` file.

``` shell
$ desktop-file-install --dir ~/.local/share/applications/ /usr/share/applications/remote-viewer.desktop
$ desktop-file-edit --set-key=Exec --set-value='myremote-viewer %u' ~/.local/share/applications/remote-viewer.desktop
```

and write your `myremote-viewer` wrapper (eg. to force some options).
