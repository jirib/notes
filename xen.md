# Xen cheatsheet

## kdump

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
ppCopying System.map             Finished.
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

## XCP-ng

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


## Xen on KVM

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
