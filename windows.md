## Windows

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
