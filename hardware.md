# Hardware cheatsheet


## IPMI


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


## Supermicro

OMG, supermicro! Anyway, how to generate a license for IPMI to be able to update
their crappy BIOS? See https://techblog.jeppson.org/2018/12/generate-supermicro-ipmi-license/ .

``` shell
$ echo -n 'XX:XX:XX:XX:XX:XX | \
    xxd -r -p | \
    openssl dgst -sha1 -mac HMAC -macopt hexkey:8544E3B47ECA58F9583043F8 | \
    awk '{ printf $2 }' | \
    cut -c 1-24 | \
    sed -r 's/(....)/\1-/g;s/-$//'
yyyy-yyyy-yyyy-yyyy-yyyy-yyyy
```
