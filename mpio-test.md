# mpio test

## libvirt

``` shell
cat > /tmp/test1 <<EOF
<network>
  <name>test1</name>
  <uuid>6e51db8d-c67b-41d2-8400-48c82e6e20ec</uuid>
  <bridge name='virbr1' stp='on' delay='0'/>
  <mac address='52:54:00:90:6b:81'/>
  <domain name='test1'/>
  <ip address='192.168.123.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.123.128' end='192.168.123.254'/>
    </dhcp>
  </ip>
</network>
EOF

virsh net-define /tmp/test1
virsh net-autostart test1
virsh net-start test1

cat > /tmp/test2 <<EOF
<network>
  <name>test1</name>
  <uuid>6e51db8d-c67b-41d2-8400-48c82e6e20ec</uuid>
  <bridge name='virbr1' stp='on' delay='0'/>
  <mac address='52:54:00:90:6b:81'/>
  <domain name='test1'/>
  <ip address='192.168.123.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.123.128' end='192.168.123.254'/>
    </dhcp>
  </ip>
</network>
EOF

virsh net-define /tmp/test2
virsh net-autostart test2
virsh net-start test2
```

## iscsi

``` shell
targetcli /backstores/fileio create mpio01 /home/iscsi/mpio01.raw 1G # block
targetcli /iscsi create iqn.2021-05.home.arpa:t14s-mpio              # target
targetcli /iscsi/iqn.2021-05.home.arpa:t14s-mpio/tpg1/portals \
  create 192.168.123.1                                               # portal on test1
targetcli /iscsi/iqn.2021-05.home.arpa:t14s-mpio/tpg1/portals \
  create 192.168.124.1                                               # portal on test2
```

...to be continued...
