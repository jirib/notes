# DevOps cheatsheet


## Hashicorp ecosystem


### Hashicorp: Packer

``` shell
$ git clone https://github.com/asdf-vm/asdf.git ~/.asdf --branch v0.14.0
$ . "$HOME/.asdf/asdf.sh"
$ . "$HOME/.asdf/completions/asdf.bash"
$ asdf plugin add packer
$ asdf install packer latest
$ asdf global packer latest
```

Usually, Packer plugins are installed via `packer init`; they might be defined in a file ending with `pkr.hcl`:

``` shell
# plugins

$ find .config/packer/plugins -type f -name 'packer-plugin*amd64'
.config/packer/plugins/github.com/hashicorp/vsphere/packer-plugin-vsphere_v1.4.0_x5.0_linux_amd64
.config/packer/plugins/github.com/hashicorp/ansible/packer-plugin-ansible_v1.1.1_x5.0_linux_amd64
.config/packer/plugins/github.com/hashicorp/qemu/packer-plugin-qemu_v1.1.0_x5.0_linux_amd64

$ grep -H '' !(*var*|*templ*).pkr.hcl
provider.pkr.hcl:packer {
provider.pkr.hcl:  required_version = ">= 1.10.0"
provider.pkr.hcl:  required_plugins {
provider.pkr.hcl:    vsphere = {
provider.pkr.hcl:      version = ">= 1.3.0"
provider.pkr.hcl:      source  = "github.com/hashicorp/vsphere"
provider.pkr.hcl:    }
provider.pkr.hcl:    ansible = {
provider.pkr.hcl:      version = ">= 1.1.0"
provider.pkr.hcl:      source  = "github.com/hashicorp/ansible"
provider.pkr.hcl:    }
provider.pkr.hcl:    qemu = {
provider.pkr.hcl:      version = ">= 1.1.0"
provider.pkr.hcl:      source = "github.com/hashicorp/qemu"
provider.pkr.hcl:    }
provider.pkr.hcl:  }
provider.pkr.hcl:}
```

If you define a variable which is _sensitive_, then do NOT define it
inside Packer templates; or it might end in the artifact and,
oops... It's better to fail if such a variable is not defined properly
_outside_ of the _fixed_ template files. See [Assigning Values to
input
Variables](https://developer.hashicorp.com/packer/docs/templates/hcl_templates/variables#assigning-values-to-input-variables):

``` shell
$ packer validate -var-file=$(echo *.pkrvars.hcl) .
Error: Unset variable "ssh_private_key_file"

A used variable must be set or have a default value; see
https://packer.io/docs/templates/hcl_templates/syntax for details.

Error: Unset variable "root_password"

A used variable must be set or have a default value; see
https://packer.io/docs/templates/hcl_templates/syntax for details.

Error: Unset variable "encrypted_bootloader_password"

A used variable must be set or have a default value; see
https://packer.io/docs/templates/hcl_templates/syntax for details.
```

And, a real example:

``` shell
$ ls -l template.pkr.hcl
-rw-r--r--. 1 root root 8735 Aug 21 08:38 template.pkr.hcl

$ PACKER_LOG=1 packer build \
  -var=root_password=foobar \
  -var=encrypted_bootloader_password=foobar \
  -var=build_username=packer \
  -var=ssh_private_key_file=.ssh/id_rsa \
  -var-file=variables.pkrvars.hcl .
```

Packer can server "dynamic" files via HTTP:

``` hcl
locals {
  data_source_content = {
    autoinstxml = templatefile("${abspath(path.root)}/data/autoinst.pkrtpl.hcl", {
      build_username                   = var.build_username
      build_user_id                    = var.build_user_id
      encrypted_bootloader_password    = var.encrypted_bootloader_password
      vm_guest_os_language             = var.vm_guest_os_language
      vm_guest_os_keyboard             = var.vm_guest_os_keyboard
      vm_guest_os_timezone             = var.vm_guest_os_timezone
      vm_guest_os_cloudinit            = var.vm_guest_os_cloudinit
      additional_packages              = var.additional_packages
      reg_server                       = regex_replace(var.reg_server, "https?://", "")
      reg_server_cert_fingerprint_type = var.reg_server_cert_fingerprint_type
      reg_server_cert_fingerprint      = var.reg_server_cert_fingerprint
      reg_server_install_updates       = var.reg_server_install_updates
      reg_server_addons                = var.reg_server_addons
      reg_server_os_level              = var.reg_server_os_level
      reg_server_os_arch               = var.reg_server_os_arch
      proxy_enabled                    = var.proxy_enabled
      proxy_host                       = var.proxy_host
      no_proxy                         = var.no_proxy
    })
  }
  # for 'boot_cmd'
  data_source_command = " netsetup=dhcp autoyast=http://{{ .HTTPIP }}:{{ .HTTPPort }}/autoinst.xml rootpassword=${var.root_password}"
}

source "qemu" "root_iso" {
  ...
  http_content = {
    "/autoinst.xml" = "${local.data_source_content.autoinstxml}"
  }
  ...
```

Packer QEMU builder notes:

``` hcl
source "qemu" "root_iso" {
  ...
  qemu_binary = "/usr/libexec/qemu-kvm"
  display = "none"
  use_default_display = true

  vm_name              = "SLES15SP6-template"
  memory               = var.vm_mem_size
  disk_size            = var.vm_disk_size
  cpus                 = var.vm_cpu_count
  format               = "qcow2"
  disk_interface       = element(var.vm_disk_controller_type, 0)
  disk_compression     = true
  accelerator          = "kvm"
  headless             = "false"
  machine_type         = "q35"
  cpu_model            = "host"
  net_device           = var.vm_network_card
  vtpm                 = true
  efi_firmware_code    = "ovmf-x86_64-smm-suse-code.bin"
  efi_firmware_vars    = "ovmf-x86_64-smm-suse-vars.bin"
  ...

  # log to serial console file-backend, not everything seems to work correctly !!!
  qemuargs             = [
          ["-vga", "virtio"],
          ["-serial", "file:/tmp/ttyS0.log"]
  ]

  ...
  # SLES/OpenSUSE specific
  boot_command = [
    "<esc>",
    "e",
    "<down><down><down><down><end>",
    "${local.data_source_command}",
    "<f10>"
  ]

  ...
```

Packer cache is located at `./packer_cache` by default, or
`PACKER_CACHE_DIR` environment variable, see:
https://developer.hashicorp.com/packer/docs/configure#configure-the-cache-directory.

To debug Packer/boot of a VM, one might do:

- add `-monitor telnet:127.0.0.1:5555,server,nowait` to `qemuargs`
- add `-S` to `qemuargs` (starts QEMU in stopped mode)

```
$ PACKER_lOG=1 packer build -debug...
...
==> qemu.root_iso: Overriding default Qemu arguments with qemuargs template option...
2025/02/21 09:09:14 packer-plugin-qemu_v1.1.0_x5.0_linux_amd64 plugin: 2025/02/21 09:09:14 Executing /usr/libexec/qemu-kvm: []string{"-name", "Linux-SLES15SP6-Minimal", "-chardev", "socket,id=vtpm,path=/tmp/2901371886/vtpm.sock", "-machine", "type=q35,accel=kvm", "-vga", "virtio", "-serial", "file:/tmp/ttyS0.log", "-vnc", "127.0.0.1:52", "-m", "2048M", "-cpu", "host", "-device", "virtio-scsi-pci,id=scsi0", "-device", "scsi-hd,bus=scsi0.0,drive=drive0", "-device", "virtio-net,netdev=user.0", "-device", "tpm-tis,tpmdev=tpm0", "-smp", "2", "-tpmdev", "emulator,id=tpm0,chardev=vtpm", "-drive", "if=none,file=/data/install/__temp__/out/Linux-SLES15SP6-Minimal,id=drive0,cache=writeback,discard=ignore,format=qcow2", "-drive", "file=/data/install/__temp__/usb.img,media=cdrom", "-drive", "file=ovmf-x86_64-smm-suse-code.bin,if=pflash,unit=0,format=raw,readonly=on", "-drive", "file=/data/install/__temp__/out/efivars.fd,if=pflash,unit=1,format=raw", "-netdev", "user,id=user.0,hostfwd=tcp::2313-:22"}
...
```

An ungly hack to allow an installation from a disk image, that is, a
copy of an usb bootable media; note, it's not an installation with a
backing image!

``` hcl
source "qemu" "root_iso" {
  iso_url = "/data/install/__temp__/usb.img"
...
  qemuargs             = [
  ...
          ["-device", "ahci,id=ahci0"],
          ["-device", "ide-hd,drive=sata0,bus=ahci0.1"],
          ["-device", "ide-hd,drive=sata1,bus=ahci0.2"],
          ["-drive", "if=none,file=/data/install/__temp__/usb.img,id=sata0,cache=writeback,discard=ignore,format=raw,file.locking=off"], <---+--- same as iso_url
          ["-drive", "if=none,file=/data/install/__temp__/out/Linux-SLES15SP6-Minimal,id=sata1,cache=writeback,discard=ignore,format=qcow2,file.locking=off"] <---+--- as vm_name
  ]
```


## Hashicorp: Vault

**NOTE:** Sharing publicly Vault token, keys is stupid but this is a test instance!!!

By default `init` would create 5 keys with 3 keys required to unseal.

``` shell
$ vault operator init
Unseal Key 1: <key1>
Unseal Key 2: <key2>
Unseal Key 3: <key3>
Unseal Key 4: <key4>
Unseal Key 5: <key5>

Initial Root Token: <token>

Vault initialized with 5 key shares and a key threshold of 3. Please securely
distribute the key shares printed above. When the Vault is re-sealed,
restarted, or stopped, you must supply at least 3 of these keys to unseal it
before it can start servicing requests.

Vault does not store the generated root key. Without at least 3 keys to
reconstruct the root key, Vault will remain permanently sealed!

It is possible to generate new unseal keys, provided you have a quorum of
existing unseal keys shares. See "vault operator rekey" for more information.
```

1. use 'key' to unseal (here one key is enough to unseal!!!)

``` shell
$ export VAULT_ADDR=https://avocado.example.com:8200
$ export VAULT_TOKEN=<token>

$ vault status
Key                Value
---                -----
Seal Type          shamir
Initialized        true
Sealed             true <---+--- !!!
Total Shares       1
Threshold          1
Unseal Progress    0/1
Unseal Nonce       n/a
Version            1.12.3
Build Date         2023-02-02T09:07:27Z
Storage Type       file
HA Enabled         false

$ vault operator unseal
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false
Total Shares    1
Threshold       1
Version         1.12.3
Build Date      2023-02-02T09:07:27Z
Storage Type    file
Cluster Name    vault-cluster-3904eff6
Cluster ID      45238404-cc0a-f9d1-a65e-07b57d32034f
HA Enabled      false

$ vault status
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false <---+--- !!!
Total Shares    1
Threshold       1
Version         1.12.3
Build Date      2023-02-02T09:07:27Z
Storage Type    file
Cluster Name    vault-cluster-3904eff6
Cluster ID      45238404-cc0a-f9d1-a65e-07b57d32034f
HA Enabled      false
```

2. you can login via browser with 'root.token'

``` shell
$ export VAULT_ADDR=https://avocado.example.com:8200
$ export VAULT_TOKEN=<token>
```

#### Hashicorp vault: pki secrets engine

``` shell
$ vault secrets list
Path          Type         Accessor              Description
----          ----         --------              -----------
cubbyhole/    cubbyhole    cubbyhole_ea287431    per-token private secret storage
identity/     identity     identity_0dc45c85     identity store
sys/          system       system_0378cabc       system endpoints used for control, policy and debugging

$ vault secrets enable -description=hashiCorpVaultCA pki
Success! Enabled the pki secrets engine at: pki/

$ vault secrets list
Path          Type         Accessor              Description
----          ----         --------              -----------
cubbyhole/    cubbyhole    cubbyhole_ea287431    per-token private secret storage
identity/     identity     identity_0dc45c85     identity store
pki/          pki          pki_65e37d8e          hashiCorpVaultCA <---+--- !!!
sys/          system       system_0378cabc       system endpoints used for control, policy and debugging
```

Importing existing CA cert and key into Vault:

``` shell
$ jq -n --arg v "$(cat ca.crt ca.key)" '{"pem_bundle": $v }' > payload.json

$ curl -s -H "X-Vault-Token: <token>" -X POST --data "@payload.json" https://avocado.example.com:8200/v1/pki/config/ca
```

Creating a role which allows issuing of certs:

``` shell
$ vault write pki/roles/example-dot-com allowed_domains="*example.com" allow_glob_domains=true allow_subdomains=true     max_ttl=72h
Success! Data written to: pki/roles/example-dot-com
```

Issue/request a cert (note that role should be linked to a user/group
in production).

``` shell
$ vault write pki/issue/example-dot-com \
  common_name=jb154sapqe01.example.com \
  alt_names="jb154sapqe01.example.com,example.com,*.example.com"
WARNING! The following warnings were returned from Vault:

  * TTL "768h0m0s" is longer than permitted maxTTL "72h0m0s", so maxTTL is
  being used

Key                 Value
---                 -----
ca_chain            [-----BEGIN CERTIFICATE-----
MIIFxjCCA66gAwIBAgIUCWy6A27QQO8sdQcFz+S4Or2iD9YwDQYJKoZIhvcNAQEL
BQAwezELMAkGA1UEBhMCQ1oxDzANBgNVBAgMBlByYWd1ZTEPMA0GA1UEBwwGUHJh
Z3VlMSMwIQYDVQQKDBphdm9jYWRvIEhhc2hpQ29ycCBWYXVsdCBDQTElMCMGA1UE
AwwcYXZvY2Fkb0hhc2hpQ29ycFZhdWx0Q0EgMjAyMzAeFw0yMzAyMjExMTA4MzNa
Fw0yMzAzMjMxMTA4MzNaMHsxCzAJBgNVBAYTAkNaMQ8wDQYDVQQIDAZQcmFndWUx
DzANBgNVBAcMBlByYWd1ZTEjMCEGA1UECgwaYXZvY2FkbyBIYXNoaUNvcnAgVmF1
bHQgQ0ExJTAjBgNVBAMMHGF2b2NhZG9IYXNoaUNvcnBWYXVsdENBIDIwMjMwggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQClI0POCUzvpkGWo/RbNJEkYi/0
WifzjQI5bpfa9TyjyVuQHkCKRMv2iyNSxxGCeNCuMoSVitxC/rpEvQf9SvhVcAfT
vu8MPg2ptWn4ACjsmxYBe5N3RGSEPXmMwc8XTY+ZIdgcF9PuvIcqz8A1uN+C1Qpc
pxm8HsuAOp/HFJMZ8uFRO6/akAmBbZwQi/8X6aXY8hMMtF638RdxJDQS6I30cEvX
q57gsNCX68fQOiNmZw1K2Ra8soEldfG7BXJruKkCaUbfGeqsEmShld+FMYGiDJuJ
ti1FdGdyCshxHEFlK90WCUYKKrjxn0zBcQmkfD5qhyOSDu9GJ07kHhmI9zme4NTC
SOMmK6HEhBCATsGo3ckxcg7BefcwhFjXIlWhsXXIAW1LakTT62M/K3SrrD/3u+Ad
egIceirlbx5i+7aBdg+obnp3R8ZSCNwB5t3nIbj4wPivsBQKmf60O+kXvk9psXK0
w6xjPLH4HuWHO4IE6lNeGfvuIlBMuIupoVyqH+G0LRvTOaSQ1aY3dZwmzh2luopE
E1NWWWtluEYmC8uF9cpUm4z9n0D45ULSZ+BXwHFEAvC09xdKSOrdghicOvhOfIGA
4V0eOGhXeqGlG1PsoPDpGrV7tIAJxRHYz4F6kcKU7Tnv6yX95bNCN6sEO7K1ZDza
gBDvkYIieTSzSSFZDwIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/
BAUwAwEB/zAdBgNVHQ4EFgQU7zH1WVWqWYutUhYK0zxMAPCNBvEwDQYJKoZIhvcN
AQELBQADggIBABgxIgH/biVsxN+7fBl+5ar/uW5yeLAomaVz7/762MX8yifY9qP5
IhAQRF8HPv6YkPoBOJROtmE4oZmbmGth1cDqIZEIaKzTu7Pum/CR48lYkheOD4Jx
R4U4fhJv7Un1/gkpuNEJ7LmBaIdXwg2LLLD1yUa7v19lZIcMZ/nA+fTA4L0SXHo+
tUxP9Yzyk+j2X+DHvdSctdUYlXNNz8leY+g8Zw/Q4BDfm2e6cohjnQ0h/zOA1Drl
ZHs4oLjkngu55/kwuq55kv5A7+lKf4Vq00jEzgueD8Gr5XQ8MnWgn9GvohqQxn+t
WNcn/gZLIHgyfyMwXOBKYULg32HQjzaeRgjm5Le9znI5TK6jTTUz0fGbkQWkGgYF
l9Qm9q0wwUmnDHL2PA/Rlm/upS2Fb9/U/oY7tD6CUIvfeGwBMssgLFyp3ap6Uj8D
ObgOw5wUvS0A9XauZmY2DEwdqYdHGentx0Fl3s+bazApKCdkmwYl6j6EiHYlqKPw
GGiEfAVoXhbRkt/m2oiNReTGYDaHoqI8PfyhVV5pQctEXt3GWNPzXG/02XUcpL3H
NeGsb39wF0PfwSuy/37ZgvTWNR74FTLm4ZJ4LVMVJ52O9GhKt8SGpfFzJJGge0ZX
GVmyR4YFKBSOJ4If53xIFBUCfa4uiyrqw4VbvgEd2l9uZYQgmz0Re1yI
-----END CERTIFICATE-----]
certificate         -----BEGIN CERTIFICATE-----
MIIFaDCCA1CgAwIBAgIUaeDqKZV2JPw9OBLqwdgD8PamcDUwDQYJKoZIhvcNAQEL
BQAwezELMAkGA1UEBhMCQ1oxDzANBgNVBAgMBlByYWd1ZTEPMA0GA1UEBwwGUHJh
Z3VlMSMwIQYDVQQKDBphdm9jYWRvIEhhc2hpQ29ycCBWYXVsdCBDQTElMCMGA1UE
AwwcYXZvY2Fkb0hhc2hpQ29ycFZhdWx0Q0EgMjAyMzAeFw0yMzAyMjExMjA5MTda
Fw0yMzAyMjQxMjA5NDdaMCMxITAfBgNVBAMTGGpiMTU0c2FwcWUwMS5leGFtcGxl
LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANxqYVrxnoz1G/fP
Nm6tw+Aql8nh0MkUe8ZOAlXqze69bGZr4iJnsNnhVtFBXQEhqQxUVv8uYMgvtFyJ
/UXcg+yWp6DgPnwpkSAxe51mKaoVMogHO8dPxJIApWqGqttKBhmlOmdvzbnQynqF
6d6X0Rdy91edFrnxwuG9o1vu0E4Oo/nMCGg40xqQkOPi2DFhX/6EzFrTEyNqTo20
mObKu9id/2M7+his2zDvpCtBW1BaKS5x58A+9QkVY4B+4U8/DqkJUNiEc2VqrSnD
Gd3pwAJYvakw+oDZAbmSMosejPzwDXkP89+9dBK0yhLelo2tF+Lk+VXnKTsu5xUh
IJxEkUMCAwEAAaOCATowggE2MA4GA1UdDwEB/wQEAwIDqDAdBgNVHSUEFjAUBggr
BgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFE01xwNbCr6lKv5OyeDjDaTy2WLo
MB8GA1UdIwQYMBaAFO8x9VlVqlmLrVIWCtM8TADwjQbxMEYGCCsGAQUFBwEBBDow
ODA2BggrBgEFBQcwAoYqaHR0cHM6Ly9hdm9jYWRvLmV4YW1wbGUuY29tOjgyMDAv
djEvcGtpL2NhMD8GA1UdEQQ4MDaCDSouZXhhbXBsZS5jb22CC2V4YW1wbGUuY29t
ghhqYjE1NHNhcHFlMDEuZXhhbXBsZS5jb20wPAYDVR0fBDUwMzAxoC+gLYYraHR0
cHM6Ly9hdm9jYWRvLmV4YW1wbGUuY29tOjgyMDAvdjEvcGtpL2NybDANBgkqhkiG
9w0BAQsFAAOCAgEAlbzAd4fI1XT2hfjobf4dbjvfLaKNfh9/WQ3dGJ9W3QHQfw89
GELAu7Uw+VFqME6HVEKue3fKf8TwL4+GuwTX24WvOS57y4+u3xFm3rAmDs9ar5tM
xerwuq9YxqUabpNktXXaZYBNiusiAuZUh/U40UzGa5vHRZa7kpOLumFFQMqKBMRI
rekqFETjJTScSDXOCS2NMZZp+2pt8G5bC+rFtKGbdc/c/BXtBZYrWVFEK4Fm9Jq9
yIL2LmGuJbcHNZN/Dpo8rcFr5uYFubLwilKRj3ecWBB1T6JtefSy9MXAeqaTeMyz
b9uRzlM2NLbwXM6y8yDvVq6tQulw/6oEaElpc9byYf10mV/FIJH/sZzTrBM9L2cC
GJIGVbIqGlFenA6nFehOfocgCNJrwlSe/cq/akd/ZzPwBKE12JtufcXs5jYs2Wlx
QdstthGk4hp90ugGwEHYoIGaZqDlOhyniK1RCsFEXA9gY37saEPdBltcltMqw7qd
1i8ngqQEadSzEyDEGGvlUbR2F9YZZaJyPk+42qlx5rtox3igwilILV/qf8s2Wibv
QvTsxYUgKA1A+w0pFcdNQmZD9tb+cvlC+QEijrXp799R/mXO6VpYuqcOj/jXx1na
ZzAjS0/g+XheiOki72DUlxPN6YlRKDxxthTFViohKAEYsf+KHcgBotfHLoI=
-----END CERTIFICATE-----
expiration          1677240587
issuing_ca          -----BEGIN CERTIFICATE-----
MIIFxjCCA66gAwIBAgIUCWy6A27QQO8sdQcFz+S4Or2iD9YwDQYJKoZIhvcNAQEL
BQAwezELMAkGA1UEBhMCQ1oxDzANBgNVBAgMBlByYWd1ZTEPMA0GA1UEBwwGUHJh
Z3VlMSMwIQYDVQQKDBphdm9jYWRvIEhhc2hpQ29ycCBWYXVsdCBDQTElMCMGA1UE
AwwcYXZvY2Fkb0hhc2hpQ29ycFZhdWx0Q0EgMjAyMzAeFw0yMzAyMjExMTA4MzNa
Fw0yMzAzMjMxMTA4MzNaMHsxCzAJBgNVBAYTAkNaMQ8wDQYDVQQIDAZQcmFndWUx
DzANBgNVBAcMBlByYWd1ZTEjMCEGA1UECgwaYXZvY2FkbyBIYXNoaUNvcnAgVmF1
bHQgQ0ExJTAjBgNVBAMMHGF2b2NhZG9IYXNoaUNvcnBWYXVsdENBIDIwMjMwggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQClI0POCUzvpkGWo/RbNJEkYi/0
WifzjQI5bpfa9TyjyVuQHkCKRMv2iyNSxxGCeNCuMoSVitxC/rpEvQf9SvhVcAfT
vu8MPg2ptWn4ACjsmxYBe5N3RGSEPXmMwc8XTY+ZIdgcF9PuvIcqz8A1uN+C1Qpc
pxm8HsuAOp/HFJMZ8uFRO6/akAmBbZwQi/8X6aXY8hMMtF638RdxJDQS6I30cEvX
q57gsNCX68fQOiNmZw1K2Ra8soEldfG7BXJruKkCaUbfGeqsEmShld+FMYGiDJuJ
ti1FdGdyCshxHEFlK90WCUYKKrjxn0zBcQmkfD5qhyOSDu9GJ07kHhmI9zme4NTC
SOMmK6HEhBCATsGo3ckxcg7BefcwhFjXIlWhsXXIAW1LakTT62M/K3SrrD/3u+Ad
egIceirlbx5i+7aBdg+obnp3R8ZSCNwB5t3nIbj4wPivsBQKmf60O+kXvk9psXK0
w6xjPLH4HuWHO4IE6lNeGfvuIlBMuIupoVyqH+G0LRvTOaSQ1aY3dZwmzh2luopE
E1NWWWtluEYmC8uF9cpUm4z9n0D45ULSZ+BXwHFEAvC09xdKSOrdghicOvhOfIGA
4V0eOGhXeqGlG1PsoPDpGrV7tIAJxRHYz4F6kcKU7Tnv6yX95bNCN6sEO7K1ZDza
gBDvkYIieTSzSSFZDwIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/
BAUwAwEB/zAdBgNVHQ4EFgQU7zH1WVWqWYutUhYK0zxMAPCNBvEwDQYJKoZIhvcN
BAUwAwEB/zAdBgNVHQ4EFgQU7zH1WVWqWYutUhYK0zxMAPCNBvEwDQYJKoZIhvcN
AQELBQADggIBABgxIgH/biVsxN+7fBl+5ar/uW5yeLAomaVz7/762MX8yifY9qP5
IhAQRF8HPv6YkPoBOJROtmE4oZmbmGth1cDqIZEIaKzTu7Pum/CR48lYkheOD4Jx
R4U4fhJv7Un1/gkpuNEJ7LmBaIdXwg2LLLD1yUa7v19lZIcMZ/nA+fTA4L0SXHo+
tUxP9Yzyk+j2X+DHvdSctdUYlXNNz8leY+g8Zw/Q4BDfm2e6cohjnQ0h/zOA1Drl
ZHs4oLjkngu55/kwuq55kv5A7+lKf4Vq00jEzgueD8Gr5XQ8MnWgn9GvohqQxn+t
l9Qm9q0wwUmnDHL2PA/Rlm/upS2Fb9/U/oY7tD6CUIvfeGwBMssgLFyp3ap6Uj8D
ObgOw5wUvS0A9XauZmY2DEwdqYdHGentx0Fl3s+bazApKCdkmwYl6j6EiHYlqKPw
GGiEfAVoXhbRkt/m2oiNReTGYDaHoqI8PfyhVV5pQctEXt3GWNPzXG/02XUcpL3H
NeGsb39wF0PfwSuy/37ZgvTWNR74FTLm4ZJ4LVMVJ52O9GhKt8SGpfFzJJGge0ZX
GVmyR4YFKBSOJ4If53xIFBUCfa4uiyrqw4VbvgEd2l9uZYQgmz0Re1yI
-----END CERTIFICATE-----
private_key         -----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3GphWvGejPUb9882bq3D4CqXyeHQyRR7xk4CVerN7r1sZmvi
Imew2eFW0UFdASGpDFRW/y5gyC+0XIn9RdyD7JanoOA+fCmRIDF7nWYpqhUyiAc7
x0/EkgClaoaq20oGGaU6Z2/NudDKeoXp3pfRF3L3V50WufHC4b2jW+7QTg6j+cwI
aDjTGpCQ4+LYMWFf/oTMWtMTI2pOjbSY5sq72J3/Yzv6GKzbMO+kK0FbUFopLnHn
wD71CRVjgH7hTz8OqQlQ2IRzZWqtKcMZ3enAAli9qTD6gNkBuZIyix6M/PANeQ/z
3710ErTKEt6Wja0X4uT5VecpOy7nFSEgnESRQwIDAQABAoIBAQCLTEfeu9ih6L4W
LMSPyg2CfCiVk7rpeaKHvwFG3y/qc5gwWnn9mF5yNDEz6gUnE+jMO/kHKH5NxahM
24BPSH+vY77osw+KVJK9L8iZvtkR/neC9F9ZJRZr1zCzVAxirjOQvZVdjZEMn+F2
8W7OGFAya5vZqROVzC6Hj9vP2+uViArbOE0Uq9rqQXhSWGPEJgKcZ5d5t9+9eiHB
auZ6K/YtF3laBGDSQScYSrhsU/OrTun/J81iKykKZvxhnUXwBVAYKFJt4s1pT2F+
AwZLEFbtVG/ITp4zj0WUjRZPVyyOykQWscH9r7HKhz7gzlosgZIFicQjH74y6QEG
O7nTuythAoGBAPGKXpePJo+eTa3xwXIge37OtySIRdUCMSsn1N2s3hbXFVJphTze
VFm4U1Prl7iioVVkMrvpcuJJJrH/gjBTcOBy+yyRZYZWeEU7dNtAmGU59TEvMaYb
yNuStWUc8uydVQ1NNp96LicM03XCNd8uIWsDA3gAWU8EfpLpgsbMC737AoGBAOmc
RNSdIrtoAqOH82Zb/0QaZDkECjk9EA1vESqvjmvDs9PxYjduuQSlNojYxfTQl0gg
UrMTuZjnBSmIcYAiXcyE8g1YbpocNMikC5aH6mfjZzzvsP1tuDZyGsEdianBmsKn
NUKMvHYvsZRZR6uZeXaP+cX8agHnO3LYO9bn0H9ZAoGAZqlIISTP3/UJ0SfS774M
n04fG2DsRWfkHBKW8A08a/rI7jk5TzC0K1oj2KRm3SwKZG/s/F9x2+n5j2gpHn8o
l81nIn895oY0IkDuHw5qd4PVyizj7lUa3vCRNsPCIH2Sm8+4qrnUifZynjeIjC5g
N8qVG9kSHHqtjaXAVtx9FScCgYAmkKCgRMyOCY6d9nyNAlTypjSzYOJbLqRuw04f
MNofGjCepXOkWQf8J1YIY1jSoHjI9GUSoQf7oO+uOpMaJxI7CBt5bobbtBpWoRY0
pH1i5xyM57jdLXbCrjWSedDXEFn/FmFpehhGnnr/VXnKb0yo8P233IKXi9e5js7a
HGzECQKBgCUi3Gf60N6Ryi0AnroTU8AdKOnajMcMqoYxxLFcRiO7K8RnUDVifszy
fNfyjluHMo3Rj5iErDbORW4WKkjjdRaHq4HjZmU/wq0rjM1ABFgCENi9aZoHezU+
gVTmNlEl3qjYpCc96OvuMo83aI7laGg+mSa5EASBqhray00jfq7x
-----END RSA PRIVATE KEY-----
private_key_type    rsa
serial_number       69:e0:ea:29:95:76:24:fc:3d:38:12:ea:c1:d8:03:f0:f6:a6:70:35
```

**NEVER** leak private key, the above is just a test!!!

Same can be done via `curl`:

``` shell
$ curl -s -H "X-Vault-Token: <token>" -X POST \
  -d '{"common_name": "jb154sapqe01.example.com", "alt_names": "jb154sapqe01.example.com,example.com,*.example.com"}' \
  https://avocado.example.com:8200/v1/pki/issue/example-dot-com | \
  jq '.'
```

And parsing output from `curl` to make things easier:

``` shell
$ curl -s -H "X-Vault-Token: <token>"  -X POST \
  -d '{ "common_name": "jb154sapqe01.example.com", "alt_names": "jb154sapqe01.example.com,example.com,*.example.com"}' \
  https://avocado.example.com:8200/v1/pki/issue/example-dot-com | \
  tee >(jq -r .data.certificate > cert.pem) >(jq -r .data.private_key > key.pem) >(jq -r .data.ca_chain[] > chained.pem)

$ file *.pem
cert.pem:    PEM certificate
chained.pem: PEM certificate
key.pem:     PEM RSA private key

$ openssl x509 -in cert.pem -subject -ext subjectAltName -noout
subject=CN = jb154sapqe01.example.com
X509v3 Subject Alternative Name:
    DNS:*.example.com, DNS:example.com, DNS:jb154sapqe01.example.com
```
