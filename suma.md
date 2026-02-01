# SUSE Manager aka SUSE Multi-Linux-Manager cheatsheet

- UI issues might be in `rhweb_ui.log`
- synchronization issues:
  ``` shell
  env URGLGRABBER_DEBUG=DEBUG spacewalk-repo-sync -vv <channel> -Y
  less /var/log/rhn/reposync...
  ```

/var/log/venv_salt_minion.log - not collected by supportconfig ???
cat > /etc/venv-salt-minion/minion.d/debug.conf << EOF
log_level = debug ???
EOF


## SMLM 5.x deployment

``` shell
# preparing SMLM host fstab(5) for storage volumes,
# using LVM since that can be extended later if needed

$ mgr-storage-server /dev/jbsmlmqe01/data 
--> Checking disk for content signature
--> Creating xfs filesystem
--> Mounting storage at /var/lib/containers/storage/manager_storage_tmp
--> Syncing SUSE Multi-Linux Manager Server directories to storage disk(s)
--> Creating entry in /etc/fstab

$ tail -n1 /etc/fstab 
UUID=eb003a00-d859-4c91-9302-9f30b44e3aed /var/lib/containers/storage/volumes xfs defaults,nofail 1 2
```

``` shell
# a deployment using export RMT data/settings/repos

$ mgradm install podman \
  --mirror /mnt \
  --admin-password <password> \
  --ssl-password <password>
11:51AM INF Starting mgradm install podman --mirror /mnt --admin-password <REDACTED> --ssl-password <REDACTED>
11:51AM INF Use of this software implies acceptance of the End User License Agreement.
11:51AM INF Setting up the server with the FQDN 'jbsmlmqe01.example.com'
11:51AM INF Computed image name is registry.suse.com/suse/multi-linux-manager/5.1/x86_64/server:5.1.1.1
11:51AM INF Computed image name is registry.suse.com/suse/multi-linux-manager/5.1/x86_64/server-postgresql:5.1.1.1
11:51AM INF Ensure image registry.suse.com/suse/multi-linux-manager/5.1/x86_64/server:5.1.1.1 is available
11:51AM INF skipping loading image from RPM as /usr/share/suse-docker-images/native/ doesn't exist
11:51AM INF Cannot find RPM image for registry.suse.com/suse/multi-linux-manager/5.1/x86_64/server:5.1.1.1
11:51AM INF Running podman pull registry.suse.com/suse/multi-linux-manager/5.1/x86_64/server:5.1.1.1
...
```
