# Databases cheatsheet

## IBM DB2

DB2 requires `bin` user, see
https://www.ibm.com/support/pages/db2-luw-product-installation-fails-unix-platform-without-bin-user.

*WIP* !!! https://www.tutorialspoint.com/db2/db2_instance.htm
          https://community.ibm.com/community/user/datamanagement/discussion/how-to-run-docker-ibmcomdb2-image-as-non-root


- ./db2setup to install db2

``` shell
$ cat > response_file <<EOF
LIC_AGREEMENT       = ACCEPT
PROD       = DB2_SERVER_EDITION
FILE       = /opt/ibm/db2/V11.5
INSTALL_TYPE       = CUSTOM
INTERACTIVE               = YES
COMP       = SQL_PROCEDURES
COMP       = CONNECT_SUPPORT
COMP       = BASE_DB2_ENGINE
COMP       = REPL_CLIENT
COMP       = JDK
COMP       = JAVA_SUPPORT
COMP       = BASE_CLIENT
COMP       = COMMUNICATION_SUPPORT_TCPIP
DAS_CONTACT_LIST       = LOCAL
LANG       = EN
EOF

$ db2/server_dec/db2setup -r response_file
```

- users/groups

- ./db2icrt ... to create instance

- disable db2fmd
- populate data into instance
- backup / restore
- hadr
- pacemaker
