#!/bin/bash

logfile="/var/log/fedora-samba-dc_joindc2domain.log"

if [ -z $SCRIPT ]; then
    script $logfile -c "/bin/bash -c \"SCRIPT=1 sh $(realpath $0) $*\""
    exit
fi

ADDC_Hostname="$HOSTNAME"
read -p "Enter the subnets /24 space delimited, that should be allowed to synchronize its time: " -a subnets
read -p "Enter the fqdn of the domain (example.com): " Domain_Name
ReplMaster=$(host -t SRV _ldap._tcp.pdc._msdcs.$Domain_Name | awk '{split($8, a, "."); print a[1]}')
ReplMasterIP=$(host -t A $ReplMaster.$Domain_Name | awk '{print $4}')
IPAddress=$(ip route | awk 'Begin{a=""} /^default/ {a=$5} $0 !~ "default" {if (a != "" && $3 == a) {print $9}}')

# https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller#Preparing_the_Installation
# DHCP is not allowed on a DC
first=$(/bin/true)
for interface in `ls /sys/class/net`; do
    if ip a show $interface | grep -A 1 "inet " | grep -v inet | grep -v forever; then
        if $first; then
            echo The following interfaces are configured with dhcp:
            first=$(/bin/false)
        fi
        address=$(ip a show $interface | grep "inet " | sed 's/|/ /' | awk '{print $2}')
        echo $interface - $address
    fi
done
if ! $first; then
    read -p "Press Ctrl+c to exit or Enter to continue"
fi

# resolv.conf shouldn’t be managed - https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller#Preparing_the_Installation
systemctl stop systemd-resolved
systemctl disable systemd-resolved

ssh-keygen -t rsa
ssh-copy-id -i ~/.ssh/id_rsa.pub root@$ReplMasterIP
cat << EOF > /etc/ssh/sshd_config
$(awk 'BEGIN{skip=0} /PermitRootLogin / {print "PermitRootLogin yes"; skip=1} /.*/ {if (skip) {skip=0} else print $0}' /etc/ssh/sshd_config)
EOF
systemctl restart sshd

echo Run the following command in the ssh session:
echo     ssh-copy-id -i ~/.ssh/id_rsa.pub root@$IPAddress
echo     exit
ssh root@$ReplMasterIP
# Customize ntp server
cat << EOF > /etc/ntp.conf 
$(awk -v sn="${subnets[*]}" 'BEGIN{n=split(sn,a," ");skip=0} /^restrict 127\.0\.0\.1.*$/ {print $0; for (i in a) {print "restrict "a[i]"   mask 255.255.255.0   nomodify notrap"} skip=1} /.*/ {if (skip) {skip=0} else print $0}' /etc/ntp.conf)
EOF
systemctl restart ntpd

# Configure Replication - https://wiki.samba.org/index.php/Bidirectional_Rsync/osync_based_SysVol_replication_workaround
ssh -q root@$ReplMasterIP << ENDSSH
cat << EOF > /etc/osync/sync_$HOSTNAME.conf
#!/usr/bin/env bash
###### osync - Rsync based two way sync engine with fault tolerance
###### (C) 2013-2021 by Orsiris de Jong (www.netpower.fr)

[GENERAL]
CONFIG_FILE_REVISION=1.3.0

## Sync job identification
INSTANCE_ID="sysvol_sync_$HOSTNAME"

## Directories to synchronize.
## Initiator is the system osync runs on. The initiator directory must be a local path.
INITIATOR_SYNC_DIR="/usr/local/samba/var/locks/sysvol"

## Target is the system osync synchronizes to (can be the same system as the initiator in case of local sync tasks). The target directory can be a local or remote path.
#TARGET_SYNC_DIR="/home/git/osync/dir2"
TARGET_SYNC_DIR="ssh://root@${IPAddress}:22//usr/local/samba/var/locks/sysvol"

## If the target system is remote, you can specify a RSA key (please use full path). If not defined, the default ~/.ssh/id_rsa will be used. See documentation for further information.
SSH_RSA_PRIVATE_KEY="/root/.ssh/id_rsa"

## Alternatively, you may specify an SSH password file (less secure). Needs sshpass utility installed.
#SSH_PASSWORD_FILE=""

## When using ssh filter, you must specify a remote token matching the one setup in authorized_keys
_REMOTE_TOKEN=SomeAlphaNumericToken9

## Create sync directories if they do not exist (true/false)
CREATE_DIRS=true

## Log file location. Leaving this empty will create a logfile at /var/log/osync_version_SYNC_ID.log (or current directory if /var/log doesn't exist)
LOGFILE="/var/log/osync_sysvol_$HOSTNAME.log"

## Generate an alert if initiator or target replicas have less free space than given value in KB. Set this to zero to skip disk space tests. 
MINIMUM_SPACE=10240

## Bandwidth limit Kbytes / second. Leave 0 to disable limitation
BANDWIDTH=0

## If enabled, synchronization on remote system will be processed as superuser. See documentation for /etc/sudoers file configuration.
SUDO_EXEC=false
## Paranoia option. Don't change this unless you read the documentation.
RSYNC_EXECUTABLE=rsync
## Remote rsync executable path. Leave this empty in most cases
RSYNC_REMOTE_PATH=""

## Rsync exclude / include order (the option set here will be set first, eg: include will make include then exclude patterns)
RSYNC_PATTERN_FIRST=include

## List of files / directories to incldue / exclude from sync on both sides (see rsync patterns, wildcards work).
## Paths are relative to sync dirs. List elements are separated by a semicolon.
RSYNC_INCLUDE_PATTERN=""
RSYNC_EXCLUDE_PATTERN=""
#RSYNC_EXCLUDE_PATTERN="tmp;archives"

## Files that contains lists of files / directories to include / exclude from sync on both sides. Leave this empty if you don't want to use an exclusion file.
## This file has to be in the same directory as the config file
## Paths are relative to sync dirs. One element per line.
RSYNC_INCLUDE_FROM=""
RSYNC_EXCLUDE_FROM=""
#RSYNC_EXCLUDE_FROM="exclude.list"

## List elements separator char.  You may set an alternative separator char for your directories lists above.
PATH_SEPARATOR_CHAR=";"

## By default, osync stores its state into the replica_path/.osync_workdir/state
## This behavior can be changed for initiator or slave by overriding the following with an absolute path to a statedir, ex /opt/osync_state/initiator
## If osync runs locally, initiator and target state dirs **must** be different
INITIATOR_CUSTOM_STATE_DIR=""
TARGET_CUSTOM_STATE_DIR=""

[REMOTE_OPTIONS]

## ssh compression should be used on WAN links, unless your remote connection is good enough (LAN), in which case it would slow down things
SSH_COMPRESSION=true

## Optional ssh options. Example to lower CPU usage on ssh compression, one can specify '-T -c arcfour -o Compression=no -x'
## -T = turn off pseudo-tty, -c arcfour = weakest but fasted ssh encryption (destination must accept "Ciphers arcfour" in sshd_config), -x turns off X11 forwarding
## arcfour isn't accepted on most newer systems, you may then prefer any AES encryption if processor has aes-ni hardware acceleration
## If the system does not provide hardware assisted acceleration, chacha20-poly1305@openssh.com is a good cipher to select
## See: https://wiki.csnu.org/index.php/SSH_ciphers_speed_comparison
## -o Compression=no is already handled by SSH_COMPRESSION option
## Uncomment the following line to use those optimizations, on secured links only
#SSH_OPTIONAL_ARGS="-T -c aes128-ctr -x"
#SSH_OPTIONAL_ARGS="-T -c chacha20-poly1305@openssh.com -x"

## Ignore ssh known hosts. DANGER WILL ROBINSON DANGER ! This can lead to security issues. Only enable this if you know what you're doing.
SSH_IGNORE_KNOWN_HOSTS=false

## Use a single TCP connection for all SSH calls. Will make remote sync faster, but may work less good on lossy links.
SSH_CONTROLMASTER=false

## Check for connectivity to remote host before launching remote sync task. Be sure the hosts responds to ping. Failing to ping will stop sync.
REMOTE_HOST_PING=false

## Check for internet access by pinging one or more 3rd party hosts before remote sync task. Leave empty if you don't want this check to be be performed. Failing to ping will stop sync.
## If you use this function, you should set more than one 3rd party host, and be sure you can ping them.
## Be aware some DNS like opendns redirect false hostnames. Also, this adds an extra execution time of a bit less than a minute.
REMOTE_3RD_PARTY_HOSTS=""

[MISC_OPTIONS]

## Optional arguments passed to rsync executable. The following are already managed by the program and shoul never be passed here
## -r -l -p -t -g -o -D -E - u- i- n --executability -A -X -L -K -H -8 -zz –skip-compress –checksum –bwlimit –partial –partial-dir –no-whole-file –whole-file –backup –backup-dir –suffix
## --exclude --exclude-from --include --include-from --list-only --stats
## When dealing with different filesystems for sync, or using SMB mountpoints, try adding --modify-window=2 --omit-dir-times as optional arguments.
RSYNC_OPTIONAL_ARGS=""

## Preserve basic linux permissions
PRESERVE_PERMISSIONS=true
PRESERVE_OWNER=true
PRESERVE_GROUP=true
## On MACOS X, does not work and will be ignored
PRESERVE_EXECUTABILITY=true

## Preserve ACLS. Make sure source and target FS can handle ACL. Disabled on Mac OSX.
PRESERVE_ACL=true
## Preserve Xattr. Make sure source and target FS can manage identical XATTRS. Disabled on Mac OSX. Apparently, prior to rsync v3.1.2 there are some performance caveats with transferring XATTRS.
PRESERVE_XATTR=true
## Transforms symlinks into referent files/dirs. Be careful as symlinks without referrent will break sync as if standard files could not be copied.
COPY_SYMLINKS=false
## Treat symlinked dirs as dirs. CAUTION: This also follows symlinks outside of the replica root.
KEEP_DIRLINKS=false
## Preserve hard links. Make sure source and target FS can manage hard links or you will lose them.
PRESERVE_HARDLINKS=false
## Do a full checksum on all files that have identical sizes, they are checksummed to see if they actually are identical. This can take a long time.
CHECKSUM=false

## Let RSYNC compress file transfers. Do not use this if both initator and target replicas are on local system. Also, do not use this if you already enabled SSH compression.
RSYNC_COMPRESS=true

## Maximum execution time (in seconds) for sync process. Set these values zero will disable max execution times.
## Soft exec time only generates a warning. Hard exec time will generate a warning and stop sync process.
SOFT_MAX_EXEC_TIME=0
#7200
HARD_MAX_EXEC_TIME=0
#10600

## Log a message every KEEP_LOGGING seconds just to know the task is still alive
KEEP_LOGGING=1801

## Minimum time (in seconds) in file monitor /daemon mode between modification detection and sync task in order to let copy operations finish.
MIN_WAIT=60

## Maximum time (in seconds) waiting in file monitor / daemon mode. After this time, sync is run.
## Use 0 to wait indefinitely.
MAX_WAIT=0
#7200

[BACKUP_DELETE_OPTIONS]

## Log a list of conflictual files (EXPERIMENTAL)
LOG_CONFLICTS=false
## Send an email when conflictual files are found (implies LOG_CONFLICTS)
ALERT_CONFLICTS=false
## Enabling this option will keep a backup of a file on the target replica if it gets updated from the source replica. Backups will be made to .osync_workdir/backups
CONFLICT_BACKUP=true
## Keep multiple backup versions of the same file. Warning, This can be very space consuming.
CONFLICT_BACKUP_MULTIPLE=false
## Osync will clean backup files after a given number of days. Setting this to 0 will disable cleaning and keep backups forever. Warning: This can be very space consuming.
CONFLICT_BACKUP_DAYS=30
## If the same file exists on both replicas, newer version will be synced. However, if both files have the same timestamp but differ, CONFILCT_PREVALANCE sets winner replica.
CONFLICT_PREVALANCE=initiator

## On deletion propagation to the target replica, a backup of the deleted files can be kept. Deletions will be kept in .osync_workdir/deleted
SOFT_DELETE=true
## Osync will clean deleted files after a given number of days. Setting this to 0 will disable cleaning and keep deleted files forever. Warning: This can be very space consuming.
SOFT_DELETE_DAYS=30

## Optional deletion skip on replicas. Valid values are "initiator", "target", or "initiator,target"
SKIP_DELETION=

## Optional sync type. By default, osync is bidirectional. You may want to use osync as unidirectional sync in some circumstances. Valid values are "initiator2target" or "target2initiator"
SYNC_TYPE=

[RESUME_OPTIONS]

## Try to resume an aborted sync task
RESUME_SYNC=true
## Number maximum resume tries before initiating a fresh sync.
RESUME_TRY=2
## When a pidlock exists on slave replica that does not correspond to the initiator's instance-id, force pidlock removal. Be careful with this option if you have multiple initiators.
FORCE_STRANGER_LOCK_RESUME=false

## Keep partial uploads that can be resumed on next run, experimental feature
PARTIAL=false

## Use delta copy algortithm (usefull when local paths are network drives), defaults to true
DELTA_COPIES=true

[ALERT_OPTIONS]
## List of alert mails separated by spaces
## Most Unix systems (including Win10 bash) have mail support out of the box
## Just make sure that the current user has enough privileges to use mail / mutt / sendmail and that the mail system is configured to allow outgoing mails
## on pfSense platform, smtp support needs to be configured in System > Advanced > Notifications
DESTINATION_MAILS="invictusservers27@gmail.com"

## By default, only sync warnings / errors are sent by mail. This default behavior can be overrided here
ALWAYS_SEND_MAILS=true

## Optional change of mail body encoding (using iconv)
## By default, all mails are sent in UTF-8 format without header (because of maximum compatibility of all platforms)
## You may specify an optional encoding here (like "ISO-8859-1" or whatever iconv can handle)
MAIL_BODY_CHARSET=""

## Additional mail parameters needed for Android / Busybox / Cygwin / MSYS
## Android & Busybox use sendmail (and openssl if encryption is needed)
## MSYS & Cygwin Windows mail support relies on mailsend.exe from muquit, http://github.com/muquit/mailsend which needs to be in %PATH% environment variable
SENDER_MAIL="invictusservers27@gmail.com"
SMTP_SERVER=192.168.1.12
SMTP_PORT=25
# encryption can be tls, ssl or none
SMTP_ENCRYPTION=none
SMTP_USER=
SMTP_PASSWORD=

[EXECUTION_HOOKS]

## Commands can will be run before and / or after sync process
LOCAL_RUN_BEFORE_CMD=""
LOCAL_RUN_AFTER_CMD=""

REMOTE_RUN_BEFORE_CMD=""
REMOTE_RUN_AFTER_CMD="/usr/local/samba/bin/samba-tool ntacl sysvolreset"

## Max execution time of commands before they get force killed. Leave 0 if you don't wan't this to happen. Time is specified in seconds.
MAX_EXEC_TIME_PER_CMD_BEFORE=0
MAX_EXEC_TIME_PER_CMD_AFTER=0

## Stops osync execution if one of the above before commands fail
STOP_ON_CMD_ERROR=true

## Run local and remote after sync commands even on failure
RUN_AFTER_CMD_ON_ERROR=false
EOF
tdbbackup -s .bak /usr/local/samba/private/idmap.ldb
scp -f /usr/local/samba/private/idmap.ldb.bak root@$IPAddress:/usr/local/samba/private/idmap.ldb
cat << EOF > /usr/local/bin/osync.sh 
awk 'BEGIN{skip=0} /^.*:\\\042\047.*$/ {gsub(/\\\042\047/, "\\\""); gsub(/\047\\\042/, "\\\""); print $0; skip=1} /.*/ {if (skip) {skip=0} else print $0}' /usr/local/bin/osync.sh
EOF
ENDSSH

# Configure on Host before next reboot!!!!Setup resolv.conf - https://wiki.samba.org/index.php/Linux_and_Unix_DNS_Configuration#Configuring_the_.2Fetc.2Fresolv.conf
echo search $Domain_Name > /etc/resolv.conf
for nameServer in `dig -t NS $Domain_Name | sed -n '/;; ANSWER SECTION:/,/;; AUTHORITY SECTION:/{/;; ANSWER SECTION:/b;/;; AUTHORITY SECTION/b;p}' | sed 's/|/ /' | awk '{print $5}' | sed 's/\.\ *$//'`; do
    echo $(echo $(nslookup $nameServer | grep Address) | awk '{print $4}') >> /etc/resolv.conf
done
ip route | awk 'Begin{a=""} /^default/ {a=$5} $0 !~ "default" {if (a != "" && $3 == a) {print $9}}' >> /etc/resolv.conf

#Add domain to Kerberos
cat << EOF > /etc/krb5.conf 
$(awk 'Begin{p=0;f1=0} /^\[libdefaults\]/ {p=1;} /^    default_realm = / {if (p) {print $n; skip=1; f1=1}} /^\[[^(libdefaults\])]/ {if (p) {p=0; add=""; if (! f1) {add="    default_realm = "$n"\n"add} print add}} /.*/ {if (skip) {skip=0;} else print $0}' n=$Domain_Name /etc/krb5.conf)
EOF

# Replicate the sysvol - https://wiki.samba.org/index.php/Bidirectional_Rsync/osync_based_SysVol_replication_workaround#Osync_Configuration_Setup_on_DC1
ssh -q root@$ReplMasterIP << ENDSSH
/usr/local/bin/osync.sh /etc/osync/sync_$HOSTNAME.conf --dry --verbose
/usr/local/bin/osync.sh /etc/osync/sync_$HOSTNAME.conf --verbose
(crontab -l 2>/dev/null; echo "*/5 * * * * root /usr/local/bin/osync.sh /etc/osync/sync_$HOSTNAME.conf --verbose") | crontab -
ENDSSH
net cache flush
ssh -q root@$ReplMaster << ENDSSH
/usr/local/bin/osync.sh /etc/osync/sync_$HOSTNAME.conf --verbose
ENDSSH

# Join the domain as a DC - https://wiki.samba.org/index.php/Joining_a_Samba_DC_to_an_Existing_Active_Directory#Joining_the_Active_Directory_as_a_Domain_Controller

samba-tool domain join $Domain_Name DC -U"$(echo ${Domain_Name%%.*} | tr '[:lower:]' '[:upper:]')\administrator"
cat << EOF > /usr/local/samba/etc/smb.conf
$(awk 'BEGIN{p=0;f1=0;f2=0;f3;skip=0} /^\[global\].*$/ {p=1} /^\ttemplate shell = .*$/ {print "\t"$1" "$2" = /bin/bash";skip=1;f1=1} /^\ttemplate homedir = .*$/ {print "\t"$1" "$2" = /home/%U";skip=1;f2=1} /^\tdns forwarder = .*$/ {print "\t"$1" "$2" = 192.168.1.1";skip=1;f3=1} /^$/ {if (p) {add=""; if (! f1) {add="\ttemplate shell = /bin/bash\n"add} if (! f2) {add="\ttemplate homedir = /home/%U\n"add} if (! f3) {add="\tdns forwarder = 192.168.1.1\n"add} print add; next}} /^\[[^(global\])].*$/ {if (p) {p=0}} /.*/ {if (skip) {skip=0;} else print $0}' /usr/local/samba/etc/smb.conf)
EOF
systemctl enable samba-ad-dc --now
journalctl -xe —unit=samba-ad-dc -f

# CONFIGURE ON HOST BEFORE NEXT REBOOT!!! Configure DNS - https://wiki.samba.org/index.php/Joining_a_Samba_DC_to_an_Existing_Active_Directory#DNS_Configuration_on_Domain_Controllers

echo search $Domain_Name > /etc/resolv.conf
ip route | awk 'Begin{a=""} /^default/ {a=$5} $0 !~ "default" {if (a != "" && $3 == a) {print $9}}' >> /etc/resolv.conf
for nameServer in `dig -t NS $Domain_Name | sed -n '/;; ANSWER SECTION:/,/;; AUTHORITY SECTION:/{/;; ANSWER SECTION:/b;/;; AUTHORITY SECTION/b;p}' | sed 's/|/ /' | awk '{print $5}' | sed 's/\.\ *$//'`; do
    echo $(echo $(nslookup $nameServer | grep Address) | awk '{print $4}') >> /etc/resolv.conf
done

# Confirm the DNS entries - https://wiki.samba.org/index.php/Verifying_and_Creating_a_DC_DNS_Record#Domain_Controller_A_Record
host -t A "${HOSTNAME}.${Domain_Name}." | grep "NXDOMAIN" && die "Failed to populate the dns referencing confirm installation successful"

# objectGUID and CNAME
objectGUID=$(ldbsearch -H /usr/local/samba/private/sam.ldb '(invocationId=*)' --cross-ncs objectguid | awk -v var="$HOSTNAME" 'BEGIN{p=0} {if( $0 ~ "CN="var) {p=1}} /^objectGUID.*$/ {if (p) {print $2; p=0}}')
[ "$objectGUID" == "" ] && die "Hostname was not found in Directory, could not retrieve objectGUID"
host -t CNAME "${objectGUID}._msdcs.${Domain_Name}." | grep "NXDOMAIN" && die "Failed to populate the dns referencing for GUID confirm installation successful"

# Verifying Replication Status - https://wiki.samba.org/index.php/Verifying_the_Directory_Replication_Statuses#Displaying_the_Replication_Statuses_on_a_Samba_DC
(samba-tool drs showrepl | grep unsuccessful) && echo "Some replication jobs were not successful"

# Verify the file server - https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller#Verifying_the_File_Server_.28Optional.29
smbclient -L localhost -N | awk 'BEGIN{f1=0;f2=0;f3=0} /^ *netlogon.*$/ {f1=1} /^ *sysvol.*$/ {f2=1} /^ *IPC\$.*$/ {f3=1} END {if (! f1) {print "netlogon share was not found"} if (! f2) {print "sysvol share was not found"} if (! f3) {print "IPC$ share was not found"}}'

# Testing winbindd - https://wiki.samba.org/index.php/Setting_up_Samba_as_a_Domain_Member#Sending_a_Winbindd_Ping
wbinfo --ping-dc | awk '{if ($NF != "succeeded") {print "See the below message for the error:\nprint$0"} else {print $0}}'