#!/bin/bash

dnf update
# dnf-plugins-core is required for builddep - https://dnf-plugins-core.readthedocs.io/en/latest/builddep.html
# builddep - https://wiki.samba.org/index.php/Package_Dependencies_Required_to_Build_Samba#Fedora
# nano - preferred editor
# wget - preferred downloader
# attr and acl - extended attributes and POSIXACL are required - https://wiki.samba.org/index.php/File_System_Support#Testing_your_filesystem
# lmdb-devel, perl-JSON - dependencies missing in builddep
# krb5-workstation, sssd-client - functional dependencies
# automake - may not be required but was installed as additional build tool for ntp
# patch - required to patch the ntp source
# rsync - required for sysvol replication
# openssh-server - adds an additional access method and compatibility with ansible
# net-tools - common network troubleshooting utilities

dnf install dnf-plugins-core nano wget attr acl lmdb-devel perl-JSON krb5-workstation openssl-devel automake patch rsync openssh-server sssd-client net-tools

# default repo urls populated incorrectly due to containerized environment, the following fixes this
sed 's/\SRPMS/x86_64/g' /etc/yum.repos.d/fedora-updates.repo > /etc/yum.repos.d/fedora-updates.repo.new
mv /etc/yum.repos.d/fedora-updates.repo.new /etc/yum.repos.d/fedora-updates.repo
sed 's/\SRPMS/x86_64/g' /etc/yum.repos.d/fedora-updates-modular.repo > /etc/yum.repos.d/fedora-updates-modular.repo.new
mv /etc/yum.repos.d/fedora-updates-modular.repo.new /etc/yum.repos.d/fedora-updates-modular.repo

# installs dependencies to build Samba from source
dnf builddep libldb samba

# RHEL Samba package does not support AD setup - https://wiki.samba.org/index.php/Distribution-specific_Package_Installation#Version_7_and_8
# download Samba source code - https://wiki.samba.org/index.php/Build_Samba_from_Source#Stable_Version_.28Recommended.29
wget https://download.samba.org/pub/samba/samba-latest.tar.gz -P /tmp 

# download ntp server source code due to build requirement - https://wiki.samba.org/index.php/Time_Synchronisation#Configuring_Time_Synchronisation_on_a_DC
wget https://archive.ntp.org/ntp4/ntp-4.2/ntp-4.2.8p15.tar.gz -O /tmp/ntp-latest.tar.gz

# download osync for sysvol replication - https://wiki.samba.org/index.php/Bidirectional_Rsync/osync_based_SysVol_replication_workaround
wget https://github.com/deajan/osync/archive/refs/tags/v1.3-rc3.tar.gz -O /tmp/osync-latest.tar.gz

# download NTP source code Patch - https://bugs.ntp.org/show_bug.cgi?id=3741
wget --user-agent=Mozilla https://bugs.ntp.org/attachment.cgi?id=1814 -O /tmp/NTP.patch

# Validation step to ensure all old configs are purged - https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller#Preparing_the_Installation
rm -f $(smbd -b | grep "CONFIGFILE" | sed '0,/|/s// /' | awk '{print $2}')

# extract Samba source - https://wiki.samba.org/index.php/Build_Samba_from_Source#Extracting_the_Source_Package
mkdir /tmp/samba-latest
tar -zxf /tmp/samba-latest.tar.gz -C /tmp/samba-latest 

# Configure Samba - https://wiki.samba.org/index.php/Build_Samba_from_Source#configure
pushd /tmp/samba-latest
mv ./samba-*/* ./
./configure

# make - https://wiki.samba.org/index.php/Build_Samba_from_Source#make
make -j 2

# make install - https://wiki.samba.org/index.php/Build_Samba_from_Source#make_install
make install

# Add binary paths to PATH - https://wiki.samba.org/index.php/Build_Samba_from_Source#Adding_Samba_Commands_to_the_.24PATH_Variable
cat << "EOF" > /etc/profile.d/samba.sh
pathmunge /usr/local/samba/sbin/
pathmunge /usr/local/samba/bin/
EOF
source /etc/bashrc

# Create the systemd unit, mask independent Samba features
systemctl mask smbd nmbd winbind
systemctl disable smbd nmbd winbind
cat << EOF > /etc/systemd/system/samba-ad-dc.service
[Unit]
Description=Samba Active Directory Domain Controller
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
ExecStart=/usr/local/samba/sbin/samba -D
PIDFile=/usr/local/samba/var/run/samba.pid
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

#Configure Kerberos - https://wiki.samba.org/index.php/Joining_a_Samba_DC_to_an_Existing_Active_Directory#Kerberos
cat << EOF > /etc/krv5.conf
$(awk 'Begin{p=0;f1=0;f2=0} /^\[libdefaults\]/ {p=1;} /^    dns_lookup_realm = / {if (p) {print "    "$1" = false"; skip=1; f1=1}} /^    dns_lookup_kdc = / {if (p) {print "    "$1" = true"; skip=1; f2=1}} /^\[[^(libdefaults\])]/ {if (p) {p=0; add=""; if (! f1) {add="    dns_lookup_realm = false\n"add} if (! f2) {add="    dns_lookup_kdc = true\n"add} print add}} /.*/ {if (skip) {skip=0;} else print $0}' /etc/krb5.conf)
EOF

popd
#Install ntp server - https://wiki.samba.org/index.php/Time_Synchronisation
mkdir /tmp/ntp-latest
tar -zxf /tmp/ntp-latest.tar.gz -C /tmp/ntp-latest
pushd /tmp/ntp-latest
mv ./*/* ./
mv /tmp/NTP.patch ./
patch -ruN -p1 < NTP.patch
./configure --enable-ntp-signd
make
make install
mkdir -p /usr/local/samba/var/lib/ntp_signd/
chown root:systemd-timesync /usr/local/samba/var/lib/ntp_signd/
chmod u=rwx,g=rx,o-rwx /usr/local/samba/var/lib/ntp_signd
cat << EOF > /etc/systemd/system/ntpd.service

[Unit]
Description=Network Time Service
After=network.target nss-lookup.target
Conflicts=systemd-timesyncd.service

[Service]
Type=forking
PrivateTmp=true
ExecStart=/usr/local/sbin/ntpd -g -u systemd-timesync:systemd-timesync -c /etc/ntp.conf
Restart=always

[Install]
WantedBy=multi-user.target
EOF
cat << EOF > /etc/ntp.conf

# Local clock. Note that is not the "localhost" address!
server 127.127.1.0
fudge  127.127.1.0 stratum 10

# Where to retrieve the time from
server 0.pool.ntp.org     iburst prefer
server 1.pool.ntp.org     iburst prefer
server 2.pool.ntp.org     iburst prefer

driftfile       /var/lib/ntp/ntp.drift
logfile         /var/log/ntp
ntpsigndsocket  /usr/local/samba/var/lib/ntp_signd/
disable kernel

# Access control
# Default restriction: Allow clients only to query the time
restrict default kod nomodify notrap nopeer limited mssntp

# No restrictions for "localhost"
restrict 127.0.0.1


# Enable the time sources to only provide time to this host
#restrict 0.pool.ntp.org   mask 255.255.255.255    nomodify notrap nopeer noquery
#restrict 1.pool.ntp.org   mask 255.255.255.255    nomodify notrap nopeer noquery
#restrict 2.pool.ntp.org   mask 255.255.255.255    nomodify notrap nopeer noquery

tinker panic 0
EOF
systemctl daemon-reload
systemctl enable ntpd --now

# Configure winbindd - https://wiki.samba.org/index.php/Configuring_Winbindd_on_a_Samba_AD_DC
ln -s /usr/local/samba/lib/libnss_winbind.so.2 /lib64/
ln -s /lib64/libnss_winbind.so.2 /lib64/libnss_winbind.so
ldconfig
cat << EOF > /etc/nsswitch.conf
$(awk 'BEGIN{skip=0} /^(passwd:|group:) .*$/ {print $0" winbind";skip=1} /.*/ {if (skip) {skip=0} else print $0}' /etc/nsswitch.conf)
EOF
ln -s /usr/local/samba/lib/security/pam_winbind.so /lib64/security/