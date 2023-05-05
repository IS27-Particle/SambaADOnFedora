# Samba AD on Fedora
## Description
This is a set of scripts written to automate the deployment and management of Samba AD on Fedora Linux, according to the 
[Samba Wiki] (https://wiki.samba.org/index.php/Distribution-specific_Package_Installation#Version_7_and_8) the package available is not compatible with Active Directory and can only be used with NT4 domains.

## SELinux advisory
At this time we will not be configuring SELinux profiles. However, this is planned for the future. To disable SELinux run the following:
```
sudo setenforce 0
sudo cat << EOF > /etc/selinux/config
$(awk '/^SELINUX=/ {split($0,a,"="); print a[1]"=disabled";next}1' /etc/selinux/config)
EOF
reboot
```
or to set it to permissive
```
sudo setenforce 0
sudo cat << EOF > /etc/selinux/config
$(awk '/^SELINUX=/ {split($0,a,"="); print a[1]"=permissive";next}1' /etc/selinux/config)
EOF
reboot
```

if you'd like to enable SELINUX in the future see the troubleshooting article on the [wiki] (https://wiki.samba.org/index.php/Troubleshooting_SELinux_on_a_Samba_AD_DC)

## JoinDC2Domain.sh
This is a companion script to the install.sh and is found on the lxc template (Proxmox or LXD), all coming soon.

This script does all the leg work of configuring and enabl ing the AD DC. When ran it will ask for two inputs: subnets and Domain FQDN.
- subnets are space delimited and only /24 is allowed, planned to extend this. Must be the Subnet ID (ex: 192.168.1.0)
- Domain FQDN is as described (ex: example.com)
The rest of the information it will attempt to auto discover.
| :warning:         | Currently no Error checking on inputs is configured
|-------------------|:------------------|