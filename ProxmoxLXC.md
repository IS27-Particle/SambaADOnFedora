ProxmoxLXC Install

### Image Deployment

Download the LXC Template [here](https://is27.duckdns.org/nextcloud/s/ZYDagsYw7r6LzbT/download/fedora-37-samba-ad-dc_20230501_amd64.tar.gz) as a Container Template and use it as the image to deploy the container.

Container must be privileged as Domain controllers requires the ability to modify the Security namespace of the extended attributes

Set a static IP

For setting up a new domain DNS Search Domain should be the anticipated domain, nameservers can be anything that resolves

For joining an existing domain, DNS Search Domain should be the domain to be joined, nameservers need to be the DNS servers broadcasting the ldap servers for the Domain (\_ldap.msdcs.example.com)

All other configurations can be whatever you wish

Recommended:

###### PDC Controller:

- CPU - 2
- RAM - 2048
- Storage - 16GB

###### All Other DCs:

- CPU - 1
- RAM - 1024
- Storage - 16GB

The PDC Controller does the bulk of the processing for the environment

### Configuration

To join the DC to an existing domain download the script [JoinDC2Domain.sh](https://is27.duckdns.org/nextcloud/s/weBA7fJaw7J6oGn), run it and following the prompts.

For a new domain download the script DCCreateDomain.sh (Coming Soon)

### Common Issues

Report any issues on [GitHub](https://github.com/IS27-Particle/SambaADOnFedora), if any special instructions are necessary I will update this Readme below with each use case