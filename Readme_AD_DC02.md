# Configure the second and consecutive Active Directory Domain Controllers

### Change the hostname of the VM before installing Samba
``` bash
sed -i 's/BaseVMBuild/SambaDC02/g' /etc/hosts
sed -i 's/BaseVMBuild/SambaDC02/g' /etc/hostname

# If you are using a domain other than MYDOMAIN.COM execute the following (replace newdomain with your domain name):
sed -i 's/mydomain\.com/newdomain\.com/g' /etc/hosts
```

### Change the Network to use a static IP Address
``` bash 
#Make sure you change the IP, mask and gateway to the correct IP before executing this command
sed -i 's/dhcp/static\n   address 192\.168\.2\.41\n   netmask 255\.255\.255\.0\n   gateway 192\.168\.2\.1\n   dns-nameservers 192\.168\.2\.40\n   dns-domain mydomain\.com\n   dns-search mydomain\.com/g' /etc/network/interfaces

#Modify resolv.conf to point to local system:
Change /etc/resolv.conf

echo domain mydomain.com > /etc/resolv.conf
echo search mydomain.com >> /etc/resolv.conf
echo nameserver 192.168.2.40 >> /etc/resolv.conf

## Reboot Server to make the change take effect
/usr/sbin/reboot
```

### Install Samba Services and enter initial values
``` bash
apt install samba smbclient krb5-user winbind bind9 dnsutils -y   
```
<br>

### Clean up the /etc/krb5.conf
Copy this text to a notepad document and change the occurrences of MYDOMAIN.COM or mydomain.com to the correct domain name you are creating for your environment. <br>
``` bash
cat <<EOF > /etc/krb5.conf
[libdefaults]
        default_realm = MYDOMAIN.COM
        rdns=false

# The following krb5.conf variables are only for MIT Kerberos.
        kdc_timesync = 1
        ccache_type = 4
        forwardable = true
        proxiable = true

        fcc-mit-ticketflags = true

[realms]
        MYDOMAIN.COM = {
                kdc = SAMBADC01.mydomain.com
                kdc = SAMBADC02.mydomain.com
                admin_server = SAMBADC01.mydomain.com
                default_domain = mydomain.com
        }

[domain_realm]
        .mydomain.com = MYDOMAIN.COM
EOF

# Remove the Default SAMBA Config to prepare for setup
(cd /etc/samba && mv smb.conf smb.conf.orig)
```

### Generate Active Directory (AD) Domain with BIND9_DLZ backend
``` bash
samba-tool domain join mydomain.com DC -U "mydomain\AD_Admin" --dns-backend=BIND9_DLZ
```

### Modify named.conf for Bind to use the correct dns.keytab for the domain
``` bash 
#Add the tkey and minimal responses statements to the /etc/bind/named.conf.options file 
sed -i 's/directory \"\/var\/cache\/bind\";/directory \"\/var\/cache\/bind\";\n        tkey-gssapi-keytab \"\/var\/lib\/samba\/private\/dns\.keytab\";\n        minimal\-responses yes;/g' /etc/bind/named.conf.options

# Change file permissions and ownership for the dns.keytab
chmod 640 /var/lib/samba/private/dns.keytab
chown root:bind /var/lib/samba/private/dns.keytab

# Enable the Bind-DLZ Modules and modify the /etc/bind/named.conf file
sed -i 's/# database.*11.*;/database \"dlopen \/usr\/lib\/x86_64-linux-gnu\/samba\/bind9\/dlz_bind9_11.so\";/g' /var/lib/samba/bind-dns/named.conf

#Include the Bind-DLZ module in the main named.conf config file
echo 'include "/var/lib/samba/bind-dns/named.conf";' >> /etc/bind/named.conf

#Disable DNSSec Validation
sed -i 's/dnssec\-validation auto;/\/\/dnssec\-validation auto;/g' /etc/bind/named.conf.options

#Set permissions on the /var/lib/samba/bind-dns folder to allow the service to access it
chmod 755 /var/lib/samba/bind-dns

#Restart the Bind9 Service
systemctl restart bind9

# Enable the SAMBA-AD-DC Service
systemctl stop smbd nmbd winbind
systemctl disable smbd nmbd winbind
systemctl mask smbd nmbd winbind
systemctl unmask samba-ad-dc
systemctl enable samba-ad-dc

#Restart the the Samba AD Service
systemctl restart samba-ad-dc
```

### Add a DNS Reverse Lookup Zone Entry and Test DNS
``` bash
#Create a reverse DNS Zone
kinit AD_Admin
samba-tool dns add SambaDC01 2.168.192.in-addr.arpa 41.2.168.192.in-addr.arpa PTR sambadc02.mydomain.com

#Test DNS Resolution
host -t A SAMBADC01.mydomain.com
host -t SRV _ldap._tcp.mydomain.com
host -t SRV _kerberos._tcp.mydomain.com
host -t SRV _kerberos._udp.mydomain.com
host -t PTR 192.168.2.40
host -t PTR 192.168.2.41
```

##  Configure PAM Login for Linux 
This next step will reconfigure the login process on the newly installed DC so that ssh and other sessions to the server are authenticated against the Active Directory.   

``` bash
#Install the supporting software required
apt-get install oddjob-mkhomedir realmd sssd-tools sssd libnss-sss libpam-sss adcli sssd-krb5 krb5-config krb5-user libpam-krb5 sudo -y

#Modify PAM settings to enable auto-creation of home directorys for Active Directory users
echo "session optional      pam_oddjob_mkhomedir.so skel=/etc/skel" >> /etc/pam.d/common-session

#Create the /etc/sssd/sssd.conf file to enable authentication to the newly installed AD
cat <<EOF > /etc/sssd/sssd.conf 
[sssd]
domains = MYDOMAIN.COM
config_file_version = 2
services = nss, pam

[domain/MYDOMAIN.COM]
ad_domain = mydomain.com
krb5_realm = MYDOMAIN.COM
realmd_tags = manages-system joined-with-adcli
cache_credentials = True
ad_maximum_machine_account_password_age = 30
id_provider = ad
krb5_store_password_if_offline = True
default_shell = /bin/bash
ldap_id_mapping = True
ldap_schema = ad
auto_private_groups = true
dyndns_update = false
dyndns_refresh_interval = 43200
dyndns_update_ptr = false
dyndns_ttl = 3600
use_fully_qualified_names = False
fallback_homedir = /home/%u@%d
access_provider = ad
id_provider = ad
auth_provider = ad
chpass_provider = ad
EOF

#Change permissions on sssd.conf
chown root:root /etc/sssd/sssd.conf
chmod 600 /etc/sssd/sssd.conf

#Modify /etc/samba/smb.conf
sed -i 's/workgroup \= MYDOMAIN/workgroup \= MYDOMAIN\n        kerberos method = secrets and keytab/g' /etc/samba/smb.conf

```

## Create KRB5.Keytab
``` bash
kinit AD_Admin
net ads keytab create
klist -k -K -t /etc/krb5.keytab
```

## Restart SSSD and add Sudoers
``` bash
/usr/bin/systemctl restart sssd

# Add linux groups to /etc/sudoers to enable access to the DC for Management Purposes
Now that the DC is installed and authentication is configured to use the Active Directory, we will add the following groups to the sudoers file so that any members of these Active Directory Groups will be able to manage the newly installed Samba DC. 

#Add Active Directory Group to sudoers file
echo '%linuxsudoers           ALL=(ALL)       ALL' >> /etc/sudoers

#The goal is to use the group above, but you can also add the Administrators group to allow any user on the Domain Controller that is in that group to use sudo.
echo '%domain\ admins	         ALL=(ALL)	       ALL' >> /etc/sudoers

#MAKE SURE TO LOG OUT OF ALL Putty Sessions after making the changes to the SUDOERS group and then use putty to log back into the DC and test things out. 

```

# Configure Firewall
``` bash
apt-get install iptables iptables-persistent -y
export PATH=$PATH:/usr/sbin
iptables -F
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 88 -j ACCEPT
iptables -A INPUT -p udp --dport 88 -j ACCEPT
iptables -A INPUT -p udp --dport 123 -j ACCEPT
iptables -A INPUT -p tcp --dport 135 -j ACCEPT
iptables -A INPUT -p udp --dport 137 -j ACCEPT
iptables -A INPUT -p udp --dport 138 -j ACCEPT
iptables -A INPUT -p tcp --dport 139 -j ACCEPT
iptables -A INPUT -p tcp --dport 389 -j ACCEPT
iptables -A INPUT -p udp --dport 389 -j ACCEPT
iptables -A INPUT -p tcp --dport 445 -j ACCEPT
iptables -A INPUT -p tcp --dport 464 -j ACCEPT
iptables -A INPUT -p udp --dport 464 -j ACCEPT
iptables -A INPUT -p tcp --dport 636 -j ACCEPT
iptables -A INPUT -p tcp --dport 3268 -j ACCEPT
iptables -A INPUT -p tcp --dport 3269 -j ACCEPT
iptables -A INPUT -p tcp --dport 49152:65535 -j ACCEPT
iptables -A INPUT -p tcp -j DROP
iptables-save > /etc/iptables/rules.v4
```

## Restart DNS on DC01, then trigger DNS Updates
``` bash 
#Restart the DNS Services on DC01
ssh -l AD_Admin -t SAMBADC01 "sudo systemctl restart bind9"

#Log on to DC02 with putty and execute the following
/usr/sbin/samba_dnsupdate

#Reboot DC02
/usr/sbin/reboot

```

## Add Domain Certificate from DC01 and DC02 to the System's trusted certificates store
``` bash
cd ~/
cp /var/lib/samba/private/tls/ca.pem ./DC2CA.crt
scp AD_Admin@192.168.2.40:/var/lib/samba/private/tls/ca.pem ./DC1CA.crt
sudo cp *.crt /usr/local/share/ca-certificates
sudo /usr/sbin/update-ca-certificates
```
