#Change the Network to use a static IP Address (DC02)
sed -i 's/dhcp/static\n   address 192\.168\.2\.41\n   netmask 255\.255\.255\.0\n   gateway 192\.168\.2\.1\n   dns-nameservers 192\.168\.2\.40 192\.168\.2\.41\n   dns-domain mydomain\.com\n   dns-search mydomain\.com/g' /etc/network/interfaces

#Modify resolv.conf to point to local system:
Change /etc/resolv.conf

echo domain mydomain.com > /etc/resolv.conf
echo search mydomain.com >> /etc/resolv.conf
echo nameserver 192.168.2.40 >> /etc/resolv.conf

#Reboot Server 
/usr/sbin/reboot

# Name the domain and answer prompts
apt install samba smbclient krb5-user winbind bind9 dnsutils -y   


#Remove the Default SAMBA Config to prepare for setup
(cd /etc/samba && mv smb.conf smb.conf.orig)

samba-tool domain join mydomain.com DC -U "mydomain\Administrator" --dns-backend=BIND9_DLZ

#Open the following file with your favorite editor, and uncomment the bind9-dlz module of your choice by removing the # before the version that is the closest match in /var/lib/samba/bind-dns/named.conf:

sed -i 's/# database.*11.*;/database \"dlopen \/usr\/lib\/x86_64-linux-gnu\/samba\/bind9\/dlz_bind9_11.so\";/g' /var/lib/samba/bind-dns/named.conf

#Open the /etc/bind/named.conf file, and add the following include statement to the end of named.conf:
echo 'include "/var/lib/samba/bind-dns/named.conf";' >> /etc/bind/named.conf


#Add the tkey and minimal responses statements to the /etc/bind/named.conf.options file 
sed -i 's/directory \"\/var\/cache\/bind\";/directory \"\/var\/cache\/bind\";\n        tkey-gssapi-keytab \"\/var\/lib\/samba\/private\/dns\.keytab\";\n        minimal\-responses yes;/g' /etc/bind/named.conf.options


#Change file permissions
chmod 640 /var/lib/samba/private/dns.keytab
chown root:bind /var/lib/samba/private/dns.keytab
chmod 644 /var/lib/samba/bind-dns/named.conf
chown root:bind /var/lib/samba/bind-dns/named.conf
chmod 755 /var/lib/samba/bind-dns

#Disable DNSSec Validation
sed -i 's/dnssec\-validation auto;/\/\/dnssec\-validation auto;/g' /etc/bind/named.conf.options

#Restart some services
systemctl restart bind9

systemctl stop smbd nmbd winbind
systemctl disable smbd nmbd winbind
systemctl mask smbd nmbd winbind
systemctl unmask samba-ad-dc
systemctl enable samba-ad-dc

#Clean up the /etc/krb5.conf
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
                kdc = SambaDC01.mydomain.com
                kdc = sambadc02.mydomain.com
                admin_server = SambaDC01.mydomain.com
                default_domain = mydomain.com
        }

[domain_realm]
        .mydomain.com = MYDOMAIN.COM
EOF


#Restart the SAMBA DC Service
systemctl start samba-ad-dc

#Add Reverse DNS Entry
kinit administrator
samba-tool dns add SambaDC01 2.168.192.in-addr.arpa 41.2.168.192.in-addr.arpa PTR sambadc02.mydomain.com

#Test DNS Resolution
host -t A SambaDC01.mydomain.com
host -t PTR 192.168.2.40
host -t PTR 192.168.2.41
host -t SRV _ldap._tcp.mydomain.com
host -t SRV _kerberos._tcp.mydomain.com
host -t SRV _kerberos._udp.mydomain.com

#-----------  Configure PAM for Linux
apt-get install oddjob-mkhomedir realmd sssd-tools sssd libnss-sss libpam-sss adcli sssd-krb5 krb5-config krb5-user libpam-krb5 sudo -y

echo "session optional      pam_oddjob_mkhomedir.so skel=/etc/skel" >> /etc/pam.d/common-session

#Create the /etc/sssd/sssd.conf > file
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

#Create /etc/krb5.keytab
sed -i 's/workgroup \= MYDOMAIN/workgroup \= MYDOMAIN\n        kerberos method = secrets and keytab/g' /etc/samba/smb.conf
kinit administrator
net ads keytab create
klist -k -K -t /etc/krb5.keytab


#Restart SSSD to make sure the krb5 service takes the new settings.
/usr/bin/systemctl restart sssd

#Add Active Directory Group to sudoers file
echo '%linuxsudoers           ALL=(ALL)       ALL' >> /etc/sudoers

#The goal is to use the group above, but you can also add the Administrators group to allow any user on the Domain Controller that is in that group to use sudo.
echo '%Administrators	         ALL=(ALL)	      ALL' >> /etc/sudoers


