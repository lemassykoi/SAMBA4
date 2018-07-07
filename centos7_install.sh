## CentOS 7 - Samba 4.8.2 - 20180615

##############################################################
####### INIT #################################################
##############################################################

mkdir .ssh
echo "ssh-rsa AAAA" > .ssh/authorized_keys
echo "export PS1='\[\e]0;\u@\h: \w\a\]${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w \@\$ \[\033[00m\]'" >> .bashrc
su -

mkdir .ssh
echo "ssh-rsa AAAA" > .ssh/authorized_keys
echo "export PS1='\[\e]0;\u@\h: \w\a\]${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w \@\$ \[\033[00m\]'" >> .bashrc

yum update -y 

yum install -y nano yum-utils

hostnamectl set-hostname DC1.domain.local

hostname -s   # Short name
hostname -f   # FQDN
hostname -d   # Domain

nano /etc/hosts
##
127.0.0.1   localhost ....
192.168.30.254 dc1.domain.local dc1 
##

nano /etc/selinux/config
##
SELINUX=disabled
##

init 6

# make a snapshot

## verifier l'etat de SELINUX
sestatus

## clean up le boot non utilisé
package-cleanup --oldkernels --count=1

yum install -y epel-release 

yum install attr bind-utils docbook-style-xsl gcc gdb git krb5-workstation \
       libsemanage-python libxslt perl perl-ExtUtils-MakeMaker \
       perl-Parse-Yapp pkgconfig policycoreutils-python \
       python2-crypto gnutls-devel libattr-devel keyutils-libs-devel \
       libacl-devel libaio-devel libblkid-devel libxml2-devel ntp openldap-devel \
       pam-devel popt-devel python-devel readline-devel zlib-devel systemd-devel wget


wget https://download.samba.org/pub/samba/stable/samba-4.8.2.tar.gz
tar -zxvf samba-4.8.2.tar.gz
cd samba-4.8.2

mv /etc/krb5.conf /etc/krb5.conf.original

## ./configure --help
./configure --enable-debug --enable-selftest --with-systemd --with-ads --with-winbind --sysconfdir=/etc/samba --sbindir=/sbin --bindir=/bin --mandir=/usr/share/man --with-logfilebase=/var/log/samba -vv -p
make -j 4
## tests qui ratent :
echo "^samba4.rpc.echo.*on.*ncacn_np.*with.*object.*nt4_dc" >> selftest/knownfail
## make quicktest ## 20 minutes
make install

ln -s  /usr/local/samba/lib/libnss_winbind.so.2  /lib64/libnss_winbind.so
ln -s /lib64/libnss_winbind.so  /lib64/libnss_winbind.so.2
ln -s /usr/lib64/libgnutls.so.28 /usr/lib64/libgnutls.so.26

## CHOIX 1 : INTERACTIF
samba-tool domain provision --use-rfc2307 --interactive

## CHOIX 2 : MANUEL
samba-tool domain provision --use-rfc2307 --realm=DOMAIN.LOCAL --domain=DOMAIN --server-role=dc --dns-backend=SAMBA_INTERNAL --adminpass=ADMINPASS

samba-tool user setexpiry administrator --noexpiry

cp /usr/local/samba/private/krb5.conf /etc/krb5.conf.samba

cat /etc/krb5.conf.samba
nano /etc/krb5.conf
##
[libdefaults]
        default_realm = DOMAIN.LOCAL
        dns_lookup_realm = false
        dns_lookup_kdc = true

        ticket_lifetime = 24h
#        default_keytab_name = /etc/squid/HTTP.keytab
[realms]
DOMAIN.LOCAL = {
kdc = dc1.domain.local
admin_server = dc1.domain.local
default_domain = domain.local
}
;
[domain_realm]
.domain.local = DOMAIN.LOCAL
domain.local = DOMAIN.LOCAL
##

nano /etc/sysconfig/network-scripts/ifcfg-ens160
DNS1="127.0.0.1"

nano /etc/nsswitch.conf
passwd:          winbind sss
group:           winbind sss


init 6

######startup samba
nano /etc/systemd/system/samba.service
##
[Unit]
Description= Samba 4 Active Directory
After=syslog.target
After=network.target

[Service]
Type=forking
PIDFile=/usr/local/samba/var/run/samba.pid
ExecStart=/sbin/samba

[Install]
WantedBy=multi-user.target
##

systemctl enable samba
systemctl start samba

## FIREWALL RULES

firewall-cmd --permanent --add-port=53/tcp
firewall-cmd --permanent --add-port=53/udp
firewall-cmd --permanent --add-port=88/tcp
firewall-cmd --permanent --add-port=88/udp
firewall-cmd --permanent --add-port=135/tcp
firewall-cmd --permanent --add-port=137/tcp
firewall-cmd --permanent --add-port=137/udp
firewall-cmd --permanent --add-port=138/udp
firewall-cmd --permanent --add-port=139/tcp
firewall-cmd --permanent --add-port=389/tcp
firewall-cmd --permanent --add-port=389/udp
firewall-cmd --permanent --add-port=445/tcp
firewall-cmd --permanent --add-port=464/tcp
firewall-cmd --permanent --add-port=464/udp
firewall-cmd --permanent --add-port=636/tcp
firewall-cmd --permanent --add-port=1024-5000/tcp
firewall-cmd --permanent --add-port=1024-5000/udp
firewall-cmd --permanent --add-port=3268/tcp
firewall-cmd --permanent --add-port=3269/tcp
firewall-cmd --permanent --add-port=5353/tcp
firewall-cmd --permanent --add-port=5353/udp
firewall-cmd --permanent --add-service=ntp
firewall-cmd --reload

## OR DISABLE ALL

systemctl stop firewalld     # stop firewalld temporarily
systemctl mask firewalld    # not sure what mask does

nano /etc/pam.d/system-auth
# REMOVE "use_authtok"

## check
host -t SRV _ldap._tcp.domain.local
host -t SRV _kerberos._udp.domain.local
host -t A dc1.domain.local

echo ADMINPASS | kinit administrator
klist

samba-tool domain passwordsettings show
samba-tool domain passwordsettings set --complexity=off -U administrator
samba-tool domain passwordsettings set --history-length=0 -U administrator
samba-tool domain passwordsettings set --min-pwd-age=0 -U administrator
samba-tool domain passwordsettings set --max-pwd-age=0 -U administrator
samba-tool domain passwordsettings set --min-pwd-length=6 -U administrator
samba-tool domain passwordsettings show

samba-tool user create adminafpa P@ssw0rd --company=AFPA --mail-address=afpa@afpa.fr --given-name="User" --surname="AFPA" --login-shell=/bin/bash -U administrator
samba-tool group addmembers "domain admins" adminafpa
samba-tool group addmembers "schema admins" adminafpa
samba-tool group addmembers "enterprise admins" adminafpa

## Groupe Global pour le Service (achats, compta, direction...)
samba-tool group addmembers GG_DOMAIN_DG adminafpa -U administrator
## Groupe LOCAL pour les droits NTFS, par Service (achats, compta, direction...)
samba-tool group addmembers GL_DOMAIN_DG_CT GG_DOMAIN_DG

## création zone REVERSE DNS principale
samba-tool dns zonecreate DC1 30.168.192.in-addr.arpa -U administrator
## création d'un record pour la passerelle
samba-tool dns add DC1 domain.local GATEWAY A 192.168.30.1 -U administrator
## reverse DNS passerelle
samba-tool dns add DC1 30.168.192.in-addr.arpa GATEWAY PTR 192.168.30.1 -U administrator

## repertoire des Users
mkdir -p /srv/Users/
chown root:"Domain Users" /srv/Users/
chmod 0770 /srv/Users/
mkdir -p /srv/Public/
chmod 0770 /srv/Public/
mkdir -p /srv/DOMAIN_DATA/Domain_DG/
chmod -R 0770 /srv/DOMAIN_DATA/Domain_DG/

samba-tool user list
samba-tool group list
samba-tool domain level show

samba-tool group addmembers GG_DOMAIN_RDP_ALLOWED adminafpa -U administrator
## ajouter le Groupe GG_DOMAIN_RDP_ALLOWED au groupe builtin Remote Desktop Users

## créer les subnets dans sites et services

nano /etc/samba/smb.conf
## ajouter :
	template shell = /bin/bash
	allow dns updates = nonsecure
	winbind enum users = yes
	winbind enum groups = yes
	winbind use default domain = true
	winbind nss info = rfc2307
	template homedir = /srv/Users/%U
	ldap server require strong auth = no
##
	
echo "

[Public]
   comment = Partage Public
   path = /srv/Public
   guest ok = yes
   browseable = yes
   public = yes
   writable = yes
   read only = no
   printable = no
   create mask = 0777
   directory mask = 0777

[Direction]
   comment = Répertoire Direction
   path = /srv/DOMAIN_DATA/Domain_DG
   guest ok = no
   browseable = yes
   public = no
   writable = yes
   read only = no
   printable = no
   valid users = @\"DOMAIN\\gl_domain_dg_ct\" @\"DOMAIN\\administrator\"

[Users]
   path = /srv/Users
   read only = no

" >> /etc/samba/smb.conf

net rpc rights grant "DOMAIN\Domain Admins" SeDiskOperatorPrivilege -U administrator

echo "broadcast 192.168.30.255" >> /etc/ntp.conf
nano /etc/ntp.conf
pool 0.fr.pool.ntp.org iburst
## restrict sans aucune option derriere, soit 0.0.0.0, soit le LAN local 192.168.30.0
restrict 0.0.0.0 mask 0.0.0.0
server domain.local

systemctl restart ntp

## disable ipv6
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
## memory optimization
echo 'vm.nr_hugepages=128' >> /etc/sysctl.conf

sysctl -p

## memory optimization
echo '* soft memlock 262144' >> /etc/security/limits.conf
echo '* hard memlock 262144'  >> /etc/security/limits.conf

shutdown -r now

## DHCP

yum install -y dhcp

nano /etc/dhcp/dhcpd.conf
##
authoritative;
ddns-updates on;
update-static-leases on;
ddns-update-style interim;
deny declines;
deny bootp;
ignore client-updates;
default-lease-time 600;
max-lease-time 7200;
option wpad-url code 252 = text;
option wpad-url "http://192.168.30.250/proxy.pac";
option domain-name-servers 192.168.30.250, 192.168.30.251;
option domain-name "domain.local";
log-facility local7;

#include "/etc/bind/ddns.key";

zone domain.local. {
        primary 127.0.0.1;
#        key DDNS_UPDATE;
}

zone 30.168.192.in-addr.arpa. {
        primary 127.0.0.1;
#        key DDNS_UPDATE;
}

subnet 192.168.30.0 netmask 255.255.255.0 {
range 192.168.30.101 192.168.30.199;
option broadcast-address 192.168.30.255;
option subnet-mask 255.255.255.0;
option domain-name-servers 192.168.30.250, 192.168.30.251;
option domain-name "domain.local";
option routers 192.168.30.251;
option ntp-servers 192.168.30.254;
ddns-domainname "domain.local.";
ddns-rev-domainname "in-addr.arpa";
get-lease-hostnames true;
use-host-decl-names true;
default-lease-time 600;
max-lease-time 7200;
filename "pxelinux.0";
option tftp-server-name "192.168.30.254";

host PC1 {
  hardware ethernet 00:1D:7D:04:27:8E;
  fixed-address 192.168.30.90;}

}

group {
  next-server 192.168.30.254;
  host tftpclient {
    filename "pxelinux.0";
}
}
##

systemctl enable dhcpd
systemctl start dhcpd
