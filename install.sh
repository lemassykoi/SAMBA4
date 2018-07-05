## SAMBA 4.7 AD DEBIAN 9
##############################################################
####### INIT #################################################
##############################################################

## INSTALL FRAICHE DE DEBIAN - MINIMAL (sans paquets sauf serveur SSH)

## se connecter avec le user créé à l'install
## poser la clé SSH pour se connecter sans mot de passe
mkdir .ssh
echo "ssh-rsa AAAAB...==" > .ssh/authorized_keys
## un peu de couleur
echo "export PS1='\[\e]0;\u@\h: \w\a\]${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w \@\$ \[\033[00m\]'" >> .bashrc
su -
## entrer le mot de passe root
## et meme opérations que précédemment
mkdir .ssh
echo "ssh-rsa AAAAB...==" > .ssh/authorized_keys
echo "export PS1='\[\e]0;\u@\h: \w\a\]${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w \@\$ \[\033[00m\]'" >> .bashrc
## on vide la bannière, qui ne sert à rien
rm /etc/motd
touch /etc/motd

## on install quelques paquets essentiels
apt update
apt install -y sudo screen unzip git

## on ajoute le user au groupe sudo
adduser USER sudo 


nano /etc/network/interfaces
#STATIC

nano /etc/resolv.conf
#CHECK

nano /etc/hostname
#FQDN

nano /etc/hosts
127.0.0.1       localhost ....
192.168.30.250	DC1.MYDOM.local  DC1

reboot

##############################################################
##Samba 4.7 ## Conditional forwarders are not implemented yet#
##############################################################

wget -O - http://samba.tranquil.it/tissamba-pubkey.gpg  | apt-key add -
echo "deb http://samba.tranquil.it/debian/samba-4.7 stretch main" > /etc/apt/sources.list.d/tissamba.list

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install samba winbind libpam-winbind libnss-winbind krb5-user ntp dnsutils
unset DEBIAN_FRONTEND

cp /etc/ntp.conf /etc/ntp.conf.original
echo "broadcast 192.168.30.255" >> /etc/ntp.conf
nano /etc/ntp.conf
##
pool 192.168.30.254 iburst
restrict 0.0.0.0 mask 0.0.0.0
server mydom.local
##

systemctl restart ntp

mv /etc/samba/smb.conf /etc/samba/smb.conf.original
mv /etc/krb5.conf /etc/krb5.conf.original

## on provisionne le domaine
samba-tool domain provision --server-role=dc --use-rfc2307 --dns-backend=SAMBA_INTERNAL --realm=MYDOM.LOCAL --domain=MYDOM --adminpass=ADMINPASSWORD
samba-tool user setexpiry administrator --noexpiry

cp /var/lib/samba/private/krb5.conf /etc/krb5.conf.samba

nano /etc/krb5.conf
##
[libdefaults]
        default_realm = MYDOM.LOCAL
        dns_lookup_realm = false
        dns_lookup_kdc = true

        ticket_lifetime = 24h
#        default_keytab_name = /etc/squid/HTTP.keytab

[realms]
MYDOM.LOCAL = {
kdc = dc1.mydom.local
admin_server = dc1.mydom.local
default_domain = mydom.local
}
;
[domain_realm]
.mydom.local = MYDOM.LOCAL
mydom.local = MYDOM.LOCAL
##

nano /etc/resolv.conf
## doit pointer sur 127.0.0.1

nano /etc/network/interfaces
## verifier que le dns est bien OK, si static

systemctl unmask samba-ad-dc
systemctl enable samba-ad-dc
systemctl disable samba winbind nmbd smbd
systemctl mask samba winbind nmbd smbd

reboot


## check
host -t SRV _ldap._tcp.mydom.local
host -t SRV _kerberos._udp.mydom.local
host -t A dc1.mydom.local

echo ADMINPASSWORD | kinit administrator
klist

nano /etc/nsswitch.conf
## ajouter winbind
passwd:         compat winbind
group:          compat winbind
##

nano /etc/pam.d/common-password
## REMOVE "use_authtok" dans le fichier

echo ADMINPASSWORD | kinit administrator
klist -e

## test, si ne retourne rien, pas ok
getent passwd MYDOM\\administrator
getent group "MYDOM\\Domain Users"

## password complexity settings
samba-tool domain passwordsettings show
samba-tool domain passwordsettings set --complexity=off -U administrator
samba-tool domain passwordsettings set --history-length=0 -U administrator
samba-tool domain passwordsettings set --min-pwd-age=0 -U administrator
samba-tool domain passwordsettings set --max-pwd-age=0 -U administrator
samba-tool domain passwordsettings set --min-pwd-length=6 -U administrator
samba-tool domain passwordsettings show

samba-tool group add GG_MYDOM_ALL --group-scope=Global -U administrator
samba-tool group add GG_MYDOM_DG --group-scope=Global -U administrator
samba-tool group add GG_MYDOM_RDP_ALLOWED --group-scope=Global -U administrator

samba-tool dns zonecreate DC1 30.168.192.in-addr.arpa -U administrator

samba-tool dns add DC1 mydom.local GATEWAY A 192.168.30.1 -U administrator

samba-tool dns add DC1 30.168.192.in-addr.arpa GATEWAY PTR 192.168.30.1 -U administrator

## répertoire de stockage des profils si nécessaire
mkdir -p /srv/Users/Profiles/
chown -R root:"Domain Users" /srv/Users/Profiles/
chmod -R 0770 /srv/Users/Profiles/

mkdir /srv/Public
mkdir /srv/pxe
mkdir /srv/pxe/win7
mkdir /srv/pxe/win10
mkdir /srv/MyDom_DATA
mkdir /srv/MyDom_DATA/MyDom_ALL
chmod 777 /srv/Public
chmod -R 777 /srv/MyDom_DATA
chmod -R 777 /srv/pxe

## second test
 samba-tool user list
 samba-tool group list
 samba-tool domain level show
 
## ajouter le Groupe GG_MYDOM_RDP_ALLOWED au groupe builtin Remote Desktop Users avec RSAT
## créer les subnets dans sites et services

nano /etc/samba/smb.conf
## ajouter ça dans le bloc du début :
	template shell = /bin/bash
	allow dns updates = nonsecure
	winbind enum users = yes
	winbind enum groups = yes
	winbind use default domain = true
	winbind nss info = rfc2307
	template homedir = /srv/Users/%U
	ldap server require strong auth = no
##

## les partages SAMBA :	
echo "

[Public]
   comment = Dossier Public
   path = /srv/Public
   guest ok = yes
   browseable = yes
   public = yes
   writable = yes
   read only = no
   printable = no
   create mask = 0777
   directory mask = 0777

[MyDom]
   comment = Répertoire commun MyDom
   path = /srv/MyDom_DATA/MyDom_ALL
   guest ok = yes
   browseable = yes
   public = yes
   writable = yes
   read only = no
   printable = no

[Direction]
   comment = Répertoire Direction MyDom
   path = /srv/MyDom_DATA/MyDom_DG
   guest ok = no
   browseable = yes
   public = no
   writable = yes
   read only = no
   printable = no
   valid users = @\"MYDOM\\gl_mydom_dg_ct\" @\"MYDOM\\administrator\"

[TFTP]
   comment = Répertoire TFTP
   path = /srv/tftp
   guest ok = no
   browseable = yes
   public = no
   writable = yes
   read only = no
   printable = no
   valid users = @\"MYDOM\\gl_mydom_dg_ct\" @\"MYDOM\\administrator\" root USER

[PXE_Images]
   comment = Répertoire des Images PXE
   path = /srv/pxe
   guest ok = no
   browseable = yes
   public = no
   writable = yes
   read only = no
   printable = no
   valid users = @\"MYDOM\\gl_mydom_dg_ct\" @\"MYDOM\\administrator\" root USER

[Users]
   path = /srv/Users/
   read only = no

" >> /etc/samba/smb.conf

net rpc rights grant "MYDOM\Domain Admins" SeDiskOperatorPrivilege -U administrator

####### GERER LES AUTORISATIONS DU PARTAGE HOME DEPUIS UN WINDOWS : #########
	https://wiki.samba.org/index.php/User_Home_Folders

smbcontrol all reload-config

samba-tool user create testuser P@ssw0rd --company=MyDom --mail-address=test@mydom.local --login-shell=/bin/bash --home-directory=\\\\dc1.mydom.local\\Users\\testuser --home-drive=P -U administrator
samba-tool user create USER USERPASSWORD --company=MyDom --mail-address=USER@mydom.local --given-name="Admin" --surname="User" --login-shell=/bin/bash -U administrator

samba-tool group addmembers GG_MYDOM_DG USER -U administrator
samba-tool group addmembers GG_MYDOM_RDP_ALLOWED USER,testuser -U administrator
samba-tool group addmembers GL_MYDOM_DG_CT GG_MYDOM_DG
samba-tool group addmembers "domain admins" USER
samba-tool group addmembers "schema admins" USER
samba-tool group addmembers "enterprise admins" USER


testparm
systemctl restart samba-ad-dc.service

pam-auth-update





### END

##GERER LES REPERTOIRES HOME DEPUIS MMC ACTIVE DIRECTORY USERS 
## lecteur P: à \\DC1.mydom.local\Users\%USERNAME%



##############################################################
########## DHCP ##############################################
##############################################################

apt install -y isc-dhcp-server
nano /etc/default/isc-dhcp-server
 ## mettre le device eth0 ou ens192 ou ...
  
mv /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.original
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
option domain-name "mydom.local";
log-facility local7;

#include "/etc/bind/ddns.key";

zone mydom.local. {
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
option domain-name "mydom.local";
option routers 192.168.30.251;
option ntp-servers 192.168.30.250;
ddns-domainname "mydom.local.";
ddns-rev-domainname "in-addr.arpa";
get-lease-hostnames true;
use-host-decl-names true;
default-lease-time 600;
max-lease-time 7200;
filename "pxelinux.0";
option tftp-server-name "192.168.30.250";

host PC1 {
  hardware ethernet 00:1D:7D:04:27:8E;
  fixed-address 192.168.30.90;}

host iDRAC8 {
  hardware ethernet 18:66:da:7e:9e:e1;
  fixed-address 192.168.30.253;}

}

group {
  next-server 192.168.30.250;
  host tftpclient {
    filename "pxelinux.0";
}
}
##

service isc-dhcp-server restart
systemctl status isc-dhcp-server.service

## pour voir les leases
dhcp-lease-list

##############################################################
########## APACHE 2 ##########################################
##############################################################

apt install apache2

## autodiscover proxy
nano /var/www/html/proxy.pac
##
function FindProxyForURL(url, host) {

// If the requested website is hosted within the internal network, send direct.
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
        isInNet(dnsResolve(host), "172.16.0.0",  "255.240.0.0") ||
        isInNet(dnsResolve(host), "192.168.0.0",  "255.255.0.0") ||
        isInNet(dnsResolve(host), "127.0.0.0", "255.255.255.0"))
        return "DIRECT";

// If the protocol or URL matches, send direct.
    if (shExpMatch(url, "https://www.google.fr/*") ||
        shExpMatch(url, "https://www.afpa.fr/*"))
        return "DIRECT";

// DEFAULT RULE: All other traffic, use below proxies, in fail-over order.
    return "PROXY squid-http.mydom.local:3128";

}
##


##############################################################
######### PROXY -- SQUID 3.5 #################################
##############################################################

apt update
apt install -y squid msktutil gcc make linux-headers-$(uname -r) libkrb5-dev
mv /etc/squid/squid.conf /etc/squid/squid.conf.original
grep ^[^#] /etc/squid/squid.conf.original > /etc/squid/squid.conf.ori.clean

nano /etc/squid/squid.conf

##
visible_hostname DC1.MyDom.local
cache_mgr USER@mydom.local

## KERBEROS Auth
auth_param negotiate program /usr/lib/squid/negotiate_kerberos_auth -r -s HTTP/proxy.mydom.local@MYDOM.LOCAL
auth_param negotiate children 50
auth_param negotiate keep_alive on

## BASIC Auth
#auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwords
#auth_param basic realm proxy

acl authenticated proxy_auth REQUIRED
acl mydom_DG src 192.168.30.100
acl mydom_phones src 192.168.30.230-192.168.30.239
acl mydom_servers src 192.168.30.245-192.168.30.254
acl mydom_lan src 192.168.30.0/24
external_acl_type ldap_group_dg %LOGIN /usr/lib/squid/ext_kerberos_ldap_group_acl -a -g GG_MYDOM_DG@ -D MYDOM.LOCAL
acl LDAP_GROUP_CHECK_DG external ldap_group_dg
acl test src 192.168.30.101
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
acl xforwardedfor req_header X-Forwarded-For -i 127.0.0.1
acl whitelist dstdomain "/etc/squid/whitelist"
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager
http_access deny to_localhost
http_access allow localhost
##### Access rules
http_access allow mydom_DG
http_access allow mydom_servers
http_access allow mydom_phones
http_access deny !authenticated
http_access allow mydom_lan
#http_access allow test whitelist authenticated
#http_access allow mydom_lan authenticated
http_access deny all

http_port 3128
logformat squid      %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt
coredump_dir /var/spool/squid
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
dns_v4_first   on
##


nano /etc/squid/whitelist
##
.pagesjaunes.fr
.ovh.net
.w3tel.com
.airria.fr
.geoconcept.com
.mydom.local
##

chown proxy:proxy /etc/squid/whitelist

systemctl restart squid

## squid ok for local lan on port 3128

## Option 1 ## BASIC AUTH
htpasswd -c /etc/squid/passwords username

## Option 2 ## transparent : 
iptables -t nat -A PREROUTING -i eth0 -s 192.168.30.0/24 -p tcp --dport 80 -j REDIRECT --to-port 3128
iptables -t nat -A PREROUTING -i eth0 -s 192.168.30.0/24 -p tcp --dport 443 -j REDIRECT --to-port 3128

##############################################################
### SQUID Kerberos AUTH ######################################
##############################################################
http://www.aptenodyte.fr/post/2017/05/31/Proxy-Squid-avec-authentification-pure-Kerberos-et-SquidGuard-1


kinit administrator
msktutil -c -b "CN=Computers" -s HTTP/proxy.mydom.local -h proxy.mydom.local -k /etc/squid/HTTP.keytab --computer-name squid-http --upn HTTP/proxy.mydom.local --server DC1.mydom.local --verbose
samba-tool dns add DC1 mydom.local squid-http A 192.168.30.250 -U administrator

chgrp proxy /etc/squid/HTTP.keytab
chmod g+r /etc/squid/HTTP.keytab
nano /etc/krb5.conf

nano /etc/squid/squid.conf
## ajouter : 
#Authentification automatique via Kerberos 
auth_param negotiate program /usr/lib/squid/negotiate_kerberos_auth -r -s HTTP/proxy.mydom.local@MYDOM.LOCAL
auth_param negotiate children 50
auth_param negotiate keep_alive on
external_acl_type ldap_group_crtt %LOGIN /usr/lib/squid/ext_kerberos_ldap_group_acl -a -g GG_MYDOM_CRTT@ -D MYDOM.LOCAL
external_acl_type ldap_group_planifs %LOGIN /usr/lib/squid/ext_kerberos_ldap_group_acl -a -g GG_MYDOM_PLANIFS@ -D MYDOM.LOCAL
external_acl_type ldap_group_dg %LOGIN /usr/lib/squid/ext_kerberos_ldap_group_acl -a -g GG_MYDOM_DG@ -D MYDOM.LOCAL
acl LDAP_GROUP_CHECK_CRTT external ldap_group_crtt
acl LDAP_GROUP_CHECK_PLANIFS external ldap_group_planifs
acl LDAP_GROUP_CHECK_DG external ldap_group_dg
...
acl auth proxy_auth REQUIRED

http_access deny !authenticated
http_access allow authenticated
http_access deny all
##

nano /etc/default/squid
##
SQUID_MAXFD=1024 
KRB5_KTNAME=/etc/squid/HTTP.keytab
export KRB5_KTNAME
## si high CPU Usage :
#KRB5RCACHETYPE=none
#export KRB5RCACHETYPE
##

systemctl restart squid


nano /etc/profile
## ajouter /usr/lib/squid au PATH (sur les 2 lignes)

reboot

### TEST
echo ADMINPASSWORD | kinit administrator
negotiate_kerberos_auth_test proxy.mydom.local | awk '{sub(/Token:/,"YR"); print $0}END{print "QQ"}' | negotiate_kerberos_auth -r -s HTTP/proxy.mydom.local@MYDOM.LOCAL

## doit retourner :
## AF oRQwEqADCgEAoQsGCSqGSIb3EgECAg== administrator
## BH quit command


## pour le proxy dans windows, mettre la valeur : squid-http.mydom.local port 3128 (GPO et proxy.pac)

#########exemple : à tester

# Autorise
#   les users non authentifies
#   from MyDom_lan
#   a la WHITELIST site http
http_access allow mydom_lan whitelist

# Autorise
#   les users authentifies
#   from MyDom_lan
#   a l'internet
http_access allow authenticated mydom_lan LDAP_GROUP_CHECK_DG
# Refuse tout autre connexion
http_access deny all
##

##############################################################
### SARG #####################################################
##############################################################

apt install sarg 
mv /etc/sarg/sarg.conf /etc/sarg/sarg.conf.original
grep ^[^#] /etc/sarg/sarg.conf.original > /etc/sarg/sarg.conf
mkdir  /var/www/html/squid-reports

nano /etc/sarg/sarg.conf
## changer ces parametres :
access_log
output_dir /var/www/html/squid-reports
date_format e
overwrite_report
charset UTF8

cat /usr/sbin/sarg-reports
## LIRE

nano /etc/logrotate.d/squid
## CHANGE TO MONTHLY

crontab -e
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
00 08-18/1 * * * sarg-reports today
00 00      * * * sarg-reports daily
00 01      * * 1 sarg-reports weekly
30 02      1 * * sarg-reports monthly
##


##############################################################
######### CUPS ###############################################
##############################################################

apt update
apt install cups smbclient ## pour HP : hplip pour EPSON : printer-driver-escpr
cp /etc/cups/cupsd.conf /etc/cups/cupsd.conf.original
cupsctl --remote-admin

nano /etc/samba/smb.conf
##
   printcap cache time = 60
   printcap name = cups
   printing = cups
   load printers = yes
   use client driver = no
   rpc_server:spoolss = external
   rpc_daemon:spoolssd = fork

 [printers]
   comment = All Printers
   path = /var/spool/samba
   printable = Yes
   
 [print$]
   comment = Printer Drivers
   path = /var/lib/samba/printers
   read only = No
   writeable = yes
##

service cups restart

echo ADMINPASSWORD | net rpc rights grant "MYDOM\Domain Admins" SePrintOperatorPrivilege -U "MYDOM\administrator"

chmod -R 2755  /var/lib/samba/usershares/imprimantes/
setfacl -R -m g:"domain admins":rwx /var/lib/samba/printers
setfacl -R -d -m g:"domain admins":rwx /var/lib/samba/printers
chmod -R g+rwx /var/lib/samba/printers
chown -R administrator:"domain admins" /var/lib/samba/printers
chmod 1777 /var/spool/samba/

mkdir -p /usr/share/cups/drivers/x64
## récupérer sur un windows 10 x64 dans %windir%\System32\spool\drivers\x64\3
PS5UI.DLL
PSCRIPT.HLP
PSCRIPT.NTF
PSCRIPT5.DLL
## les renommer en lowercase et les copier dans /usr/share/cups/drivers/x64
mv /usr/share/cups/drivers/x64/PS5UI.DLL /usr/share/cups/drivers/x64/ps5ui.dll
mv /usr/share/cups/drivers/x64/PSCRIPT.HLP /usr/share/cups/drivers/x64/pscript.hlp
mv /usr/share/cups/drivers/x64/PSCRIPT.NTF /usr/share/cups/drivers/x64/pscript.ntf
mv /usr/share/cups/drivers/x64/PSCRIPT5.DLL /usr/share/cups/drivers/x64/pscript5.dll

cupsaddsmb -a -U Administrator -v


https://dev.tranquil.it/wiki/SAMBA_-_Samba4_et_CUPS

https://192.168.30.250:631/admin


##############################################################
######### PXE ################################################
##############################################################

https://wiki.debian-fr.xyz/PXE_avec_support_EFI

apt install syslinux syslinux-efi pxelinux memtest86+ tftpd-hpa

systemctl enable tftpd-hpa
systemctl restart tftpd-hpa
systemctl status tftpd-hpa

nano /etc/default/tftpd-hpa


#mv /srv/tftp/ /srv/tftp.bak/
mkdir -p /srv/tftp/boot/
mkdir -p /srv/tftp/iso/
mkdir -p /srv/tftp/bios/pxelinux.cfg/
mkdir -p /srv/tftp/efi32/pxelinux.cfg/
mkdir -p /srv/tftp/efi64/pxelinux.cfg/
cd /srv/tftp/bios && ln -s ../boot boot
cd /srv/tftp/efi32 && ln -s ../boot boot
cd /srv/tftp/efi64 && ln -s ../boot boot
cd /srv/tftp
chmod -R 777 /srv/tftp
cp /usr/lib/syslinux/modules/bios/* /srv/tftp/bios/
cp /usr/lib/PXELINUX/pxelinux.0 /srv/tftp/bios/
cp /boot/memtest86+.bin /srv/tftp/bios/memtest

wget -O /tmp/french.kbd http://thefredsite.free.fr/linux/knx_tutoriel/boot.img/french.kbd
cp /tmp/french.kbd /srv/tftp/bios/pxelinux.cfg/
cp /tmp/french.kbd /srv/tftp/efi64/pxelinux.cfg/
cp /tmp/french.kbd /srv/tftp/efi32/pxelinux.cfg/

#### Debian Net Boot
rm -rf /srv/tftp/boot/debian/installer/stretch/
mkdir -p /srv/tftp/boot/debian/installer/stretch/
cd /tmp
wget -c http://ftp.nl.debian.org/debian/dists/stretch/main/installer-amd64/current/images/netboot/netboot.tar.gz
tar -zxf netboot.tar.gz 
mv debian-installer/amd64/ /srv/tftp/boot/debian/installer/stretch/

##### PXE BIOS
nano /srv/tftp/bios/pxelinux.cfg/default
##
DEFAULT vesamenu.c32
PROMPT 0
TIMEOUT 300
ONTIMEOUT 0
NOESCAPE 1
KBDMAP pxelinux.cfg/french.kbd

menu title **** Menu BIOS PXE ****

label 0  
menu label ^Demarrage sur disque dur local
menu default
COM32 chain.c32
APPEND hd0 0

label 1
menu label ^Redemarrage
kernel reboot.c32

label 2
menu label ^Arret
kernel poweroff.c32

LABEL 3
MENU LABEL ^HDT - Outil de detection materiel
KERNEL hdt.c32

LABEL 12
MENU LABEL ^Memtest 86+
KERNEL memtest

MENU SEPARATOR

LABEL 4
MENU LABEL Netboot Debian 9
KERNEL boot/debian/installer/stretch/amd64/linux
APPEND vga=788 initrd=boot/debian/installer/stretch/amd64/initrd.gz --- quiet

LABEL 5
MENU LABEL Win7 x64 iPXE
kernel pxechn.c32
append 192.168.30.250::bios/undionly-w7.kpxe

LABEL 6
MENU LABEL Win10 x64 iPXE
kernel pxechn.c32
append 192.168.30.250::bios/undionly-w10.kpxe

MENU SEPARATOR

LABEL 7
MENU LABEL WinPE 3 x64 - Ghost
kernel pxechn.c32
append 192.168.30.250::bios/undionly-winpe3.kpxe

LABEL 8
MENU LABEL WinPE 4 x86 - Ghost
kernel pxechn.c32
append 192.168.30.250::bios/undionly-winpe4.kpxe

MENU SEPARATOR

LABEL 9
MENU LABEL Windows PE 3
KERNEL memdisk
INITRD ../iso/WinPE3.iso
APPEND iso raw

LABEL 10
MENU LABEL Windows PE 4
KERNEL memdisk
INITRD ../iso/WinPE4.iso
APPEND iso raw

MENU SEPARATOR

label Clonezilla-live
MENU LABEL Clonezilla Live (Ramdisk)
KERNEL ../clonezilla/live/vmlinuz
APPEND initrd=../clonezilla/live/initrd.img boot=live username=user union=overlay config components quiet noswap edd=on nomodeset nodmraid locales=fr_FR.UTF-8 keyboard-layouts=fr ocs_live_run="ocs-live-general" ocs_live_extra_param="" ocs_live_batch=no net.ifnames=0 nosplash noprompt fetch=tftp://192.168.30.250/clonezilla/live/filesystem.squashfs
##

cp /usr/lib/syslinux/modules/efi64/* /srv/tftp/efi64/
cp /usr/lib/SYSLINUX.EFI/efi64/syslinux.efi /srv/tftp/efi64/
cp /boot/memtest86+.bin /srv/tftp/efi64/memtest

##### PXE EFI64
nano /srv/tftp/efi64/pxelinux.cfg/default
##
DEFAULT vesamenu.c32
PROMPT 0
TIMEOUT 300
ONTIMEOUT 0
NOESCAPE 1
KBDMAP pxelinux.cfg/french.kbd

menu title **** Menu EFI64 PXE ****

label 0
menu label ^Demarrage sur disque dur local
menu default
COM32 chain.c32
APPEND hd0 0

label 1
menu label ^Redemarrage
kernel reboot.c32

label 2
menu label ^Arret
kernel poweroff.c32

LABEL 3
MENU LABEL ^HDT - Outil de detection materiel
KERNEL hdt.c32

LABEL 4
MENU LABEL Netboot Debian 9
KERNEL boot/debian/installer/stretch/amd64/linux
APPEND vga=788 initrd=boot/debian/installer/stretch/amd64/initrd.gz --- quiet

LABEL 5
MENU LABEL iPXE UEFI x64 - chainload iPXE from a PXE capable NIC
kernel pxechn.c32
append 192.168.30.250::efi64/ipxe.efi
##

cp /usr/lib/syslinux/modules/efi32/* /srv/tftp/efi32/
cp /usr/lib/SYSLINUX.EFI/efi32/syslinux.efi /srv/tftp/efi32/
cp /boot/memtest86+.bin /srv/tftp/efi32/memtest

##### PXE EFI32
nano /srv/tftp/efi32/pxelinux.cfg/default
##
DEFAULT vesamenu.c32
PROMPT 0
TIMEOUT 300
ONTIMEOUT 0
NOESCAPE 1
KBDMAP pxelinux.cfg/french.kbd

menu title **** Menu EFI32 PXE ****

label 0
menu label ^Demarrage sur disque dur local
menu default
COM32 chain.c32
APPEND hd0 0

label 1
menu label ^Redemarrage
kernel reboot.c32

label 2
menu label ^Arret
kernel poweroff.c32

LABEL 3
MENU LABEL ^HDT - Outil de detection materiel
KERNEL hdt.c32

LABEL 4
MENU LABEL Netboot Debian 9
KERNEL boot/debian/installer/stretch/amd64/linux
APPEND vga=788 initrd=boot/debian/installer/stretch/amd64/initrd.gz --- quiet

LABEL 5
MENU LABEL iPXE UEFI x86 - chainload iPXE from a PXE capable NIC
kernel pxechn.c32
append 192.168.30.250::efi32/ipxe.efi
##

nano /etc/dhcp/dhcpd.conf
ajouter :
##
option space PXE;
option PXE.mtftp-ip code 1 = ip-address;
option PXE.mtftp-cport code 2 = unsigned integer 16;
option PXE.mtftp-sport code 3 = unsigned integer 16;
option PXE.mtftp-tmout code 4 = unsigned integer 8;
option PXE.mtftp-delay code 5 = unsigned integer 8;
option arch code 93 = unsigned integer 16;

commenter :
##
filename "pxelinux.0";

ajouter :
##
option tftp-server-name "192.168.30.250";
option root-path "/srv/tftp/";
    if option arch = 00:06 {
                filename "efi32/syslinux.efi";
        } else if option arch = 00:07 {
                filename "efi64/syslinux.efi";
        } else if option arch = 00:09 {
                filename "efi64/syslinux.efi";
        } else {
                filename "bios/pxelinux.0";
        }
##

service isc-dhcp-server restart
systemctl status isc-dhcp-server.service



## IPXE
apt install ipxe
cp /usr/lib/ipxe/ipxe.efi /srv/tftp/efi32/
cp /usr/lib/ipxe/ipxe.efi /srv/tftp/efi64/
cp /usr/lib/ipxe/undionly.kpxe /srv/tftp/bios/
cp /usr/lib/syslinux/memdisk /srv/tftp/bios/

cd ~
wget http://git.ipxe.org/releases/wimboot/wimboot-latest.zip
unzip wimboot-latest.zip
cd wimboot-2.6.0-signed/
mkdir /var/www/html/win7
mkdir /var/www/html/win7/efi
mkdir /var/www/html/win7/efi/boot
mkdir /var/www/html/win7/boot
mkdir /var/www/html/win7/sources
mkdir /var/www/html/win10
mkdir /var/www/html/win10/efi
mkdir /var/www/html/win10/efi/boot
mkdir /var/www/html/win10/boot
mkdir /var/www/html/win10/sources
mkdir /var/www/html/winpe3
mkdir /var/www/html/winpe4
cp wimboot /var/www/html/win7
cp wimboot /var/www/html/win10
cp wimboot /var/www/html/winpe3
cp wimboot /var/www/html/winpe4

COPIER FICHIERS Win 7 ISO :
  /boot/bcd			/var/www/win7/boot/bcd
  /boot/boot.sdi	/var/www/win7/boot/boot.sdi
  /sources/boot.wim	/var/www/win7/sources/boot.wim  <== ceci est un WinPE 4 custom pour lancer install 
  /efi/boot/bootx64.efi	/var/www/win7/efi/boot/bootx64.efi

### OBLIGATOIRE

apt install liblzma-dev git
cd ~
git clone git://git.ipxe.org/ipxe.git
cd ipxe/src
nano boot-win7.ipxe
#!ipxe
  dhcp
  boot http://192.168.30.250/win7/boot.ipxe
##

nano boot-win10.ipxe
#!ipxe
  dhcp
  boot http://192.168.30.250/win10/boot.ipxe
##

nano uefi-win10.ipxe
#!ipxe
  dhcp
  boot http://192.168.30.250/win10/boot.ipxe
##

nano boot-winpe3.ipxe
#!ipxe
  dhcp
  boot http://192.168.30.250/winpe3/winPE3_boot.ipxe
##

nano boot-winpe4.ipxe
#!ipxe
  dhcp
  boot http://192.168.30.250/winpe4/winPE4_boot.ipxe
##

nano /var/www/html/win7/boot.ipxe
##
#!ipxe
set boot-url http://192.168.30.250/win7
kernel ${boot-url}/wimboot				wimboot
initrd ${boot-url}/winpeshl.ini         winpeshl.ini
initrd ${boot-url}/boot/bcd             bcd
initrd ${boot-url}/boot/boot.sdi        boot.sdi
initrd ${boot-url}/sources/boot.wim     boot.wim
boot
##

nano /var/www/html/win10/boot.ipxe
##
#!ipxe
set boot-url http://192.168.30.250/win10
kernel ${boot-url}/wimboot				wimboot
initrd ${boot-url}/boot/bcd             bcd
initrd ${boot-url}/boot/boot.sdi        boot.sdi
initrd ${boot-url}/efi/boot/bootx64.efi	bootx64.efi
initrd ${boot-url}/sources/boot.wim     boot.wim
boot
##

nano /var/www/html/winpe3/winPE3_boot.ipxe
##
#!ipxe
set boot-url http://192.168.30.250/winpe3
kernel ${boot-url}/wimboot						wimboot
initrd ${boot-url}/boot/bcd						bcd
initrd ${boot-url}/boot/boot.sdi				boot.sdi
initrd ${boot-url}/efi/boot/bootx64.efi			bootx64.efi
initrd ${boot-url}/sources/WinPE3x64_ghost.WIM	WinPE3x64_ghost.WIM
boot
##

nano /var/www/html/winpe4/winPE4_boot.ipxe
##
#!ipxe
set boot-url http://192.168.30.250/winpe4
kernel ${boot-url}/wimboot						wimboot
initrd ${boot-url}/boot/bcd						bcd
initrd ${boot-url}/boot/boot.sdi				boot.sdi
initrd ${boot-url}/sources/WinPE4x86_ghost.WIM	WinPE4x86_ghost.WIM
boot
##

make bin/undionly.kpxe EMBED=boot-win7.ipxe
mv bin/undionly.kpxe /srv/tftp/bios/undionly-w7.kpxe
make bin/undionly.kpxe EMBED=boot-win10.ipxe
mv bin/undionly.kpxe /srv/tftp/bios/undionly-w10.kpxe
make bin/undionly.kpxe EMBED=boot-winpe3.ipxe
mv bin/undionly.kpxe /srv/tftp/bios/undionly-winpe3.kpxe
make bin/undionly.kpxe EMBED=boot-winpe4.ipxe
mv bin/undionly.kpxe /srv/tftp/bios/undionly-winpe4.kpxe
make bin-x86_64-efi/ipxe.efi EMBED=uefi-win10.ipxe
mv bin-x86_64-efi/ipxe.efi /srv/tftp/efi64/ipxe.efi

systemctl restart isc-dhcp-server.service tftpd-hpa.service && systemctl status isc-dhcp-server.service tftpd-hpa.service


## contenu de install.bat à executer auto au boot :
wpeinit
net use * \\DC1.mydom.local\ISO\Win7
z:\setup.exe
