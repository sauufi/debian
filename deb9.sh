#!/bin/bash

# go to root
cd

# activate rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# By default this script does nothing.

exit 0
END

chmod +x /etc/rc.local
systemctl daemon-reload
systemctl enable rc-local
systemctl start rc-local

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# install wget and curl
apt update;apt -y install wget curl dos2unix;

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication/PasswordAuthentication/g' /etc/ssh/sshd_config
service ssh restart

# set repo
#wget -O /etc/apt/sources.list "http://dl.sshocean.com/dist/sources.list.debian9"
wget "http://www.dotdeb.org/dotdeb.gpg"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg

# remove unused
apt -y --purge remove samba*;
apt -y --purge remove apache2*;
apt -y --purge remove sendmail*;
apt -y --purge remove bind9*;


# update
apt update; apt -y upgrade;

# install webserver
#apt -y install nginx php5-fpm php5-cli

# install essential package
apt -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh unzip rsyslog debsums rkhunter
apt -y install build-essential

# disable exim
service exim4 stop
sysv-rc-conf exim4 off

# update apt-file
apt-file update

# setting vnstat
vnstat -u -i venet0
service vnstat restart

#touch screenfetch-dev
cd
wget -O screenfetch "https://raw.githubusercontent.com/sauufi/debian/master/screenfetch"
dos2unix screenfetch
mv screenfetch /usr/bin/screenfetch
chmod +x /usr/bin/screenfetch
echo "clear" >> .profile
echo "screenfetch" >> .profile

MYIP=`curl -s ipv4.icanhazip.com`;
useradd -M -s /bin/false sauufi

# install badvpn
wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/sauufi/debian/master/badvpn-udpgw64"
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 0.0.0.0:7200' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 0.0.0.0:7300' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 0.0.0.0:7200
screen -AmdS badvpn badvpn-udpgw --listen-addr 0.0.0.0:7300

# setting port ssh
sed -i 's/#Port/Port/g' /etc/ssh/sshd_config
service ssh restart

# install dropbear
wget -O /etc/bannerssh.dat "http://dl.sshocean.com/bannerssh.dat"
apt -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=80/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 143 -p 442"/g' /etc/default/dropbear
sed -i 's/DROPBEAR_BANNER=""/DROPBEAR_BANNER="\/etc\/bannerssh.dat"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
service ssh restart
service dropbear restart

# install fail2ban
apt -y install fail2ban;service fail2ban restart


# Instal DDOS Flate
if [ -d '/usr/local/ddos' ]; then
    echo; echo; echo "Please un-install the previous version first"
    exit 0
else
    mkdir /usr/local/ddos
fi
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'


#install squid
apt -y install squid
mv /etc/squid/squid.conf /etc/squid/squid.conf.bak
cat > /etc/squid/squid.conf <<-END
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
acl url1 url_regex -i 127.0.0.1
acl url2 url_regex -i localhost
acl url3 url_regex "/etc/squid/url.txt"
http_access allow url1
http_access allow url2
http_access allow url3
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
http_port 8080
http_port 3128
visible_hostname `hostname`
request_header_access Cache-Control deny all
END
cat > /etc/squid/url.txt <<-END
`curl -s ipv4.icanhazip.com`
END

# install webmin
#cd
#wget http://prdownloads.sourceforge.net/webadmin/webmin_1.910_all.deb
#dpkg --install webmin_1.910_all.deb
#apt -y -f install;
#rm /root/webmin_1.910_all.deb
#service webmin restart
#service vnstat restart

#instalasi stunnel
#detail nama perusahaan
country=SG
state=Singapore
locality=Singapore
organization=SSH
organizationalunit=SSH
commonname=domain.com
email=support@domain.com

#memeriksa port yang sedang berjalan
echo "-------------------- Stunnel Installer untuk debian dan ubuntu -------------------"

#memeriksa paket dropbear

dpkg -s dropbear &> /dev/null

if [ $? -eq 0 ]; then
    echo ""
else
    echo "Mohon install dropbear dan mengaktifkan port 443"
        break
fi

#update repository
apt update
apt install stunnel4 -y
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
pid = /stunnel.pid

client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 2222
connect = 127.0.0.1:80

[openssh]
accept = 445
connect = 127.0.0.1:22

[squid]
accept = 8000
connect = 127.0.0.1:3128
END

#membuat sertifikat
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

#konfigurasi stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart


# install sslh
apt install sslh -y
cat > /etc/default/sslh <<-END
# Default options for sslh initscript
# sourced by /etc/init.d/sslh

# Disabled by default, to force yourself
# to read the configuration:
# - /usr/share/doc/sslh/README.Debian (quick start)
# - /usr/share/doc/sslh/README, at "Configuration" section
# - sslh(8) via "man sslh" for more configuration details.
# Once configuration ready, you *must* set RUN to yes here
# and try to start sslh (standalone mode only)

RUN=yes

# binary to use: forked (sslh) or single-thread (sslh-select) version
# systemd users: don't forget to modify /lib/systemd/system/sslh.service
DAEMON=/usr/sbin/sslh

DAEMON_OPTS="--user sslh --listen 0.0.0.0:443 --ssh 127.0.0.1:80 --ssl 127.0.0.1:2222 --pidfile /var/run/sslh/sslh.pid"
END
systemctl enable sslh
systemctl start sslh

# install socks5
apt update -y
apt install build-essential -y
wget https://raw.githubusercontent.com/sauufi/debian/master/dante-1.4.2.tar.gz
tar -xf dante-1.4.2.tar.gz
cd dante-1.4.2
./configure --prefix=/home/dante
make
make install
mkdir /home/dante
IFACE=`curl -s ipv4.icanhazip.com`;
cat > /home/dante/danted.conf  <<-END
logoutput: /var/log/socks.log
internal: $IFACE port = 1080
external: $IFACE
method: username
user.privileged: root
user.notprivileged: nobody
client pass {
        from: 0.0.0.0/0 to: 0.0.0.0/0
        log: error connect disconnect
}
client block {
        from: 0.0.0.0/0 to: 0.0.0.0/0
        log: connect error
}
pass {
        from: 0.0.0.0/0 to: 0.0.0.0/0
        log: error connect disconnect
}
block {
        from: 0.0.0.0/0 to: 0.0.0.0/0
        log: connect error
}
END
cat > /etc/systemd/system/sockd.service <<-END
[Unit]
Description=Dante Socks Proxy v1.4.2
After=network.target

[Service]
Type=forking
PIDFile=/var/run/sockd.pid
ExecStart=/home/dante/sbin/sockd -f /home/dante/danted.conf -D
ExecReload=/bin/kill -HUP ${MAINPID}
KillMode=process
Restart=on-failure

[Install]
WantedBy=multi-user.target
END
systemctl start sockd
systemctl enable sockd


# auto reboot
sed -i '$ i\59 23 * * * root reboot' /etc/crontab

#Blockir Torrent
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables -A INPUT -m string --string "BitTorrent" --algo bm -j DROP
iptables -A INPUT -m string --string "BitTorrent protocol" --algo bm -j DROP
iptables -A INPUT -m string --string "peer_id=" --algo bm -j DROP
iptables -A INPUT -m string --string ".torrent" --algo bm -j DROP
iptables -A INPUT -m string --string "announce.php?passkey=" --algo bm -j DROP
iptables -A INPUT -m string --string "torrent" --algo bm -j DROP
iptables -A INPUT -m string --string "announce" --algo bm -j DROP
iptables -A INPUT -m string --string "info_hash" --algo bm -j DROP
iptables -A INPUT -m string --string "tracker" --algo bm -j DROP
iptables -A INPUT -m string --string "get_peers" --algo bm -j DROP
iptables -A INPUT -m string --string "announce_peer" --algo bm -j DROP
iptables -A INPUT -m string --string "find_node" --algo bm -j DROP
iptables -A INPUT -p tcp --dport 21 -j DROP
iptables -A INPUT -p tcp --dport 23 -j DROP
iptables -A OUTPUT -p tcp --dport 21 -j DROP
iptables -A OUTPUT -p tcp --dport 23 -j DROP
iptables -A OUTPUT -d account.sonyentertainmentnetwork.com -j DROP
iptables -A OUTPUT -d auth.np.ac.playstation.net -j DROP
iptables -A OUTPUT -d auth.api.sonyentertainmentnetwork.com -j DROP
iptables -A OUTPUT -d auth.api.np.ac.playstation.net -j DROP
iptables-save > /etc/iptables.up.rules
sed -i '$ i\iptables-restore < /etc/iptables.up.rules' /etc/rc.local

# finalisasi
service vnstat restart
service ssh restart
service dropbear restart
service fail2ban restart
service stunnel4 restart
service sslh restart
service squid restart

# info
clear
netstat -ntlp