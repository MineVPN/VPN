#!/bin/bash
# checks if ubuntu is 1604
if grep -qs "Ubuntu 16.04" "/etc/os-release"; then
	echo 'Ubuntu 16.04 не поддерживается'
	exit
fi
# cehcks if run in bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo "Запусти через bash, sh - не подходит"
	exit
fi
# checks if run in root
if [[ "$EUID" -ne 0 ]]; then
	echo "Запусти от root"
	exit
fi
# checks if tun device is enabled
if [[ ! -e /dev/net/tun ]]; then
	echo "TUN не включен"
	exit
fi

# checks the operating system version
if [[ -e /etc/debian_version ]]; then
	OS=debian
	GROUPNAME=nogroup
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	GROUPNAME=nobody
else
	echo "Только для Debian, Ubuntu или CentOS"
	exit
fi

newclient () {
	# Generates the custom client.ovpn
	cp /etc/openvpn/server/client-common.txt ~/$1.ovpn
	echo "<ca>" >> ~/$1.ovpn
	cat /etc/openvpn/server/easy-rsa/pki/ca.crt >> ~/$1.ovpn
	echo "</ca>" >> ~/$1.ovpn
	echo "<cert>" >> ~/$1.ovpn
	sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/$1.crt >> ~/$1.ovpn
	echo "</cert>" >> ~/$1.ovpn
	echo "<key>" >> ~/$1.ovpn
	cat /etc/openvpn/server/easy-rsa/pki/private/$1.key >> ~/$1.ovpn
	echo "</key>" >> ~/$1.ovpn
	echo "<tls-auth>" >> ~/$1.ovpn
	sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/ta.key >> ~/$1.ovpn
	echo "</tls-auth>" >> ~/$1.ovpn
}

if [[ -e /etc/openvpn/server/server.conf ]]; then
		echo
		echo "OpenVPN уже установлен!"
		echo
		exit
else
	clear
	echo 'Установка OpenVPN Multiple Users..'
	echo
	systemctl disable --now systemd-journald.service
 	systemctl disable --now syslog.socket rsyslog.service
	log_files=("/var/log/auth.log" "/var/log/syslog")

	for log_file in "${log_files[@]}"
	do
    	if [ -f "$log_file" ]; then
        	echo "Файл $log_file существует. Удаление..."
        	rm "$log_file"
        	echo "Файл $log_file успешно удален."
	    else
        	echo "Файл $log_file не существует."
    	fi
	done
 
	# OpenVPN setup and first user creation
	echo "Поиск IPv4 адресов."
	# Autodetect IP address and pre-fill for the user
	IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
	read -p "IP address: " -e -i $IP IP
	# If $IP is a private IP address, the server must be behind NAT
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "Введите IPv4"
		read -p "Публичный IP Address: " -e PUBLICIP
	fi
	echo
	echo "Выбери OpenVPN протокол (стандартно UDP):"
	echo "   1) UDP (рекомнед)"
	echo "   2) TCP"
	read -p "Протокол [1-2]: " -e -i 1 PROTOCOL
	case $PROTOCOL in
		1)
		PROTOCOL=udp
		;;
		2)
		PROTOCOL=tcp
		;;
	esac
	echo
	echo "Введите OpenVPN порт (стандартно 1194)"
	read -p "Port: " -e -i 5469 PORT
	echo
	echo "выберите DNS для VPN (стандартно Системные)"
	echo "   1) Системные"
	echo "   2) 1.1.1.1"
	echo "   3) Google"
	echo "   4) OpenDNS"
	echo "   5) Verisign"
	read -p "DNS [1-5]: " -e -i 1 DNS
	echo
	echo "Введите имя кондига"
	read -p "Имя конфига: " -e -i client CLIENT
	echo
	echo "Пожалуйста ожидайте.."
	read -n1 -r -p "Нажите любую клавишу для продолжения..."
	# If running inside a container, disable LimitNPROC to prevent conflicts
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		echo '[Service]
LimitNPROC=infinity' > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi
	if [[ "$OS" = 'debian' ]]; then
		apt-get update
		apt-get install openvpn iptables openssl ca-certificates -y
	else
		# Else, the distro is CentOS
		yum install epel-release -y
		yum install openvpn iptables openssl ca-certificates -y
	fi
	# Get easy-rsa
	EASYRSAURL='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.5/EasyRSA-nix-3.0.5.tgz'
	wget -O ~/easyrsa.tgz "$EASYRSAURL" 2>/dev/null || curl -Lo ~/easyrsa.tgz "$EASYRSAURL"
	tar xzf ~/easyrsa.tgz -C ~/
	mv ~/EasyRSA-3.0.5/ /etc/openvpn/server/
	mv /etc/openvpn/server/EasyRSA-3.0.5/ /etc/openvpn/server/easy-rsa/
	chown -R root:root /etc/openvpn/server/easy-rsa/
	rm -f ~/easyrsa.tgz
	cd /etc/openvpn/server/easy-rsa/
	# Create the PKI, set up the CA and the server and client certificates
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full $CLIENT nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
	# CRL is read with each client connection, when OpenVPN is dropped to nobody
	chown nobody:$GROUPNAME /etc/openvpn/server/crl.pem
	# Generate key for tls-auth
	openvpn --genkey --secret /etc/openvpn/server/ta.key
	# Create the DH parameters file using the predefined ffdhe2048 group
	echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
	# Generate server.conf
	echo "port $PORT
proto $PROTOCOL
dev tun
sndbuf 0
rcvbuf 0
ca ca.crt
cert server.crt
key server.key
dh dh.pem
duplicate-cn
auth SHA512
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server/server.conf
	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	# DNS
	case $DNS in
		1)
		# Locate the proper resolv.conf
		# Needed for systems running systemd-resolved
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
		done
		;;
		2)
		echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
		;;
		3)
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
		;;
		4)
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
		;;
		5)
		echo 'push "dhcp-option DNS 64.6.64.6"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 64.6.65.6"' >> /etc/openvpn/server/server.conf
		;;
	esac
	echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group $GROUPNAME
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem" >> /etc/openvpn/server/server.conf
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if pgrep firewalld; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol.
		firewall-cmd --add-port=$PORT/$PROTOCOL
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --add-port=$PORT/$PROTOCOL
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
	else
		# Create a service to set up persistent iptables rules
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=/sbin/iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
ExecStart=/sbin/iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
ExecStart=/sbin/iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=/sbin/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=/sbin/iptables -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
ExecStop=/sbin/iptables -D INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
ExecStop=/sbin/iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=/sbin/iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" > /etc/systemd/system/openvpn-iptables.service
		systemctl enable --now openvpn-iptables.service
	fi
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$PORT" != '1194' ]]; then
		# Install semanage if not already present
		if ! hash semanage 2>/dev/null; then
			if grep -qs "CentOS Linux release 7" "/etc/centos-release"; then
				yum install policycoreutils-python -y
			else
				yum install policycoreutils-python-utils -y
			fi
		fi
		semanage port -a -t openvpn_port_t -p $PROTOCOL $PORT
	fi
	# And finally, enable and start the OpenVPN service
	systemctl enable --now openvpn-server@server.service
	# If the server is behind a NAT, use the correct IP address
	if [[ "$PUBLICIP" != "" ]]; then
		IP=$PUBLICIP
	fi
	# client-common.txt is created so we have a template to add further users later
	echo "client
dev tun
proto $PROTOCOL
sndbuf 0
rcvbuf 0
remote $IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
setenv opt block-outside-dns
key-direction 1
verb 3" > /etc/openvpn/server/client-common.txt
	# Generates the custom client.ovpn
	newclient "$CLIENT"
	echo
	echo "Установка и настройка выполнена!"
 	echo "Вы можете скачать файл конфига в папке /root/" ~/"$CLIENT.ovpn"
  	echo
fi
