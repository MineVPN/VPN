#!/bin/bash

function isRoot() {
	if [ "$EUID" -ne 0 ]; then
		echo "Запустите скрипт с правами root."
		exit 1
	fi
}

function tunAvailable() {
	if [ ! -e /dev/net/tun ]; then
		echo "Устройство TUN недоступно."
		exit 1
	fi
}

function checkOS() {
	if [[ -e /etc/debian_version ]]; then
		OS="debian"
	elif [[ -e /etc/system-release ]]; then
		source /etc/os-release
		OS=$ID
	else
		echo "Неподдерживаемая операционная система."
		exit 1
	fi
}

function getFreePort() {
	shuf -i 49152-65535 -n 1
}

function getServerIP() {
	IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	echo "$IP"
}

function detectInterface() {
  NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
  if [[ -z $NIC ]]; then
    echo "Не удалось определить интерфейс сетевого выхода для настройки MASQUERADE."
    exit 1
  fi
}

function removeOpenVPN() {
	echo "Удаление OpenVPN и связанных файлов..."
	if systemctl is-active --quiet openvpn@server; then
		systemctl stop openvpn@server
	fi
	if systemctl is-enabled --quiet openvpn@server; then
		systemctl disable openvpn@server
	fi

	iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE 2>/dev/null
	iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
	iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT 2>/dev/null

	rm -rf /etc/openvpn
	rm -f /etc/sysctl.d/99-openvpn.conf
	find /root/ -name "*.ovpn" -delete
	rm -rf /var/log/openvpn

	echo "OpenVPN и все связанные данные были удалены."
}

function installOpenVPN() {
	if [[ $OS =~ (debian|ubuntu) ]]; then
		apt-get update
		apt-get install -y openvpn easy-rsa iptables openssl wget ca-certificates curl
	elif [[ $OS =~ (centos|fedora|amzn|oracle) ]]; then
		yum install -y openvpn easy-rsa iptables openssl wget ca-certificates curl
	fi

	make-cadir /etc/openvpn/easy-rsa
	cd /etc/openvpn/easy-rsa || exit

	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa gen-dh
	./easyrsa build-server-full server nopass
	./easyrsa gen-crl
	openvpn --genkey --secret /etc/openvpn/tls-auth.key

	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/dh.pem /etc/openvpn
	cp pki/crl.pem /etc/openvpn/crl.pem
	chown nobody:nogroup /etc/openvpn/crl.pem

	SERVER_PORT=$(getFreePort)
	SERVER_IP=$(getServerIP)

	cat <<EOF >/etc/openvpn/server.conf
port $SERVER_PORT
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
keepalive 10 120
cipher AES-128-CBC
persist-key
persist-tun
status openvpn-status.log
verb 3
tls-auth /etc/openvpn/tls-auth.key 0
auth SHA256
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
crl-verify crl.pem
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "block-outside-dns"
duplicate-cn # Позволить несколько подключений с одного сертификата
EOF

	echo 1 > /proc/sys/net/ipv4/ip_forward
	echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-openvpn.conf
	sysctl --system

	iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
	iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT

	systemctl enable openvpn@server
	systemctl start openvpn@server || { echo "Ошибка запуска службы OpenVPN"; exit 1; }
}

function createClientConfig() {
	local baseName=$1

	cd /etc/openvpn/easy-rsa || exit

	# Создание ключей и сертификатов для клиента
	./easyrsa build-client-full "$baseName" nopass

	cat <<EOF >"/root/${baseName}.ovpn"
client
proto udp
explicit-exit-notify
remote $SERVER_IP $SERVER_PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name server name
auth SHA256
auth-nocache
cipher AES-128-CBC
tls-client
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
setenv opt block-outside-dns
verb 3
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(awk '/BEGIN/,/END/' /etc/openvpn/easy-rsa/pki/issued/${baseName}.crt)
</cert>
<key>
$(cat /etc/openvpn/easy-rsa/pki/private/${baseName}.key)
</key>
<tls-auth>
$(cat /etc/openvpn/tls-auth.key)
</tls-auth>
key-direction 1
EOF

	echo "Конфигурационный файл для клиента создан: /root/${baseName}.ovpn"
}

function main() {
	if [[ "$1" == "-b" && "$2" != "" ]]; then
		local baseName=$2

		isRoot
		tunAvailable
		checkOS
		detectInterface

		# Удаление предыдущей установки, если она существует
		removeOpenVPN

		# Установка и настройка OpenVPN
		installOpenVPN

		# Генерация одного клиентского конфига
		createClientConfig "$baseName"

	else
		echo "Использование: $0 -b CLIENT_BASE_NAME"
		exit 1
	fi
}

main "$@"
