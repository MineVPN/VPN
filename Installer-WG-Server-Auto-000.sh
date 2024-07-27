#!/bin/bash
WG_CONFIG="/etc/wireguard/wg0.conf"
ROOT_DIR="/root"

function get_free_udp_port() {
  local port=$(shuf -i 2000-65000 -n 1)
  ss -lau | grep $port > /dev/null
  if [[ $? == 1 ]]; then
    echo "$port"
  else
    get_free_udp_port
  fi
}

function remove_wireguard() {
  echo "Removing WireGuard configurations and components..."

  # Stop WireGuard service
  systemctl stop wg-quick@wg0.service
  systemctl disable wg-quick@wg0.service

  # Remove WireGuard configuration file if it exists
  if [ -f "$WG_CONFIG" ]; then
    rm -f $WG_CONFIG
  fi

  # Remove WireGuard client configuration files in /root/ directory
  rm -f /root/*.conf

  # Reset iptables rules
  iptables -F
  iptables -t nat -F
  iptables -t mangle -F
  iptables -P INPUT ACCEPT
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT ACCEPT
  iptables-save > /etc/iptables/rules.v4

  # Uninstall WireGuard packages based on the distribution
  if [ "$DISTRO" == "Ubuntu" ] || [ "$DISTRO" == "Debian" ]; then
    apt-get purge --auto-remove -y wireguard qrencode iptables-persistent
  elif [ "$DISTRO" == "CentOS" ]; then
    yum remove -y wireguard-dkms wireguard-tools qrencode firewalld
  fi

  echo "WireGuard configurations and components have been removed."
}

function install_wireguard() {
  if [ ! -f "$WG_CONFIG" ]; then
    ### Install server and add default client
    PRIVATE_SUBNET="10.9.0.0/24"
    PRIVATE_SUBNET_MASK=$(echo $PRIVATE_SUBNET | cut -d "/" -f 2)
    GATEWAY_ADDRESS="${PRIVATE_SUBNET::-4}1"

    SERVER_HOST=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
    SERVER_PORT=$(get_free_udp_port)
    CLIENT_DNS="8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1"

    if [ "$DISTRO" == "Ubuntu" ]; then
      apt-get install software-properties-common -y
      add-apt-repository ppa:wireguard/wireguard -y
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install linux-headers-$(uname -r) wireguard qrencode iptables-persistent -y
    elif [ "$DISTRO" == "Debian" ]; then
      echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
      printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
      apt-get install software-properties-common -y
      apt-get update
      apt install linux-headers-$(uname -r) wireguard qrencode iptables-persistent -y
    elif [ "$DISTRO" == "CentOS" ]; then
      yum install epel-release -y
      yum install wireguard-dkms wireguard-tools qrencode firewalld -y
    fi

    SERVER_PRIVKEY=$(wg genkey)
    SERVER_PUBKEY=$(echo $SERVER_PRIVKEY | wg pubkey)
    mkdir -p /etc/wireguard
    touch $WG_CONFIG && chmod 600 $WG_CONFIG

    echo "# $PRIVATE_SUBNET $SERVER_HOST:$SERVER_PORT $SERVER_PUBKEY $CLIENT_DNS

[Interface]
Address = $GATEWAY_ADDRESS/$PRIVATE_SUBNET_MASK
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIVKEY
SaveConfig = false" > $WG_CONFIG

    for ((i = 1; i <= CLIENT_COUNT; i++)); do
      CLIENT_PRIVKEY=$(wg genkey)
      CLIENT_PUBKEY=$(echo $CLIENT_PRIVKEY | wg pubkey)
      CLIENT_ADDRESS="${PRIVATE_SUBNET::-4}$((i + 1))"

      echo "# Client ${CLIENT_BASE_NAME}-${i}

[Peer]
PublicKey = $CLIENT_PUBKEY
AllowedIPs = $CLIENT_ADDRESS/32" >> $WG_CONFIG

      echo "[Interface]
PrivateKey = $CLIENT_PRIVKEY
Address = $CLIENT_ADDRESS/$PRIVATE_SUBNET_MASK
DNS = $CLIENT_DNS

[Peer]
PublicKey = $SERVER_PUBKEY
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $SERVER_HOST:$SERVER_PORT
PersistentKeepalive = 25" > "${ROOT_DIR}/${CLIENT_BASE_NAME}-${i}.conf"

      qrencode -t ansiutf8 -l L < "${ROOT_DIR}/${CLIENT_BASE_NAME}-${i}.conf"
    done

    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.forwarding=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf

    sysctl -p

    if [ "$DISTRO" == "CentOS" ]; then
      systemctl start firewalld
      systemctl enable firewalld
      firewall-cmd --zone=public --add-port=$SERVER_PORT/udp
      firewall-cmd --zone=trusted --add-source=$PRIVATE_SUBNET
      firewall-cmd --permanent --zone=public --add-port=$SERVER_PORT/udp
      firewall-cmd --permanent --zone=trusted --add-source=$PRIVATE_SUBNET
      firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s $PRIVATE_SUBNET ! -d $PRIVATE_SUBNET -j SNAT --to $SERVER_HOST
      firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s $PRIVATE_SUBNET ! -d $PRIVATE_SUBNET -j SNAT --to $SERVER_HOST
    else
      iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
      iptables -A FORWARD -m conntrack --ctstate NEW -s $PRIVATE_SUBNET -m policy --pol none --dir in -j ACCEPT
      iptables -t nat -A POSTROUTING -s $PRIVATE_SUBNET -m policy --pol none --dir out -j MASQUERADE
      iptables -A INPUT -p udp --dport $SERVER_PORT -j ACCEPT
      iptables-save > /etc/iptables/rules.v4
    fi

    systemctl enable wg-quick@wg0.service
    systemctl start wg-quick@wg0.service

    echo "Client configurations are generated with base name ${CLIENT_BASE_NAME}-<number>."
    echo "You can find them in the /root directory."
    echo "Now reboot the server and enjoy your fresh VPN installation! :)"
  else
    echo "WireGuard is already installed or this functionality is not yet implemented."
  fi
}

if [[ "$EUID" -ne 0 ]]; then
  echo "Sorry, you need to run this as root"
  exit 1
fi

if [[ ! -e /dev/net/tun ]]; then
  echo "The TUN device is not available. You need to enable TUN before running this script"
  exit 1
fi

if [ -e /etc/centos-release ]; then
  DISTRO="CentOS"
elif [ -e /etc/debian_version ]; then
  DISTRO=$(lsb_release -is)
else
  echo "Your distribution is not supported (yet)"
  exit 1
fi

if [ "$(systemd-detect-virt)" == "openvz" ]; then
  echo "OpenVZ virtualization is not supported"
  exit 1
fi

# Check if WireGuard is installed by verifying the existence of the configuration file
if [ -f "$WG_CONFIG" ]; then
  if [[ "$1" == "-d" ]]; then
    remove_wireguard
    exit 0
  else
    echo "WireGuard is already installed. Use '$0 -d' option to remove."
    remove_wireguard
    exit 0
  fi
fi

# Installation process when WireGuard is not already installed
if [[ "$1" == "-b" && "$2" != "" && "$3" == "-c" && "$4" != "" ]]; then
  CLIENT_BASE_NAME=$2
  CLIENT_COUNT=$4
  install_wireguard
else
  echo "Usage: $0 -b CLIENT_BASE_NAME -c CLIENT_COUNT to install and generate configurations"
  echo "       $0 -d to remove WireGuard configurations and components"
  exit 1
fi
